"""VirusTotal URL/Domain/IP Checker with rate limiting and key rotation."""

import asyncio
import base64
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

import httpx

# API keys from mobile apps
VT_API_KEYS = [
    # "933fc7bdb949cfd23c89fc0e1768e8bfb66b5cd9c56534fc0d42f88cc6eb4fa8",
    "d58f006f62447c1b14a875f68da1040c637d9b37cb07a09971fe2be9f69eb9cf",
    # "f74ee4682b69cebcccdee94e54baa91652584a0fa43e26a577d9d959996f6c44",
]

API_BASE = "https://www.virustotal.com/api/v3"


class CheckType(Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"


@dataclass
class KeyState:
    """Track state for each API key."""

    key: str
    requests: int = 0
    rate_limits: int = 0
    last_request: float = 0
    cooldown_until: float = 0


@dataclass
class RateLimiter:
    """Manage multiple API keys with rotation."""

    keys: list[KeyState] = field(default_factory=list)
    total_requests: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        if not self.keys:
            self.keys = [KeyState(key=k) for k in VT_API_KEYS]

    async def get_key(self) -> KeyState:
        """Get best available key."""
        async with self._lock:
            now = time.time()
            available = [k for k in self.keys if k.cooldown_until <= now]
            if not available:
                # All keys on cooldown, wait for first one
                wait_time = min(k.cooldown_until for k in self.keys) - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                available = self.keys

            # Pick key with least requests
            key = min(available, key=lambda k: k.requests)
            key.requests += 1
            key.last_request = now
            self.total_requests += 1
            return key

    async def mark_rate_limited(self, key: KeyState, cooldown: float = 60):
        """Mark key as rate limited."""
        async with self._lock:
            key.rate_limits += 1
            key.cooldown_until = time.time() + cooldown


# Key vendors to check (for URLs - not all AV scan URLs)
KEY_VENDORS = [
    "Google Safebrowsing",  # Chrome
    "Yandex Safebrowsing",
    "Kaspersky",
    "BitDefender",
    "ESET",
    "Sophos",
    "Fortinet",
    "Avira",
]


@dataclass
class CheckResult:
    """Result of URL/domain/IP check."""

    target: str
    check_type: CheckType
    status: str  # ok, error, not_found, rate_limited
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    categories: dict = field(default_factory=dict)
    reputation: int = 0
    last_analysis_date: int = 0
    error: str = ""
    vendors: dict = field(default_factory=dict)  # All vendor results
    key_vendors: dict = field(default_factory=dict)  # Key vendors only
    raw_data: dict = field(default_factory=dict)


def url_to_id(url: str) -> str:
    """Convert URL to VT identifier (base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VTUrlChecker:
    """VirusTotal URL/Domain/IP checker."""

    def __init__(self, keys: list[str] | None = None):
        self.rate_limiter = RateLimiter(keys=[KeyState(key=k) for k in (keys or VT_API_KEYS)])
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    async def _request(self, method: str, endpoint: str, **kwargs) -> tuple[int, dict | None]:
        """Make API request with rate limiting."""
        key_state = await self.rate_limiter.get_key()

        headers = {
            "x-apikey": key_state.key,
            "accept": "application/json",
        }

        url = f"{API_BASE}{endpoint}"

        try:
            if method == "GET":
                resp = await self.client.get(url, headers=headers, **kwargs)
            else:
                resp = await self.client.post(url, headers=headers, **kwargs)

            if resp.status_code == 429:
                await self.rate_limiter.mark_rate_limited(key_state)
                return 429, None

            return resp.status_code, resp.json() if resp.content else None

        except Exception as e:
            return 0, {"error": str(e)}

    async def check_url(self, url: str, scan_if_missing: bool = True) -> CheckResult:
        """Check URL reputation.

        Args:
            url: URL to check
            scan_if_missing: If True, submit URL for scanning if not in database
        """
        url_id = url_to_id(url)

        # Try to get existing report
        status, data = await self._request("GET", f"/urls/{url_id}")

        if status == 200 and data:
            return self._parse_url_result(url, data)

        if status == 404 and scan_if_missing:
            # Submit for scanning
            status, data = await self._request("POST", "/urls", data={"url": url})

            if status == 200 and data:
                analysis_id = data.get("data", {}).get("id")
                if analysis_id:
                    # Poll for results
                    return await self._poll_analysis(url, analysis_id, CheckType.URL)

        return CheckResult(
            target=url,
            check_type=CheckType.URL,
            status="error" if status != 404 else "not_found",
            error=f"HTTP {status}",
        )

    async def check_domain(self, domain: str) -> CheckResult:
        """Check domain reputation."""
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith("http"):
            from urllib.parse import urlparse

            domain = urlparse(domain).netloc

        status, data = await self._request("GET", f"/domains/{domain}")

        if status == 200 and data:
            return self._parse_domain_result(domain, data)

        return CheckResult(
            target=domain,
            check_type=CheckType.DOMAIN,
            status="error" if status != 404 else "not_found",
            error=f"HTTP {status}",
        )

    async def check_ip(self, ip: str) -> CheckResult:
        """Check IP address reputation."""
        status, data = await self._request("GET", f"/ip_addresses/{ip}")

        if status == 200 and data:
            return self._parse_ip_result(ip, data)

        return CheckResult(
            target=ip,
            check_type=CheckType.IP,
            status="error" if status != 404 else "not_found",
            error=f"HTTP {status}",
        )

    async def _poll_analysis(
        self, target: str, analysis_id: str, check_type: CheckType, max_polls: int = 30
    ) -> CheckResult:
        """Poll analysis until complete."""
        for _ in range(max_polls):
            status, data = await self._request("GET", f"/analyses/{analysis_id}")

            if status == 429:
                await asyncio.sleep(15)
                continue

            if status == 200 and data:
                attrs = data.get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    stats = attrs.get("stats", {})
                    return CheckResult(
                        target=target,
                        check_type=check_type,
                        status="ok",
                        malicious=stats.get("malicious", 0),
                        suspicious=stats.get("suspicious", 0),
                        harmless=stats.get("harmless", 0),
                        undetected=stats.get("undetected", 0),
                        total=sum(stats.values()),
                        raw_data=data,
                    )

            await asyncio.sleep(2)

        return CheckResult(
            target=target,
            check_type=check_type,
            status="timeout",
            error="Analysis timeout",
        )

    def _parse_url_result(self, url: str, data: dict) -> CheckResult:
        """Parse URL check result."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Extract all vendors
        vendors = {}
        for name, info in results.items():
            vendors[name] = {
                "result": info.get("result"),
                "category": info.get("category"),
            }

        # Extract key vendors
        key_vendors = {}
        for vendor in KEY_VENDORS:
            if vendor in results:
                info = results[vendor]
                key_vendors[vendor] = {
                    "result": info.get("result"),
                    "category": info.get("category"),
                }

        return CheckResult(
            target=url,
            check_type=CheckType.URL,
            status="ok",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()),
            categories=attrs.get("categories", {}),
            reputation=attrs.get("reputation", 0),
            last_analysis_date=attrs.get("last_analysis_date", 0),
            vendors=vendors,
            key_vendors=key_vendors,
            raw_data=data,
        )

    def _parse_domain_result(self, domain: str, data: dict) -> CheckResult:
        """Parse domain check result."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return CheckResult(
            target=domain,
            check_type=CheckType.DOMAIN,
            status="ok",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()),
            categories=attrs.get("categories", {}),
            reputation=attrs.get("reputation", 0),
            last_analysis_date=attrs.get("last_analysis_date", 0),
            raw_data=data,
        )

    def _parse_ip_result(self, ip: str, data: dict) -> CheckResult:
        """Parse IP check result."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return CheckResult(
            target=ip,
            check_type=CheckType.IP,
            status="ok",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()),
            reputation=attrs.get("reputation", 0),
            last_analysis_date=attrs.get("last_analysis_date", 0),
            raw_data=data,
        )

    async def check_batch(
        self, targets: list[str], check_type: CheckType = CheckType.URL
    ) -> list[CheckResult]:
        """Check multiple targets."""
        results = []

        for target in targets:
            if check_type == CheckType.URL:
                result = await self.check_url(target, scan_if_missing=False)
            elif check_type == CheckType.DOMAIN:
                result = await self.check_domain(target)
            else:
                result = await self.check_ip(target)

            results.append(result)

        return results

    def get_stats(self) -> dict:
        """Get rate limiter stats."""
        return {
            "total_requests": self.rate_limiter.total_requests,
            "keys": [
                {
                    "key": k.key[:12] + "...",
                    "requests": k.requests,
                    "rate_limits": k.rate_limits,
                }
                for k in self.rate_limiter.keys
            ],
        }


JSON_DIR = Path(__file__).parent / "json"


async def check_urls_parallel(
    urls: list[str],
    workers: int = 3,
    output_file: str | None = None,
    auto_save: bool = True,
) -> dict:
    """Check URLs in parallel with multiple workers.

    Args:
        urls: List of URLs to check
        workers: Number of parallel workers
        output_file: Optional JSON file to save results

    Returns:
        Dict with meta info and results
    """
    import json

    results = []
    stats = {"ok": 0, "errors": 0, "rate_limits": 0}
    lock = asyncio.Lock()
    t0 = time.time()

    async def worker(worker_urls: list[str], checker: VTUrlChecker):
        for url in worker_urls:
            result = await checker.check_url(url, scan_if_missing=False)
            async with lock:
                results.append(result)
                if result.status == "ok":
                    stats["ok"] += 1
                elif result.status == "rate_limited":
                    stats["rate_limits"] += 1
                else:
                    stats["errors"] += 1

    # Split URLs across workers
    chunk_size = len(urls) // workers + 1
    chunks = [urls[i : i + chunk_size] for i in range(0, len(urls), chunk_size)]

    async with VTUrlChecker() as checker:
        tasks = [worker(chunk, checker) for chunk in chunks if chunk]
        await asyncio.gather(*tasks)

        elapsed = time.time() - t0
        checker_stats = checker.get_stats()

    # Build output
    output = {
        "meta": {
            "total_urls": len(urls),
            "workers": workers,
            "elapsed_seconds": round(elapsed, 1),
            "urls_per_minute": round(len(urls) / elapsed * 60, 1) if elapsed > 0 else 0,
            "ok": stats["ok"],
            "errors": stats["errors"],
            "rate_limits": stats["rate_limits"],
            "requests": checker_stats["total_requests"],
        },
        "results": [
            {
                "url": r.target,
                "status": r.status,
                "malicious": r.malicious,
                "suspicious": r.suspicious,
                "harmless": r.harmless,
                "undetected": r.undetected,
                "total": r.total,
                "reputation": r.reputation,
                "categories": r.categories,
                "key_vendors": r.key_vendors,
                "all_vendors": r.vendors,
            }
            for r in results
        ],
    }

    # Save to file
    if output_file:
        save_path = Path(output_file)
    elif auto_save:
        JSON_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = JSON_DIR / f"urls_{timestamp}.json"
    else:
        save_path = None

    if save_path:
        with open(save_path, "w") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        output["meta"]["saved_to"] = str(save_path)

    return output


async def main():
    """CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(description="VirusTotal URL Checker")
    parser.add_argument("targets", nargs="*", help="URLs to check")
    parser.add_argument("--file", "-f", help="File with URLs (one per line)")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--workers", "-w", type=int, default=1, help="Parallel workers")
    parser.add_argument("--scan", "-s", action="store_true", help="Submit for scan if not found")
    parser.add_argument("--stats", action="store_true", help="Show stats")

    args = parser.parse_args()

    # Collect targets
    targets = list(args.targets)
    if args.file:
        with open(args.file) as f:
            targets.extend(line.strip() for line in f if line.strip())

    if not targets:
        parser.print_help()
        return

    # Parallel mode (auto-save to json/)
    if args.workers >= 1 and (args.output or len(targets) > 1):
        result = await check_urls_parallel(
            urls=targets,
            workers=args.workers,
            output_file=args.output,
        )

        print(f"Checked: {result['meta']['total_urls']} URLs")
        print(f"Time: {result['meta']['elapsed_seconds']}s")
        print(f"Speed: {result['meta']['urls_per_minute']:.0f} URLs/min")
        print(
            f"OK: {result['meta']['ok']}, Errors: {result['meta']['errors']}, Rate limits: {result['meta']['rate_limits']}"
        )

        if result["meta"].get("saved_to"):
            print(f"Saved: {result['meta']['saved_to']}")
        return

    # Sequential mode
    async with VTUrlChecker() as checker:
        results = []

        for target in targets:
            result = await checker.check_url(target, scan_if_missing=args.scan)
            results.append(result)

            status_icon = "✓" if result.status == "ok" else "✗"
            mal = f"{result.malicious}/{result.total}" if result.total else "N/A"
            print(f"{status_icon} {target}: {mal} malicious")

        if args.stats:
            print("\n--- Stats ---")
            stats = checker.get_stats()
            print(f"Total requests: {stats['total_requests']}")
            for k in stats["keys"]:
                print(f"  {k['key']}: {k['requests']} req, {k['rate_limits']} rl")


if __name__ == "__main__":
    asyncio.run(main())
