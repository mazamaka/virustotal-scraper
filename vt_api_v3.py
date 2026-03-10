"""
VirusTotal API v3 client with smart rate limiting.

Features:
- 3 API keys rotation (12 req/min total)
- Large file upload (>32MB via upload_url)
- Analysis polling with status updates
- Automatic retry on rate limits
"""

import argparse
import asyncio
import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# === Configuration ===

VT_API_V3_URL = "https://www.virustotal.com/api/v3"
JSON_DIR = Path(__file__).parent / "json"

# Mobile app API keys (public, 4 req/min each)
VT_API_KEYS = [
    "933fc7bdb949cfd23c89fc0e1768e8bfb66b5cd9c56534fc0d42f88cc6eb4fa8",
    "d58f006f62447c1b14a875f68da1040c637d9b37cb07a09971fe2be9f69eb9cf",
    "f74ee4682b69cebcccdee94e54baa91652584a0fa43e26a577d9d959996f6c44",
]

# Rate limits
REQUESTS_PER_MINUTE_PER_KEY = 4
MAX_FILE_SIZE_DIRECT = 32 * 1024 * 1024  # 32MB


# === Rate Limiter ===


@dataclass
class KeyState:
    """Track state for a single API key."""

    key: str
    requests: deque = field(default_factory=deque)  # timestamps of recent requests
    rate_limited_until: float = 0.0

    def can_use(self) -> bool:
        """Check if key can be used now."""
        now = time.time()
        if now < self.rate_limited_until:
            return False
        # Clean old requests (older than 60s)
        while self.requests and self.requests[0] < now - 60:
            self.requests.popleft()
        return len(self.requests) < REQUESTS_PER_MINUTE_PER_KEY

    def record_request(self) -> None:
        """Record a request."""
        self.requests.append(time.time())

    def mark_rate_limited(self, seconds: int = 60) -> None:
        """Mark key as rate limited."""
        self.rate_limited_until = time.time() + seconds

    def time_until_available(self) -> float:
        """Get seconds until key becomes available."""
        now = time.time()
        if now < self.rate_limited_until:
            return self.rate_limited_until - now
        if len(self.requests) < REQUESTS_PER_MINUTE_PER_KEY:
            return 0.0
        # Wait until oldest request expires
        oldest = self.requests[0]
        return max(0.0, (oldest + 60) - now)


class RateLimiter:
    """
    Smart rate limiter for multiple API keys.

    Distributes requests across keys to maximize throughput
    while respecting per-key limits.
    """

    def __init__(self, keys: list[str] | None = None):
        self.keys = [KeyState(key=k) for k in (keys or VT_API_KEYS)]
        self._lock = asyncio.Lock()
        self.total_requests = 0
        self.total_rate_limits = 0

    async def acquire(self) -> str:
        """
        Get an available API key, waiting if necessary.

        Returns the API key to use.
        """
        async with self._lock:
            while True:
                # Find available key
                for ks in self.keys:
                    if ks.can_use():
                        ks.record_request()
                        self.total_requests += 1
                        return ks.key

                # No key available - find minimum wait time
                min_wait = min(ks.time_until_available() for ks in self.keys)
                if min_wait > 0:
                    # Release lock while waiting
                    self._lock.release()
                    try:
                        await asyncio.sleep(min_wait + 0.1)
                    finally:
                        await self._lock.acquire()

    def mark_rate_limited(self, key: str) -> None:
        """Mark a key as rate limited (got 429 response)."""
        for ks in self.keys:
            if ks.key == key:
                ks.mark_rate_limited()
                self.total_rate_limits += 1
                break

    def stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "total_rate_limits": self.total_rate_limits,
            "keys": len(self.keys),
            "available_now": sum(1 for ks in self.keys if ks.can_use()),
        }


# Global rate limiter instance
_rate_limiter = RateLimiter()


# === API Client ===


def calculate_hashes(file_path: Path) -> dict[str, str]:
    """Calculate MD5, SHA1, SHA256 of file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


async def api_request(
    method: str,
    endpoint: str,
    *,
    data: dict | None = None,
    files: dict | None = None,
    timeout: float = 30.0,
    max_retries: int = 3,
) -> tuple[int, dict | None]:
    """
    Make an API request with automatic rate limiting and retry.

    Returns (status_code, response_json or None).
    """
    url = f"{VT_API_V3_URL}{endpoint}" if endpoint.startswith("/") else endpoint

    for attempt in range(max_retries):
        api_key = await _rate_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                headers = {"x-apikey": api_key, "accept": "application/json"}

                if method.upper() == "GET":
                    response = await client.get(url, headers=headers)
                elif method.upper() == "POST":
                    if files:
                        response = await client.post(url, headers=headers, files=files, data=data)
                    elif data:
                        response = await client.post(url, headers=headers, json=data)
                    else:
                        response = await client.post(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported method: {method}")

            # Handle rate limit
            if response.status_code == 429:
                _rate_limiter.mark_rate_limited(api_key)
                if attempt < max_retries - 1:
                    continue
                return 429, None

            # Parse JSON response
            try:
                result = response.json()
            except Exception:
                result = None

            return response.status_code, result

        except httpx.TimeoutException:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            return 0, {"error": "timeout"}
        except Exception as e:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            return 0, {"error": str(e)}

    return 0, {"error": "max_retries_exceeded"}


# === File Operations ===


async def get_file_report(file_hash: str) -> dict:
    """
    Get file report by hash (MD5/SHA1/SHA256).

    Returns parsed report or error dict.
    """
    status, data = await api_request("GET", f"/files/{file_hash}")

    if status == 404:
        return {"error": "not_found", "hash": file_hash}
    if status == 429:
        return {"error": "rate_limited", "hash": file_hash}
    if status != 200 or not data:
        return {"error": f"api_error_{status}", "hash": file_hash}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "sha256": attrs.get("sha256"),
        "sha1": attrs.get("sha1"),
        "md5": attrs.get("md5"),
        "size": attrs.get("size"),
        "type": attrs.get("type_description"),
        "type_tag": attrs.get("type_tag"),
        "magic": attrs.get("magic"),
        "names": attrs.get("names", [])[:10],
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "timeout": stats.get("timeout", 0),
            "failure": stats.get("failure", 0),
        },
        "reputation": attrs.get("reputation", 0),
        "votes": attrs.get("total_votes", {}),
        "tags": attrs.get("tags", []),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen": attrs.get("last_analysis_date"),
        "last_modification": attrs.get("last_modification_date"),
        "detections": attrs.get("last_analysis_results", {}),
    }


async def get_upload_url() -> str | None:
    """Get special URL for uploading large files (>32MB)."""
    status, data = await api_request("GET", "/files/upload_url")

    if status != 200 or not data:
        return None

    return data.get("data")


async def upload_file(file_path: Path, wait_for_analysis: bool = True) -> dict:
    """
    Upload file to VirusTotal.

    Args:
        file_path: Path to file to upload
        wait_for_analysis: If True, wait for analysis to complete

    Returns:
        Analysis result or upload status
    """
    if not file_path.exists():
        return {"error": "file_not_found", "path": str(file_path)}

    file_size = file_path.stat().st_size
    hashes = calculate_hashes(file_path)

    print(f"[*] File: {file_path.name}")
    print(f"[*] Size: {file_size:,} bytes")
    print(f"[*] SHA256: {hashes['sha256']}")

    # Determine upload URL
    if file_size > MAX_FILE_SIZE_DIRECT:
        print(f"[*] Large file (>{MAX_FILE_SIZE_DIRECT // 1024 // 1024}MB), getting upload URL...")
        upload_url = await get_upload_url()
        if not upload_url:
            return {"error": "failed_to_get_upload_url"}
        print(f"[*] Upload URL: {upload_url[:50]}...")
    else:
        upload_url = f"{VT_API_V3_URL}/files"

    # Upload file
    print("[1] Uploading...", end=" ", flush=True)
    start_time = time.time()

    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, "application/octet-stream")}
        status, data = await api_request(
            "POST",
            upload_url,
            files=files,
            timeout=300.0,  # 5 min for large files
        )

    if status == 429:
        print("RATE LIMITED")
        return {"error": "rate_limited", "hashes": hashes}
    if status != 200 or not data:
        print(f"FAILED ({status})")
        return {"error": f"upload_failed_{status}", "hashes": hashes}

    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        print("FAILED (no analysis_id)")
        return {"error": "no_analysis_id", "hashes": hashes}

    upload_time = time.time() - start_time
    print(f"OK ({upload_time:.1f}s) -> {analysis_id[:30]}...")

    if not wait_for_analysis:
        return {
            "status": "uploaded",
            "analysis_id": analysis_id,
            "hashes": hashes,
        }

    # Wait for analysis
    return await wait_for_analysis_completion(analysis_id, hashes)


async def wait_for_analysis_completion(
    analysis_id: str,
    hashes: dict[str, str],
    timeout: int = 300,
) -> dict:
    """Wait for analysis to complete and return results."""
    print("[2] Waiting for analysis...", end=" ", flush=True)
    start_time = time.time()

    for i in range(timeout):
        status, data = await api_request("GET", f"/analyses/{analysis_id}")

        if status != 200 or not data:
            if i % 10 == 0:
                print(f"[poll error {status}]", end=" ", flush=True)
            await asyncio.sleep(1)
            continue

        attrs = data.get("data", {}).get("attributes", {})
        analysis_status = attrs.get("status", "unknown")
        stats = attrs.get("stats", {})

        if analysis_status == "queued":
            if i % 15 == 0:
                print("[queued]", end=" ", flush=True)

        elif analysis_status == "in-progress":
            total = sum(stats.values())
            if i % 10 == 0 and total > 0:
                print(f"[{total} engines]", end=" ", flush=True)

        elif analysis_status == "completed":
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) - stats.get("type-unsupported", 0)
            elapsed = int(time.time() - start_time)
            print(f"DONE: {malicious}/{total} ({elapsed}s)")

            # Get full report
            print("[3] Getting full report...", end=" ", flush=True)
            report = await get_file_report(hashes["sha256"])

            if "error" not in report:
                print("OK")
                report["analysis_time"] = elapsed
                return report
            else:
                print(f"WARN: {report.get('error')}")
                return {
                    "sha256": hashes["sha256"],
                    "sha1": hashes["sha1"],
                    "md5": hashes["md5"],
                    "stats": stats,
                    "analysis_time": elapsed,
                }

        await asyncio.sleep(1)

    elapsed = int(time.time() - start_time)
    print(f"TIMEOUT ({elapsed}s)")
    return {
        "error": "analysis_timeout",
        "hashes": hashes,
        "elapsed": elapsed,
    }


async def rescan_file(file_hash: str) -> dict:
    """
    Request rescan of existing file.

    Returns analysis ID or error.
    """
    status, data = await api_request("POST", f"/files/{file_hash}/analyse")

    if status == 404:
        return {"error": "not_found", "hash": file_hash}
    if status == 429:
        return {"error": "rate_limited", "hash": file_hash}
    if status != 200 or not data:
        return {"error": f"rescan_failed_{status}", "hash": file_hash}

    analysis_id = data.get("data", {}).get("id")
    return {"status": "queued", "analysis_id": analysis_id, "hash": file_hash}


# === Batch Operations ===


async def batch_lookup(
    hashes: list[str],
    delay: float = 0.0,
    on_result: callable = None,
) -> list[dict]:
    """
    Lookup multiple hashes with rate limiting.

    Args:
        hashes: List of file hashes to lookup
        delay: Additional delay between requests (on top of rate limiting)
        on_result: Optional callback for each result

    Returns:
        List of results
    """
    results = []
    total = len(hashes)

    for i, file_hash in enumerate(hashes, 1):
        print(f"[{i}/{total}] {file_hash[:16]}...", end=" ", flush=True)

        result = await get_file_report(file_hash)

        if "error" in result:
            print(f"ERROR: {result['error']}")
        else:
            stats = result.get("stats", {})
            malicious = stats.get("malicious", 0)
            total_engines = sum(stats.values())
            print(f"{malicious}/{total_engines}")

        results.append(result)

        if on_result:
            on_result(result)

        if delay > 0 and i < total:
            await asyncio.sleep(delay)

    return results


async def batch_upload(
    files: list[Path],
    wait_for_analysis: bool = True,
    delay: float = 0.0,
) -> list[dict]:
    """
    Upload multiple files with rate limiting.

    Args:
        files: List of file paths to upload
        wait_for_analysis: Wait for each analysis to complete
        delay: Additional delay between uploads

    Returns:
        List of results
    """
    results = []
    total = len(files)

    for i, file_path in enumerate(files, 1):
        print(f"\n=== [{i}/{total}] {file_path.name} ===")

        result = await upload_file(file_path, wait_for_analysis=wait_for_analysis)
        results.append(result)

        if delay > 0 and i < total:
            await asyncio.sleep(delay)

    return results


# === Utility ===


def save_result(result: dict, suffix: str = "_v3") -> Path | None:
    """Save result to JSON file."""
    hash_id = result.get("sha256") or result.get("md5") or result.get("hash")
    if not hash_id:
        return None

    JSON_DIR.mkdir(exist_ok=True)
    out_file = JSON_DIR / f"{hash_id}{suffix}.json"
    out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return out_file


def print_result(result: dict) -> None:
    """Pretty print result."""
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    print(f"\n{'=' * 60}")
    print(f"SHA256: {result.get('sha256', 'N/A')}")
    print(f"SHA1:   {result.get('sha1', 'N/A')}")
    print(f"MD5:    {result.get('md5', 'N/A')}")

    if result.get("size"):
        print(f"Size:   {result['size']:,} bytes")
    if result.get("type"):
        print(f"Type:   {result['type']}")
    if result.get("names"):
        print(f"Names:  {', '.join(result['names'][:5])}")

    stats = result.get("stats", {})
    if stats:
        print(
            f"\nDetections: {stats.get('malicious', 0)} malicious, "
            f"{stats.get('suspicious', 0)} suspicious, "
            f"{stats.get('undetected', 0)} undetected"
        )

    if result.get("tags"):
        print(f"Tags:   {', '.join(result['tags'][:10])}")

    print(f"{'=' * 60}\n")


# === CLI ===


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VirusTotal API v3 client with smart rate limiting"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files to upload or hashes to lookup",
    )
    parser.add_argument(
        "--lookup",
        "-l",
        action="store_true",
        help="Lookup mode: treat targets as hashes",
    )
    parser.add_argument(
        "--upload",
        "-u",
        action="store_true",
        help="Upload mode: treat targets as files",
    )
    parser.add_argument(
        "--rescan",
        "-r",
        action="store_true",
        help="Rescan mode: request rescan of existing files",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Don't wait for analysis to complete (upload/rescan)",
    )
    parser.add_argument(
        "--delay",
        "-d",
        type=float,
        default=0.0,
        help="Additional delay between requests (seconds)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output JSON file (for batch results)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show rate limiter stats at the end",
    )

    args = parser.parse_args()

    if not args.targets:
        parser.error("At least one target is required")

    async def run():
        results = []

        for target in args.targets:
            is_hash = len(target) in [32, 40, 64] and all(
                c in "0123456789abcdefABCDEF" for c in target
            )

            if args.rescan:
                # Rescan existing file
                print(f"\n[*] Requesting rescan: {target}")
                result = await rescan_file(target)
                if "error" not in result and not args.no_wait:
                    result = await wait_for_analysis_completion(
                        result["analysis_id"],
                        {"sha256": target, "sha1": "", "md5": ""},
                    )

            elif args.lookup or (is_hash and not args.upload):
                # Hash lookup
                print(f"\n[*] Looking up: {target}")
                result = await get_file_report(target)

            else:
                # File upload
                file_path = Path(target)
                if not file_path.exists() or not file_path.is_file():
                    result = {"error": "file_not_found", "path": target}
                else:
                    result = await upload_file(
                        file_path,
                        wait_for_analysis=not args.no_wait,
                    )

            results.append(result)
            print_result(result)

            # Save individual result
            if out := save_result(result):
                print(f"Saved: {out}")

            if args.delay > 0 and target != args.targets[-1]:
                await asyncio.sleep(args.delay)

        # Save batch results
        if args.output and len(results) > 1:
            out_path = Path(args.output)
            out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
            print(f"\nBatch results saved: {out_path}")

        # Show stats
        if args.stats:
            stats = _rate_limiter.stats()
            print(
                f"\n[Stats] Requests: {stats['total_requests']}, "
                f"Rate limits hit: {stats['total_rate_limits']}, "
                f"Keys: {stats['keys']}"
            )

    asyncio.run(run())


if __name__ == "__main__":
    main()
