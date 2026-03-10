"""
VirusTotal scanner via direct HTTP requests (no browser).
Uses internal UI API endpoints.
"""

import argparse
import asyncio
import base64
import csv
import hashlib
import json
import random
import time
from pathlib import Path

import httpx

JSON_DIR = Path(__file__).parent / "json"
PROXIES_FILE = Path(__file__).parent / "proxies.csv"

BASE_URL = "https://www.virustotal.com"

# Sysinternals partner API for bulk hash lookup
BULK_API_URL = "https://www.virustotal.com/partners/sysinternals/file-reports"
BULK_API_KEY = "4e3202fdbe953d628f650229af5b3eb49cd46b2d3bfe5546ae3c5fa48b554e0c"

# Official VT API v3
VT_API_V3_URL = "https://www.virustotal.com/api/v3"

# Mobile app API keys (public, rotate to avoid rate limits)
VT_API_KEYS = [
    "933fc7bdb949cfd23c89fc0e1768e8bfb66b5cd9c56534fc0d42f88cc6eb4fa8",  # Mobile app key 1
    "d58f006f62447c1b14a875f68da1040c637d9b37cb07a09971fe2be9f69eb9cf",  # Mobile app key 2
    "f74ee4682b69cebcccdee94e54baa91652584a0fa43e26a577d9d959996f6c44",  # Mobile app key 3
]
VT_API_KEY = VT_API_KEYS[0]  # Default key


def load_proxies(csv_path: Path | None = None) -> list[str]:
    """Load valid proxies from CSV file."""
    path = csv_path or PROXIES_FILE
    if not path.exists():
        return []

    proxies = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Valid", "").strip('"') != "true":
                continue
            protocol = row.get("Protocol", "socks5")
            host = row.get("Host", "")
            port = row.get("Port", "")
            login = row.get("Login", "")
            password = row.get("Password", "")
            if host and port and login and password:
                proto = "socks5" if "socks" in protocol.lower() else protocol
                proxies.append(f"{proto}://{login}:{password}@{host}:{port}")
    return proxies


class ProxyRotator:
    """Rotate through proxy list on failures."""

    def __init__(self, proxies: list[str] | None = None):
        self.proxies = proxies or load_proxies()
        self.index = 0
        self.failed: set[str] = set()

    def get_next(self) -> str | None:
        """Get next available proxy."""
        if not self.proxies:
            return None

        available = [p for p in self.proxies if p not in self.failed]
        if not available:
            # Reset failed list and try again
            self.failed.clear()
            available = self.proxies

        if not available:
            return None

        proxy = available[self.index % len(available)]
        self.index += 1
        return proxy

    def mark_failed(self, proxy: str) -> None:
        """Mark proxy as temporarily failed."""
        self.failed.add(proxy)

    def __len__(self) -> int:
        return len(self.proxies)


def generate_anti_abuse_header() -> str:
    """Generate X-VT-Anti-Abuse-Header token."""
    random_num = random.randint(10_000_000_000, 99_999_999_999)
    timestamp = time.time()
    token = f"{random_num}-ZG9udCBiZSBldmls-{timestamp}"
    return base64.b64encode(token.encode()).decode()


def get_headers() -> dict[str, str]:
    """Get required headers for VT API requests (from real browser)."""
    return {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
        "Accept": "application/json",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",  # typo is intentional - anti-bot
        "Referer": "https://www.virustotal.com/",
        "Content-Type": "application/json",
        "X-Tool": "vt-ui-main",
        "x-app-version": "v1x525x0",
        "X-VT-Anti-Abuse-Header": generate_anti_abuse_header(),
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "same-origin",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Alt-Used": "www.virustotal.com",
        "Priority": "u=4",
    }


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


async def upload_file(client: httpx.AsyncClient, file_path: Path) -> dict:
    """Upload file to VirusTotal."""
    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, "application/octet-stream")}
        headers = get_headers()

        response = await client.post(
            f"{BASE_URL}/ui/files",
            files=files,
            headers=headers,
        )

    if response.status_code != 200:
        return {"error": f"upload failed: {response.status_code}", "body": response.text}

    return response.json()


async def get_analysis_status(client: httpx.AsyncClient, analysis_id: str) -> dict:
    """Poll analysis status."""
    response = await client.get(
        f"{BASE_URL}/ui/analyses/{analysis_id}",
        headers=get_headers(),
    )

    if response.status_code != 200:
        return {"error": f"analysis poll failed: {response.status_code}"}

    return response.json()


async def get_file_report(client: httpx.AsyncClient, file_hash: str) -> dict:
    """Get full file report by hash (MD5/SHA1/SHA256)."""
    response = await client.get(
        f"{BASE_URL}/ui/files/{file_hash}",
        headers=get_headers(),
    )

    if response.status_code == 404:
        return {"error": "not_found", "status_code": 404}
    if response.status_code in [403, 429]:
        return {"error": "rate_limited", "status_code": response.status_code}
    if response.status_code != 200:
        return {"error": f"report failed: {response.status_code}"}

    return response.json()


class ApiKeyRotator:
    """Rotate through API keys on rate limit errors."""

    def __init__(self, keys: list[str] | None = None):
        self.keys = keys or VT_API_KEYS
        self.index = 0
        self.failed: dict[str, float] = {}  # key -> fail timestamp

    def get_next(self) -> str:
        """Get next available API key."""
        now = time.time()
        for _ in range(len(self.keys)):
            key = self.keys[self.index % len(self.keys)]
            self.index += 1
            # Skip keys that failed recently (within 60 seconds)
            if key in self.failed and now - self.failed[key] < 60:
                continue
            return key
        # All keys failed recently, just return next one
        return self.keys[self.index % len(self.keys)]

    def mark_rate_limited(self, key: str) -> None:
        """Mark key as rate limited."""
        self.failed[key] = time.time()


_api_key_rotator = ApiKeyRotator()


async def api_v3_get_file(file_hash: str, proxy: str | None = None) -> dict:
    """Get file report via official VT API v3."""
    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(proxy=proxy)

    api_key = _api_key_rotator.get_next()

    async with httpx.AsyncClient(timeout=30.0, transport=transport) as client:
        response = await client.get(
            f"{VT_API_V3_URL}/files/{file_hash}",
            headers={"x-apikey": api_key},
        )

    if response.status_code == 404:
        return {"error": "not_found"}
    if response.status_code == 429:
        _api_key_rotator.mark_rate_limited(api_key)
        return {"error": "rate_limited"}
    if response.status_code != 200:
        return {"error": f"api_error_{response.status_code}"}

    data = response.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "sha256": attrs.get("sha256"),
        "sha1": attrs.get("sha1"),
        "md5": attrs.get("md5"),
        "file_info": {
            "size": attrs.get("size"),
            "type": attrs.get("type_description"),
            "magic": attrs.get("magic"),
            "names": attrs.get("names", [])[:5],
        },
        "stats": stats,
        "detections": attrs.get("last_analysis_results", {}),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen": attrs.get("last_analysis_date"),
    }


async def api_v3_upload_file(file_path: Path, proxy: str | None = None) -> dict:
    """Upload file via official VT API v3."""
    if not file_path.exists():
        return {"error": "file_not_found"}

    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(proxy=proxy)

    api_key = _api_key_rotator.get_next()

    async with httpx.AsyncClient(timeout=120.0, transport=transport) as client:
        with open(file_path, "rb") as f:
            response = await client.post(
                f"{VT_API_V3_URL}/files",
                headers={"x-apikey": api_key},
                files={"file": (file_path.name, f)},
            )

    if response.status_code == 429:
        _api_key_rotator.mark_rate_limited(api_key)
        return {"error": "rate_limited"}
    if response.status_code != 200:
        return {"error": f"upload_error_{response.status_code}", "body": response.text}

    data = response.json()
    return {
        "analysis_id": data.get("data", {}).get("id"),
        "analysis_url": data.get("data", {}).get("links", {}).get("self"),
    }


async def bulk_check_hashes(hashes: list[str], proxy: str | None = None) -> list[dict]:
    """Check hashes via Sysinternals API (no rate limits)."""
    body = [{"hash": h} for h in hashes]

    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(proxy=proxy)

    async with httpx.AsyncClient(timeout=60.0, transport=transport) as client:
        response = await client.post(
            f"{BULK_API_URL}?apikey={BULK_API_KEY}",
            json=body,
            headers={"User-Agent": "VirusTotal"},
        )

    if response.status_code != 200:
        return []

    data = response.json()
    results = []
    for item in data.get("data", []):
        if item.get("found"):
            # Extract SHA256 from permalink
            permalink = item.get("permalink", "")
            sha256 = None
            if "/file/" in permalink:
                sha256 = permalink.split("/file/")[1].split("/")[0]

            results.append(
                {
                    "hash": item["hash"],
                    "sha256": sha256,
                    "found": True,
                    "stats": {
                        "malicious": item.get("positives", 0),
                        "total": item.get("total", 0),
                    },
                    "detection_ratio": item.get("detection_ratio"),
                    "permalink": permalink,
                }
            )
        else:
            results.append(
                {
                    "hash": item["hash"],
                    "found": False,
                }
            )
    return results


def parse_vt_response(result: dict) -> dict:
    """Parse VT API response into clean format."""
    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "sha256": attrs.get("sha256"),
        "sha1": attrs.get("sha1"),
        "md5": attrs.get("md5"),
        "file_info": {
            "size": attrs.get("size"),
            "type": attrs.get("type_description"),
            "magic": attrs.get("magic"),
            "names": attrs.get("names", [])[:5],
        },
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
        },
        "detections": attrs.get("last_analysis_results", {}),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen": attrs.get("last_analysis_date"),
    }


async def extract_api_key_from_browser() -> str | None:
    """Extract user's API key from browser session (if logged in)."""
    import nodriver as uc

    print("[*] Extracting API key from browser session...")

    browser = await uc.start(headless=False)  # Non-headless to allow login if needed
    try:
        tab = await browser.get("https://www.virustotal.com/gui/my-apikey")

        # Wait for page to load
        await asyncio.sleep(3)

        # Check if we need to login
        page_text = await tab.evaluate("document.body.innerText")
        if "Sign in" in page_text or "Log in" in page_text:
            print("[!] Not logged in. Please login manually...")
            # Wait for user to login
            for _ in range(60):  # Wait up to 60 seconds
                await asyncio.sleep(2)
                page_text = await tab.evaluate("document.body.innerText")
                if "API key" in page_text or "apikey" in page_text.lower():
                    break

        # Try to extract API key from page
        js_extract_key = """
        (() => {
            // Look for API key in various places
            const text = document.body.innerText;

            // Pattern for 64-char hex key
            const keyMatch = text.match(/[a-f0-9]{64}/i);
            if (keyMatch) return keyMatch[0];

            // Try to find in input fields
            const inputs = document.querySelectorAll('input[type="text"], input[readonly]');
            for (const input of inputs) {
                if (input.value && input.value.match(/^[a-f0-9]{64}$/i)) {
                    return input.value;
                }
            }

            // Try shadow DOM
            function searchShadow(root) {
                const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
                while (walker.nextNode()) {
                    const match = walker.currentNode.textContent.match(/[a-f0-9]{64}/i);
                    if (match) return match[0];
                }
                for (const el of root.querySelectorAll('*')) {
                    if (el.shadowRoot) {
                        const result = searchShadow(el.shadowRoot);
                        if (result) return result;
                    }
                }
                return null;
            }
            return searchShadow(document.body);
        })()
        """

        api_key = await tab.evaluate(js_extract_key)
        if api_key and len(api_key) == 64:
            print(f"[+] Found API key: {api_key[:8]}...{api_key[-8:]}")
            return api_key

        print("[!] Could not find API key on page")
        return None

    except Exception as e:
        print(f"[!] Error: {e}")
        return None
    finally:
        browser.stop()


async def test_session_for_api(cookies: dict) -> bool:
    """Test if browser session cookies work for v3 API."""
    async with httpx.AsyncClient(timeout=30.0, cookies=cookies) as client:
        # Try to access v3 API with session cookies
        response = await client.get(
            f"{VT_API_V3_URL}/users/current",
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        return response.status_code == 200


async def lookup_hash_browser(file_hash: str, proxy: str | None = None) -> dict:
    """Get full report by parsing VT page via browser (bypasses reCAPTCHA)."""
    import nodriver as uc

    print(f"[*] Browser lookup: {file_hash}")

    browser = await uc.start(headless=True)
    try:
        if proxy:
            proxy_host = proxy.split("@")[-1] if "@" in proxy else proxy
            print(f"[*] Proxy: {proxy_host}")
            tab = await browser.create_context(
                url=f"https://www.virustotal.com/gui/file/{file_hash}",
                proxy_server=proxy,
            )
            await asyncio.sleep(1)
            for t in list(browser.tabs):
                if t != tab:
                    try:
                        await t.close()
                    except Exception:
                        pass
        else:
            tab = await browser.get(f"https://www.virustotal.com/gui/file/{file_hash}")

        # Wait for page to load
        for _ in range(20):
            await asyncio.sleep(1)
            check = await tab.evaluate(
                "document.body.innerText.includes('security vendors') || "
                "document.body.innerText.includes('Undetected')"
            )
            if check:
                break

        # Parse report from DOM
        js_get_report = """
        (() => {
            const result = {hashes: {}, file_info: {}, stats: {}, detections: {}};

            function getAllText(root) {
                let text = '';
                const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
                while (walker.nextNode()) text += walker.currentNode.textContent + ' ';
                root.querySelectorAll('*').forEach(el => {
                    if (el.shadowRoot) text += getAllText(el.shadowRoot);
                });
                return text;
            }

            const text = getAllText(document.body);

            // Check for 404 (specific error message, not just any 'not found')
            if (text.includes('Item not found') || text.includes('File not found')) {
                return JSON.stringify({error: 'not_found'});
            }

            // Extract hashes
            const sha256Match = text.match(/SHA-?256\\s*([a-f0-9]{64})/i) || text.match(/\\b([a-f0-9]{64})\\b/i);
            const sha1Match = text.match(/SHA-?1\\s*([a-f0-9]{40})/i);
            const md5Match = text.match(/MD5\\s*([a-f0-9]{32})/i);

            if (sha256Match) result.hashes.sha256 = sha256Match[1].toLowerCase();
            if (sha1Match) result.hashes.sha1 = sha1Match[1].toLowerCase();
            if (md5Match) result.hashes.md5 = md5Match[1].toLowerCase();

            // Extract stats - format can be "X/Y" or "X / Y"
            const statsMatch = text.match(/(\\d+)\\s*\\/\\s*(\\d+)\\s*security vendors/i) ||
                               text.match(/(\\d+)\\s+\\/\\s+(\\d+)/);
            if (statsMatch) {
                result.stats.malicious = parseInt(statsMatch[1]);
                result.stats.total = parseInt(statsMatch[2]);
            }

            // Check for clean file
            if (text.includes('No security vendors flagged')) {
                result.stats.malicious = 0;
                // Try to find total from "X/Y" pattern with higher Y
                const allMatches = [...text.matchAll(/(\\d+)\\s*\\/\\s*(\\d+)/g)];
                let maxTotal = 0;
                for (const m of allMatches) {
                    const total = parseInt(m[2]);
                    if (total >= 40 && total <= 100 && total > maxTotal) {
                        maxTotal = total;
                    }
                }
                if (maxTotal) result.stats.total = maxTotal;
            }

            // Extract size
            const sizeMatch = text.match(/(\\d+(?:\\.\\d+)?\\s*[KMG]?B)\\s*Size/i);
            if (sizeMatch) result.file_info.size = sizeMatch[1];

            // Known vendors
            const vendors = ['Kaspersky', 'ESET-NOD32', 'BitDefender', 'Avast', 'Microsoft',
                'McAfee', 'Symantec', 'DrWeb', 'Sophos', 'Avira', 'ClamAV', 'Malwarebytes'];

            for (const vendor of vendors) {
                const pattern = new RegExp(vendor + '\\\\s+(Undetected|Malicious|Suspicious|Clean)', 'i');
                const match = text.match(pattern);
                if (match) {
                    const status = match[1].toLowerCase();
                    result.detections[vendor] = {
                        detected: status === 'malicious' || status === 'suspicious',
                        result: status
                    };
                }
            }

            return JSON.stringify(result);
        })()
        """

        report_json = await tab.evaluate(js_get_report)
        if not report_json:
            return {"error": "parse_failed", "hash": file_hash}

        report = json.loads(report_json)
        if "error" in report:
            return {"error": report["error"], "hash": file_hash}

        return {
            "sha256": report.get("hashes", {}).get("sha256"),
            "sha1": report.get("hashes", {}).get("sha1"),
            "md5": report.get("hashes", {}).get("md5"),
            "file_info": report.get("file_info", {}),
            "stats": report.get("stats", {}),
            "detections": report.get("detections", {}),
        }

    except Exception as e:
        return {"error": str(e), "hash": file_hash}
    finally:
        browser.stop()


async def lookup_hash(
    file_hash: str,
    proxy: str | None = None,
    max_retries: int = 5,
    use_proxy_rotation: bool = True,
) -> dict:
    """Lookup file info by hash without uploading."""
    print(f"[*] Looking up: {file_hash}")

    rotator = ProxyRotator() if use_proxy_rotation else None
    if rotator and len(rotator) > 0:
        print(f"[*] Loaded {len(rotator)} proxies for rotation")

    current_proxy = proxy

    for attempt in range(max_retries):
        # Get proxy for this attempt
        if rotator and len(rotator) > 0 and (attempt > 0 or not current_proxy):
            current_proxy = rotator.get_next()

        transport = None
        if current_proxy:
            proxy_host = current_proxy.split("@")[-1] if "@" in current_proxy else current_proxy
            if attempt == 0:
                print(f"[*] Proxy: {proxy_host}")
            else:
                print(f"[*] Retry {attempt + 1}/{max_retries} with proxy: {proxy_host}")
            transport = httpx.AsyncHTTPTransport(proxy=current_proxy)

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                follow_redirects=True,
                verify=False,  # Like winbindex
            ) as client:
                result = await get_file_report(client, file_hash)

                if "error" not in result:
                    return parse_vt_response(result)

                if result.get("error") == "not_found":
                    return {"error": "not_found", "hash": file_hash}

                if result.get("error") == "rate_limited":
                    if rotator and current_proxy:
                        rotator.mark_failed(current_proxy)
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue

                return result

        except Exception as e:
            print(f"[!] Error: {e}")
            if rotator and current_proxy:
                rotator.mark_failed(current_proxy)
            if attempt < max_retries - 1:
                continue
            return {"error": str(e), "hash": file_hash}

    return {"error": "max_retries_exceeded", "hash": file_hash}


async def init_session(client: httpx.AsyncClient) -> bool:
    """Visit homepage to get session cookies."""
    try:
        response = await client.get(
            f"{BASE_URL}/gui/home/upload",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )
        return response.status_code == 200
    except Exception as e:
        print(f"[!] Session init failed: {e}")
        return False


async def scan_file(file_path: Path, proxy: str | None = None) -> dict:
    """Upload and scan file, wait for results."""
    if not file_path.exists():
        return {"error": "file not found"}

    hashes = calculate_hashes(file_path)
    print(f"[*] {file_path.name} ({file_path.stat().st_size} bytes)")
    print(f"[*] SHA256: {hashes['sha256']}")

    start = time.time()

    transport = None
    if proxy:
        proxy_host = proxy.split("@")[-1] if "@" in proxy else proxy
        print(f"[*] Proxy: {proxy_host}")
        transport = httpx.AsyncHTTPTransport(proxy=proxy)

    async with httpx.AsyncClient(
        transport=transport,
        timeout=60.0,
        follow_redirects=True,
        cookies=httpx.Cookies(),  # Enable cookie jar
    ) as client:
        # Init session first
        print("[0] Init session...", end=" ", flush=True)
        if await init_session(client):
            print("OK")
        else:
            print("WARN")
        # Step 1: Upload file
        print("[1] Upload...", end=" ", flush=True)
        upload_result = await upload_file(client, file_path)

        if "error" in upload_result:
            print(f"FAIL: {upload_result['error']}")
            return upload_result

        analysis_id = upload_result.get("data", {}).get("id")
        if not analysis_id:
            print("FAIL: no analysis_id")
            return {"error": "no analysis_id", "response": upload_result}

        print(f"OK -> {analysis_id[:20]}...")

        # Step 2: Poll for analysis completion
        print("[2] Waiting for analysis...", end=" ", flush=True)

        sha256 = None
        for i in range(180):  # Max 3 minutes
            status_result = await get_analysis_status(client, analysis_id)

            if "error" in status_result:
                print(f"poll error: {status_result['error']}")
                await asyncio.sleep(2)
                continue

            attrs = status_result.get("data", {}).get("attributes", {})
            status = attrs.get("status", "unknown")
            stats = attrs.get("stats", {})

            # Get SHA256 from meta
            meta = status_result.get("meta", {}).get("file_info", {})
            if meta.get("sha256"):
                sha256 = meta["sha256"]

            if status == "queued":
                if i % 10 == 0:
                    print("[queued]", end=" ", flush=True)

            elif status == "in-progress":
                total = sum(stats.values())
                if i % 5 == 0 and total > 0:
                    print(f"[{total}]", end=" ", flush=True)

            elif status == "completed":
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) - stats.get("type-unsupported", 0)
                elapsed = int(time.time() - start)
                print(f"[{malicious}/{total}] OK ({elapsed}s)")

                # Get full report
                if sha256:
                    print("[3] Getting full report...", end=" ", flush=True)
                    report = await get_file_report(client, sha256)
                    if "error" not in report:
                        print("OK")
                        report_attrs = report.get("data", {}).get("attributes", {})
                        return {
                            "sha256": sha256,
                            "sha1": hashes["sha1"],
                            "md5": hashes["md5"],
                            "file_info": {
                                "size": report_attrs.get("size"),
                                "type": report_attrs.get("type_description"),
                                "magic": report_attrs.get("magic"),
                            },
                            "stats": {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "undetected": stats.get("undetected", 0),
                                "timeout": stats.get("timeout", 0),
                                "type_unsupported": stats.get("type-unsupported", 0),
                            },
                            "detections": report_attrs.get("last_analysis_results", {}),
                            "scan_time": elapsed,
                        }

                # Fallback: return analysis results
                return {
                    "sha256": sha256 or hashes["sha256"],
                    "sha1": hashes["sha1"],
                    "md5": hashes["md5"],
                    "stats": stats,
                    "detections": attrs.get("results", {}),
                    "scan_time": elapsed,
                }

            await asyncio.sleep(1)

        return {
            "sha256": sha256 or hashes["sha256"],
            "status": "timeout",
            "time": int(time.time() - start),
        }


def save_result(result: dict) -> Path | None:
    """Save result to JSON file."""
    hash_id = result.get("sha256") or result.get("md5")
    if not hash_id:
        return None
    JSON_DIR.mkdir(exist_ok=True)
    out_file = JSON_DIR / f"{hash_id}_api.json"
    out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return out_file


def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal scanner (HTTP API)")
    parser.add_argument("targets", nargs="*", help="Files to scan or hashes to lookup")
    parser.add_argument(
        "--proxy",
        "-p",
        help="Proxy URL (socks5://user:pass@host:port)",
    )
    parser.add_argument(
        "--lookup",
        "-l",
        action="store_true",
        help="Lookup mode: treat targets as hashes (full report, may be rate limited)",
    )
    parser.add_argument(
        "--bulk",
        "-b",
        action="store_true",
        help="Bulk check mode: quick check via Sysinternals API (no rate limits)",
    )
    parser.add_argument(
        "--browser",
        "-B",
        action="store_true",
        help="Browser mode: full report via DOM parsing (bypasses reCAPTCHA)",
    )
    parser.add_argument(
        "--api",
        "-a",
        action="store_true",
        help="Use official VT API v3 (full report, ~4 req/min limit)",
    )
    parser.add_argument(
        "--extract-key",
        "-k",
        action="store_true",
        help="Extract API key from browser session (opens browser for login)",
    )
    args = parser.parse_args()

    # Extract API key mode
    if args.extract_key:
        import nodriver as uc

        api_key = uc.loop().run_until_complete(extract_api_key_from_browser())
        if api_key:
            print(f"\n[+] API Key: {api_key}")
            print("\nYou can use this key with --api flag or set VT_API_KEY env var")
        return

    # Check that targets provided for non-extract modes
    if not args.extract_key and not args.targets:
        parser.error("targets are required (unless using --extract-key)")

    # Bulk check mode - all hashes at once
    if args.bulk:
        hashes = args.targets
        print(f"[*] Bulk checking {len(hashes)} hashes...")
        results = asyncio.run(bulk_check_hashes(hashes, args.proxy))
        for result in results:
            print(json.dumps(result, indent=2))
            if result.get("found") and (out := save_result(result)):
                print(f"Saved: {out}")
        return

    # Single target processing
    for target in args.targets:
        is_hash = len(target) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in target)

        if args.api and is_hash:
            # Official VT API v3 mode
            result = asyncio.run(api_v3_get_file(target, args.proxy))
        elif args.browser and is_hash:
            # Browser lookup mode (full report via DOM)
            import nodriver as uc

            result = uc.loop().run_until_complete(lookup_hash_browser(target, args.proxy))
        elif args.lookup or is_hash:
            # HTTP lookup mode (may be rate limited)
            result = asyncio.run(lookup_hash(target, args.proxy))
        else:
            # File upload mode
            if args.api:
                result = asyncio.run(api_v3_upload_file(Path(target), args.proxy))
            else:
                result = asyncio.run(scan_file(Path(target), args.proxy))

        print(json.dumps(result, indent=2))
        if out := save_result(result):
            print(f"Saved: {out}")


if __name__ == "__main__":
    main()
