"""
VirusTotal file scanner — upload via fetch, DOM polling for results.
Minimal network requests, Shadow DOM support.
"""

import argparse
import asyncio
import base64
import csv
import json
import time
from pathlib import Path

import nodriver as uc

JSON_DIR = Path(__file__).parent / "json"

JS_GET_ALL_TEXT = """
function getAllText(root) {
    let text = '';
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
        text += walker.currentNode.textContent + ' ';
    }
    root.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) text += getAllText(el.shadowRoot);
    });
    return text;
}
"""

JS_CHECK_STATUS = (
    JS_GET_ALL_TEXT
    + """
(() => {
    const text = getAllText(document.body);

    // Queued
    if (text.includes('Queued')) {
        return JSON.stringify({status: 'queued'});
    }

    // Analyzing: "Analysing (XX.Xs)..."
    const analyzingMatch = text.match(/Analysing\\s*\\((\\d+\\.?\\d*)s\\)/i);
    if (analyzingMatch) {
        return JSON.stringify({status: 'analyzing', time: analyzingMatch[1]});
    }

    // Check for results
    const hasResults = text.includes('No security vendors') ||
                       text.includes('security vendors flagged') ||
                       text.includes('Community Score') ||
                       text.includes('Undetected');

    if (hasResults) {
        // "Reanalyze" appears only when analysis is 100% complete
        const isFullyCompleted = text.includes('Reanalyze') ||
                                 text.includes('Last analysis');

        // Find X/Y pattern with max Y (total AV count)
        const allMatches = [...text.matchAll(/(\\d+)\\s*\\/\\s*(\\d+)/g)];
        let bestMatch = null;
        let maxTotal = 0;
        for (const m of allMatches) {
            const total = parseInt(m[2]);
            if (total >= 40 && total <= 100 && total > maxTotal) {
                maxTotal = total;
                bestMatch = {detections: parseInt(m[1]), total: total};
            }
        }
        if (bestMatch) {
            return JSON.stringify({
                status: isFullyCompleted ? 'completed' : 'partial',
                detections: bestMatch.detections,
                total: bestMatch.total
            });
        }
    }

    return JSON.stringify({status: 'loading'});
})()
"""
)

JS_GET_SHA256 = (
    JS_GET_ALL_TEXT
    + """
(() => {
    // Check URL first
    const urlMatch = window.location.href.match(/\\/gui\\/file\\/([a-f0-9]{64})/i);
    if (urlMatch) return urlMatch[1];

    // Search in DOM (Shadow DOM)
    function findSha256(root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            const match = walker.currentNode.textContent.match(/\\b([a-f0-9]{64})\\b/i);
            if (match) return match[1];
        }
        for (const el of root.querySelectorAll('*')) {
            if (el.shadowRoot) {
                const found = findSha256(el.shadowRoot);
                if (found) return found;
            }
        }
        return null;
    }
    return findSha256(document.body);
})()
"""
)

JS_GET_FULL_REPORT = """
(() => {
    const result = {
        hashes: {},
        file_info: {},
        stats: {},
        detections: {}
    };

    // Known AV vendors (full names)
    const knownVendors = new Set([
        'Bkav', 'Lionic', 'MicroWorld-eScan', 'ClamAV', 'CMC', 'CAT-QuickHeal',
        'Skyhigh', 'ALYac', 'Malwarebytes', 'VIPRE', 'Sangfor', 'K7AntiVirus',
        'K7GW', 'CrowdStrike', 'Arcabit', 'Baidu', 'VirIT', 'Symantec',
        'ESET-NOD32', 'TrendMicro-HouseCall', 'Avast', 'Cynet', 'Kaspersky',
        'BitDefender', 'NANO-Antivirus', 'SUPERAntiSpyware', 'Tencent', 'Sophos',
        'F-Secure', 'DrWeb', 'Zillya', 'TrendMicro', 'McAfee', 'CTX', 'Emsisoft',
        'Huorong', 'Jiangmin', 'Google', 'Avira', 'Antiy-AVL', 'Kingsoft',
        'Gridinsoft', 'Xcitium', 'Microsoft', 'ViRobot', 'ZoneAlarm', 'GData',
        'Varist', 'AhnLab-V3', 'Acronis', 'VBA32', 'TACHYON', 'Zoner', 'Rising',
        'Yandex', 'Ikarus', 'MaxSecure', 'Fortinet', 'AVG', 'Panda',
        'Avast-Mobile', 'SymantecMobileInsight', 'BitDefenderFalx', 'Elastic',
        'DeepInstinct', 'Webroot', 'APEX', 'Paloalto', 'Alibaba', 'Trapmine',
        'Cylance', 'SentinelOne', 'TEHTRIS', 'Trustlook', 'AliCloud', 'WithSecure',
        'SecureAge', 'Cyren', 'eScan', 'TotalDefense', 'Comodo', 'Qihoo-360',
        'ZoneAlarm-Check-Point', 'McAfee-GW-Edition', 'TrendMicro-HouseCall',
        'Trellix', 'TrellixENS'
    ]);

    // Helper: get text from Shadow DOM
    function getAllText(root) {
        let text = '';
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            text += walker.currentNode.textContent + ' ';
        }
        root.querySelectorAll('*').forEach(el => {
            if (el.shadowRoot) text += getAllText(el.shadowRoot);
        });
        return text;
    }

    const text = getAllText(document.body);

    // Extract hashes - look for labeled hashes
    const sha256Match = text.match(/SHA-?256\\s*([a-f0-9]{64})/i) ||
                        text.match(/\\b([a-f0-9]{64})\\b/i);
    const sha1Match = text.match(/SHA-?1\\s*([a-f0-9]{40})/i) ||
                      text.match(/\\b([a-f0-9]{40})\\b(?!\\w)/i);
    const md5Match = text.match(/MD5\\s*([a-f0-9]{32})/i) ||
                     text.match(/\\b([a-f0-9]{32})\\b(?!\\w)/i);

    if (sha256Match) result.hashes.sha256 = sha256Match[1].toLowerCase();
    if (sha1Match) result.hashes.sha1 = sha1Match[1].toLowerCase();
    if (md5Match) result.hashes.md5 = md5Match[1].toLowerCase();

    // Extract file size
    const sizeMatch = text.match(/(\\d+(?:\\.\\d+)?\\s*[KMG]?B)\\s*Size/i) ||
                      text.match(/Size\\s*(\\d+(?:\\.\\d+)?\\s*[KMG]?B)/i) ||
                      text.match(/(\\d+)\\s*bytes/i);
    if (sizeMatch) result.file_info.size = sizeMatch[1];

    // Extract detection stats
    const statsMatch = text.match(/(\\d+)\\s*\\/\\s*(\\d+)\\s*security vendors/i);
    if (statsMatch) {
        result.stats.malicious = parseInt(statsMatch[1]);
        result.stats.total = parseInt(statsMatch[2]);
    }

    // Parse vendor results - match known vendors followed by status
    for (const vendor of knownVendors) {
        const escapedVendor = vendor.replace(/[-\\/\\\\^$*+?.()|[\\]{}]/g, '\\\\$&');
        const pattern = new RegExp(escapedVendor + '\\\\s+(Undetected|Type-unsupported|Unable to process|Timeout|Clean|Malicious|Suspicious)', 'i');
        const match = text.match(pattern);
        if (match) {
            const status = match[1].toLowerCase();
            let category = 'undetected';
            if (status === 'malicious') category = 'malicious';
            else if (status === 'suspicious') category = 'suspicious';
            else if (status === 'type-unsupported' || status === 'unable to process') category = 'type-unsupported';
            else if (status === 'timeout') category = 'timeout';

            result.detections[vendor] = {
                result: category === 'malicious' ? 'detected' : null,
                category: category
            };
        }
    }

    return JSON.stringify(result);
})()
"""


def load_proxy_from_csv(csv_path: str) -> str | None:
    """Load SOAX proxy from CSV file."""
    path = Path(csv_path)
    if not path.exists():
        return None

    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            protocol = row.get("Protocol", "socks5")
            host = row.get("Host", "")
            port = row.get("Port", "")
            login = row.get("Login", "")
            password = row.get("Password", "")
            if host and port and login and password:
                proto = "socks" if "socks" in protocol.lower() else protocol
                return f"{proto}://{login}:{password}@{host}:{port}"
    return None


async def upload_and_scan(file_path: Path, proxy: str | None = None) -> dict:
    """Upload file to VirusTotal and wait for scan results."""
    if not file_path.exists():
        return {"error": "file not found"}

    print(f"[*] {file_path.name} ({file_path.stat().st_size} bytes)")
    if proxy:
        proxy_host = proxy.split("@")[-1] if "@" in proxy else proxy
        print(f"[*] Proxy: {proxy_host}")

    start = time.time()

    with open(file_path, "rb") as f:
        file_b64 = base64.b64encode(f.read()).decode()

    browser = await uc.start(headless=False)

    try:
        # Open VT with optional proxy
        if proxy:
            tab = await browser.create_context(
                url="https://www.virustotal.com/",
                proxy_server=proxy,
            )
            await asyncio.sleep(1)
            # Close extra tabs
            for t in list(browser.tabs):
                if t != tab:
                    try:
                        await t.close()
                    except Exception:
                        pass
        else:
            tab = await browser.get("https://www.virustotal.com/")

        await asyncio.sleep(2)

        # Upload via fetch API
        print("[1] Upload...", end=" ", flush=True)
        await tab.evaluate(f"""
            window.__VT__ = null;
            const b64 = "{file_b64}";
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            const file = new File([bytes], "{file_path.name}", {{type: "application/octet-stream"}});
            const formData = new FormData();
            formData.append("file", file);
            fetch("/ui/files", {{method: "POST", body: formData, credentials: "include"}})
                .then(r => r.json())
                .then(d => {{ window.__VT__ = JSON.stringify(d); }})
                .catch(e => {{ window.__VT__ = JSON.stringify({{error: e.message}}); }});
        """)

        # Wait for upload response
        for _ in range(30):
            r = await tab.evaluate("window.__VT__")
            if r:
                break
            await asyncio.sleep(0.1)

        if not r:
            return {"error": "upload timeout"}

        data = json.loads(r)
        if "error" in data:
            return {"error": data["error"]}

        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "no analysis_id", "data": data}

        # Extract MD5 from analysis_id (base64 encoded "md5:timestamp")
        decoded = base64.b64decode(analysis_id).decode()
        md5 = decoded.split(":")[0]
        print(f"OK -> {md5}")

        # Navigate to file page
        print("[2] Waiting for analysis...", end=" ", flush=True)
        await tab.get(f"https://www.virustotal.com/gui/file/{md5}")
        await asyncio.sleep(3)

        # Poll DOM for status (no extra network requests)
        analysis_started = False
        for i in range(120):  # Max 2 minutes
            dom_status = await tab.evaluate(JS_CHECK_STATUS)

            if dom_status:
                try:
                    status = json.loads(dom_status)

                    if status["status"] == "queued":
                        if i % 10 == 0:
                            print("[queued]", end=" ", flush=True)

                    elif status["status"] == "analyzing":
                        if not analysis_started:
                            analysis_started = True
                            print("[started]", end=" ", flush=True)
                        if i % 5 == 0:
                            print(f"[{status.get('time', '?')}s]", end=" ", flush=True)

                    elif status["status"] == "partial":
                        if not analysis_started:
                            analysis_started = True
                            print(
                                f"[{status['detections']}/{status['total']}]", end=" ", flush=True
                            )

                    elif status["status"] == "completed":
                        t = int(time.time() - start)
                        print(f"[{status['detections']}/{status['total']}] OK ({t}s)")

                        # Get full report from DOM
                        report_json = await tab.evaluate(JS_GET_FULL_REPORT)
                        try:
                            report = json.loads(report_json) if report_json else {}
                        except json.JSONDecodeError:
                            report = {}

                        sha256 = report.get("hashes", {}).get("sha256")
                        if not sha256:
                            sha256 = await tab.evaluate(JS_GET_SHA256)

                        return {
                            "sha256": sha256,
                            "sha1": report.get("hashes", {}).get("sha1"),
                            "md5": md5,
                            "file_info": report.get("file_info", {}),
                            "stats": {
                                "malicious": status["detections"],
                                "total": status["total"],
                            },
                            "detections": report.get("detections", {}),
                            "scan_time": t,
                        }

                except (json.JSONDecodeError, TypeError):
                    pass

            await asyncio.sleep(1)

        return {"md5": md5, "status": "timeout", "time": int(time.time() - start)}

    except Exception as e:
        import traceback

        traceback.print_exc()
        return {"error": str(e)}
    finally:
        browser.stop()


def save_result(result: dict) -> Path | None:
    """Save result to JSON file."""
    hash_id = result.get("sha256") or result.get("md5")
    if not hash_id:
        return None
    JSON_DIR.mkdir(exist_ok=True)
    out_file = JSON_DIR / f"{hash_id}.json"
    out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return out_file


def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal file scanner")
    parser.add_argument("files", nargs="+", help="Files to scan")
    parser.add_argument(
        "--proxy",
        "-p",
        help="Proxy (socks://user:pass@host:port) or path to CSV file",
    )
    args = parser.parse_args()

    proxy = None
    if args.proxy:
        if args.proxy.endswith(".csv") and Path(args.proxy).exists():
            proxy = load_proxy_from_csv(args.proxy)
            if not proxy:
                print(f"[!] No valid proxy found in {args.proxy}")
        else:
            proxy = args.proxy

    for fp in args.files:
        result = uc.loop().run_until_complete(upload_and_scan(Path(fp), proxy))
        print(json.dumps(result, indent=2))
        if out := save_result(result):
            print(f"Saved: {out}")


if __name__ == "__main__":
    main()
