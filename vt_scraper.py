"""
VT Upload — fetch upload + GUI для результатов
"""

import asyncio
import base64
import json
import sys
import time
from pathlib import Path

import nodriver as uc


async def upload_and_scan(file_path: Path) -> dict:
    if not file_path.exists():
        return {"error": "file not found"}

    print(f"[*] {file_path.name} ({file_path.stat().st_size} bytes)")
    start = time.time()

    with open(file_path, "rb") as f:
        file_b64 = base64.b64encode(f.read()).decode()

    browser = await uc.start(headless=False)

    try:
        tab = await browser.get("https://www.virustotal.com/")
        await tab.send(uc.cdp.network.enable())
        await asyncio.sleep(1)

        # Upload через fetch
        print("[1] Upload...", end=" ", flush=True)
        await tab.evaluate(f'''
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
        ''')

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

        decoded = base64.b64decode(analysis_id).decode()
        md5 = decoded.split(":")[0]
        print(f"OK -> {md5}")

        # Переходим на GUI страницу и перехватываем API ответ
        print("[2] Results...", end=" ", flush=True)
        result_data = {}

        async def capture(event):
            nonlocal result_data
            if "/ui/files/" in event.response.url and event.response.status == 200:
                try:
                    r = await tab.send(
                        uc.cdp.network.get_response_body(request_id=event.request_id)
                    )
                    body = r[0] if isinstance(r, tuple) else str(r)
                    d = json.loads(body)
                    if "data" in d and "attributes" in d.get("data", {}):
                        result_data = d
                except:
                    pass

        tab.add_handler(uc.cdp.network.ResponseReceived, capture)
        await tab.get(f"https://www.virustotal.com/gui/file/{md5}")

        # Ждём результат
        for i in range(60):
            await asyncio.sleep(0.5)
            if result_data and "data" in result_data:
                attrs = result_data["data"].get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                if total > 0:
                    t = int(time.time() - start)
                    print(f"OK ({t}s)")

                    # Собираем детекции
                    detections = {}
                    for av, res in attrs.get("last_analysis_results", {}).items():
                        detections[av] = {
                            "result": res.get("result"),
                            "category": res.get("category"),
                        }

                    return {
                        "sha256": attrs.get("sha256"),
                        "sha1": attrs.get("sha1"),
                        "md5": attrs.get("md5"),
                        "ssdeep": attrs.get("ssdeep"),
                        "tlsh": attrs.get("tlsh"),
                        "file_type": attrs.get("type_description"),
                        "magic": attrs.get("magic"),
                        "size": attrs.get("size"),
                        "name": attrs.get("meaningful_name")
                        or attrs.get("names", [""])[0]
                        if attrs.get("names")
                        else None,
                        "first_submission": attrs.get("first_submission_date"),
                        "last_submission": attrs.get("last_submission_date"),
                        "last_analysis": attrs.get("last_analysis_date"),
                        "stats": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "harmless": stats.get("harmless", 0),
                            "timeout": stats.get("timeout", 0),
                            "failure": stats.get("failure", 0),
                            "unsupported": stats.get("type-unsupported", 0),
                            "total": total,
                        },
                        "detections": detections,
                        "tags": attrs.get("tags", []),
                        "scan_time": t,
                    }
                # Есть данные но total=0 — reload
                if i % 4 == 0:
                    print(".", end="", flush=True)
                    result_data = {}
                    await tab.reload()
            elif i > 0 and i % 4 == 0:
                # Нет данных — reload
                print(".", end="", flush=True)
                result_data = {}
                await tab.reload()

        return {"md5": md5, "status": "timeout", "time": int(time.time() - start)}

    except Exception as e:
        import traceback

        traceback.print_exc()
        return {"error": str(e)}
    finally:
        browser.stop()


def main():
    if len(sys.argv) < 2:
        print("Usage: python vt_scraper.py <file_path>")
        sys.exit(1)
    fp = Path(sys.argv[1])
    r = uc.loop().run_until_complete(upload_and_scan(fp))
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
