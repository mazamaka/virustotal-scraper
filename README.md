# VirusTotal Scraper

![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-supported-blue?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)

Multi-strategy VirusTotal scanner: upload files, look up hashes, check URLs/domains/IPs. Supports browser automation, HTTP API, and official VT API v3 with smart rate limiting and proxy rotation.

## Features

- **4 scanning modules** with different trade-offs (speed, rate limits, detail level)
- **Browser automation** (`vt_scraper.py`) -- headless Chromium, Shadow DOM parsing, no API key needed
- **HTTP API** (`vt_api.py`) -- internal VT UI endpoints, proxy rotation, Sysinternals bulk fallback
- **Official API v3** (`vt_api_v3.py`) -- smart rate limiter with 3-key rotation (~12 req/min)
- **URL/Domain/IP checker** (`vt_url_checker.py`) -- parallel checking with worker pools
- **Proxy rotation** with CSV-based proxy pools and automatic failover
- **JSON result persistence** in `./json/` directory

## Quick Start

### With Docker

```bash
git clone https://github.com/mazamaka/virustotal-scraper.git
cd virustotal-scraper

# Build
docker compose build

# Scan a file
docker compose run --rm vt-scraper /data/sample.exe
```

### Without Docker

```bash
pip install nodriver httpx

# Browser scan (no API key needed)
python vt_scraper.py /path/to/file.exe

# API v3 hash lookup
python vt_api_v3.py <sha256_hash>

# Bulk hash check (no rate limits)
python vt_api.py <hash1> <hash2> --bulk

# URL check
python vt_url_checker.py https://example.com
```

## Modules

| Module | Method | Speed | Rate Limit | Detail |
|--------|--------|-------|-----------|--------|
| `vt_scraper.py` | Headless browser | 20-60s/file | None | Full |
| `vt_api.py` | Internal HTTP API | 1-5s/lookup | ~4 req/min | Full |
| `vt_api_v3.py` | Official API v3 | 1-5s/lookup | ~12 req/min (3 keys) | Full |
| `vt_api.py --bulk` | Sysinternals API | <1s/hash | None | Detection count only |
| `vt_url_checker.py` | API v3 | 1-3s/url | ~4 req/min/key | Full |

## Usage Examples

```bash
# Upload file via browser with proxy
python vt_scraper.py file.exe --proxy socks5://user:pass@host:1080

# Upload file via browser with proxy CSV and retry
python vt_scraper.py file.exe --proxy proxies.csv --retries 5

# Look up hash via official API v3
python vt_api_v3.py abc123def456 --lookup

# Upload file via API v3 (waits for analysis)
python vt_api_v3.py /path/to/file.exe --upload

# Request rescan of known file
python vt_api_v3.py <sha256> --rescan

# Bulk hash check (fast, no rate limits)
python vt_api.py hash1 hash2 hash3 --bulk

# Full report via browser DOM (bypasses reCAPTCHA)
python vt_api.py <hash> --browser

# Check multiple URLs in parallel
python vt_url_checker.py url1 url2 --workers 3 --output results.json

# Extract your VT API key from browser session
python vt_api.py --extract-key
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_API_KEY` | Personal VirusTotal API key | Built-in public keys |
| `CHROME_PATH` | Path to Chromium binary | Auto-detected |

## Proxy CSV Format

```csv
Protocol,Host,Port,Login,Password,Valid
socks5,proxy.example.com,1080,user,pass,"true"
http,proxy2.example.com,8080,user2,pass2,"true"
```

Only rows with `Valid="true"` are used. Proxies rotate automatically on failure.

## Output Format

Results are saved to `./json/<hash>.json`:

```json
{
  "sha256": "abc123...",
  "md5": "def456...",
  "stats": { "malicious": 5, "total": 70 },
  "detections": { "Kaspersky": { "result": "detected" } },
  "scan_time": 45
}
```

## Project Structure

```
.
├── vt_scraper.py       # Browser automation scanner
├── vt_api.py           # HTTP API scanner (internal endpoints + bulk)
├── vt_api_v3.py        # Official VT API v3 client
├── vt_url_checker.py   # URL/Domain/IP checker
├── Dockerfile          # Chromium + nodriver image
├── docker-compose.yml  # Compose config
├── pyproject.toml      # Project metadata and deps
├── proxies.csv         # Proxy pool (gitignored)
└── json/               # Scan results (gitignored)
```

## Limitations

- **Browser mode**: slower, needs Chromium, higher memory usage
- **API mode**: subject to VT rate limits (4 req/min per key)
- **Bulk API**: returns detection count only, not full vendor details
- **File size**: VT free tier limit is 256 MB

## License

MIT

## Disclaimer

For educational and authorized security research only. Respect [VirusTotal Terms of Service](https://www.virustotal.com/gui/terms-of-service).

## Author

**Maksym Babenko** -- [GitHub](https://github.com/mazamaka) | [Telegram](https://t.me/Mazamaka)
