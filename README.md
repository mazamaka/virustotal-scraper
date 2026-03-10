# VirusTotal Scraper

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Multi-strategy VirusTotal file scanner: headless browser automation, HTTP API, official API v3 with smart rate limiting, and URL/domain/IP reputation checker.

## Features

- **Browser Automation** (`vt_scraper.py`) -- headless Chrome via `nodriver`, Shadow DOM parsing, file upload through `fetch()` API
- **HTTP API Scanner** (`vt_api.py`) -- direct requests to VT internal UI endpoints, proxy rotation, Sysinternals bulk API fallback
- **Official API v3 Client** (`vt_api_v3.py`) -- smart rate limiter with 3-key rotation (12 req/min), large file upload (>32MB), batch operations
- **URL/Domain/IP Checker** (`vt_url_checker.py`) -- reputation checks, parallel workers, auto-scan missing URLs
- **Proxy Rotation** -- SOCKS5/HTTP proxy pool from CSV, automatic failover on errors
- **Retry Logic** -- configurable retries with proxy rotation on failures
- **Result Persistence** -- all scan results saved as JSON files

## Architecture

```
virustotal-scraper/
├── vt_scraper.py          # Browser automation (nodriver + Chromium)
├── vt_api.py              # HTTP API (internal VT endpoints + Sysinternals)
├── vt_api_v3.py           # Official VT API v3 (smart rate limiting)
├── vt_url_checker.py      # URL/Domain/IP reputation checker
├── Dockerfile             # Chromium + Python runtime
├── docker-compose.yml     # Container orchestration
├── proxies.csv            # Proxy pool (SOCKS5/HTTP)
├── json/                  # Scan results (auto-created)
└── data/                  # Input files for scanning
```

### Scanning Strategies

| Strategy | Script | Speed | Rate Limits | Use Case |
|----------|--------|-------|-------------|----------|
| Browser | `vt_scraper.py` | 20-60s/file | None | Full scan, bypass reCAPTCHA |
| Internal API | `vt_api.py` | 1-5s/lookup | ~4 req/min | Upload + lookup, proxy rotation |
| Official API v3 | `vt_api_v3.py` | <1s/lookup | 12 req/min (3 keys) | Batch lookups, production use |
| Bulk API | `vt_api.py --bulk` | <1s/hash | None | Quick hash check (detection count only) |
| URL Checker | `vt_url_checker.py` | ~1s/url | 4 req/min/key | URL/domain/IP reputation |

## Quick Start

### Prerequisites

- Python 3.11+
- Chromium (for browser automation only)

### Installation

```bash
git clone https://github.com/mazamaka/virustotal-scraper.git
cd virustotal-scraper
pip install -e .
```

### Docker

```bash
docker compose up -d
docker compose exec vt-scraper python vt_scraper.py /data/sample.exe
```

## Usage

### Browser Automation

```bash
# Upload and scan file
vt-scan /path/to/file.exe

# With proxy
vt-scan /path/to/file.exe --proxy socks5://user:pass@host:port

# With proxy CSV pool
vt-scan /path/to/file.exe --proxy proxies.csv

# Retry with proxy rotation
vt-scan /path/to/file.exe --retries 5
```

### HTTP API

```bash
# Upload file via internal API
python vt_api.py /path/to/file.exe

# Lookup hash (internal API, may be rate limited)
python vt_api.py abc123def456 --lookup

# Quick bulk check (Sysinternals API, no rate limits)
python vt_api.py hash1 hash2 hash3 --bulk

# Full report via browser DOM parsing
python vt_api.py abc123def456 --browser

# Official API v3
python vt_api.py abc123def456 --api

# Extract personal API key from browser session
python vt_api.py --extract-key
```

### Official API v3

```bash
# Lookup hash
python vt_api_v3.py abc123def456

# Upload file
python vt_api_v3.py /path/to/file.exe --upload

# Batch lookup
python vt_api_v3.py hash1 hash2 hash3 --lookup

# Rescan existing file
python vt_api_v3.py abc123def456 --rescan

# Show rate limiter stats
python vt_api_v3.py hash1 --stats
```

### URL/Domain/IP Checker

```bash
# Check URL
python vt_url_checker.py https://example.com

# Check from file
python vt_url_checker.py --file urls.txt --workers 3

# Save results
python vt_url_checker.py https://example.com --output results.json
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CHROME_PATH` | Path to Chromium binary | Auto-detected |
| `VT_API_KEY` | Personal VirusTotal API key | Built-in public keys |

### Proxy CSV Format

```csv
Protocol,Host,Port,Login,Password,Valid
socks5,proxy.example.com,1080,user,pass,"true"
http,proxy2.example.com,8080,user2,pass2,"true"
```

Only rows with `Valid="true"` are used. Scanner rotates through available proxies on failures.

## Output Format

```json
{
  "sha256": "abc123...",
  "sha1": "def456...",
  "md5": "ghi789...",
  "file_info": { "size": "1.5 MB", "type": "PE executable" },
  "stats": { "malicious": 5, "total": 70 },
  "detections": {
    "Kaspersky": { "result": "detected", "category": "malicious" }
  },
  "scan_time": 45
}
```

Results auto-saved to `./json/{hash}.json`.

## Docker

```bash
# Build
docker build -t virustotal-scraper:latest .

# Scan file
docker run --rm \
  -v $(pwd)/json:/app/json \
  -v $(pwd)/data:/data \
  --shm-size=2gb \
  virustotal-scraper:latest \
  /data/sample.exe

# Multiple files
docker run --rm \
  -v $(pwd)/json:/app/json \
  -v $(pwd)/data:/data \
  --shm-size=2gb \
  virustotal-scraper:latest \
  /data/file1.exe /data/file2.exe
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Lint and format
ruff check --fix .
ruff format .
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Chrome path not found | `apt install chromium` or set `CHROME_PATH` |
| Rate limited (429) | Use `--bulk` for quick checks, or `--browser` for DOM parsing |
| Proxy errors | Verify format: `socks5://user:pass@host:port` |
| File too large | VT limit: 256MB (free), 500MB (premium) |

## Author

**Maksym Babenko**
- GitHub: [@mazamaka](https://github.com/mazamaka)
- Telegram: [@Mazamaka](https://t.me/Mazamaka)

## License

MIT

## Disclaimer

For educational and authorized security research only. Respect VirusTotal's terms of service.
