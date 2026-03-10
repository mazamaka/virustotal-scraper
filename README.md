# VirusTotal Scraper

VirusTotal file scanner via browser automation and HTTP API. Upload files, scan for malware, and retrieve detailed analysis reports without manual interaction.

## Features

- **Two scanning approaches:**
  - Browser automation (`vt_scraper.py`): Uses headless Chrome with DOM parsing, minimal network requests
  - HTTP API (`vt_api.py`): Direct API requests, multiple lookup modes, official VT API v3 support

- **File upload and scan:** Upload files directly to VirusTotal and wait for analysis completion

- **Hash lookup:** Query existing scan results by MD5/SHA1/SHA256 without uploading

- **Proxy rotation:** Built-in proxy support with automatic rotation on failures

- **Result persistence:** Save scan results as JSON files for later processing

- **Rate limit handling:** API key rotation, retry logic, Sysinternals bulk API fallback

- **Shadow DOM support:** Parse results from modern VirusTotal UI with Shadow DOM

## Installation

### Requirements

- Python 3.11+
- For browser automation: Chromium (or use Docker)

### From source

```bash
git clone https://github.com/yourusername/virustotal-scraper.git
cd virustotal-scraper
pip install -e .
```

### Docker

```bash
docker-compose up -d
docker-compose exec vt-scraper python vt_scraper.py /data/sample.exe
```

## Usage

### Browser Automation Approach

Upload and scan a file:

```bash
vt-scan /path/to/file.exe
```

With proxy:

```bash
vt-scan /path/to/file.exe --proxy socks5://user:pass@proxy.host:1080
```

Proxy CSV file support:

```bash
vt-scan /path/to/file.exe --proxy proxies.csv
```

With retry logic:

```bash
vt-scan /path/to/file.exe --retries 5
```

Disable retry:

```bash
vt-scan /path/to/file.exe --no-retry
```

### API Approach (`vt_api.py`)

Upload and scan file via official VT API:

```bash
python vt_api.py /path/to/file.exe --api
```

Lookup hash (quick check via Sysinternals API, no rate limits):

```bash
python vt_api.py abc123def456 --bulk
```

Lookup hash with full report via browser (bypasses reCAPTCHA):

```bash
python vt_api.py abc123def456 --browser
```

Lookup hash with official VT API:

```bash
python vt_api.py abc123def456 --api
```

Extract your personal API key from browser session:

```bash
python vt_api.py --extract-key
# Opens browser for login, then extracts and displays your API key
```

## Proxy CSV Format

If using a proxy CSV file, format must be:

```csv
Protocol,Host,Port,Login,Password,Valid
socks5,proxy.example.com,1080,username,password,"true"
http,proxy2.example.com,8080,user2,pass2,"true"
```

The scanner reads only rows where `Valid="true"`.

## Output Format

### JSON Result Structure

```json
{
  "sha256": "abc123...",
  "sha1": "def456...",
  "md5": "ghi789...",
  "file_info": {
    "size": "1.5 MB",
    "type": "PE executable"
  },
  "stats": {
    "malicious": 5,
    "total": 70
  },
  "detections": {
    "Kaspersky": {
      "result": "detected",
      "category": "malicious"
    },
    "ESET-NOD32": {
      "result": null,
      "category": "undetected"
    }
  },
  "scan_time": 45
}
```

Results are saved to `./json/{hash}.json` automatically.

## Configuration

### Browser Automation

The browser approach uses `nodriver` to control Chromium in headless mode. Key environment variables:

- `CHROME_PATH`: Path to Chromium binary (default: detected automatically)

### API Approach

The API approach includes built-in public API keys and supports proxy rotation. For better rate limits, set your own API key:

```bash
export VT_API_KEY="your_64_char_key"
python vt_api.py target --api
```

## Error Handling

### Browser Approach

- Automatic retry on timeout or network errors
- Proxy rotation on failure (if proxy pool available)
- Graceful fallback when analysis doesn't complete

### API Approach

- Automatic API key rotation on rate limits (429 errors)
- Proxy rotation via `ProxyRotator` class
- Bulk API fallback for quick hash checks (no rate limits)

## Docker Usage

### Build

```bash
docker build -t virustotal-scraper:latest .
```

### Run with volume

```bash
# Copy files to scan
cp sample.exe ./data/

# Run scan
docker run --rm \
  -v $(pwd)/json:/app/json \
  -v $(pwd)/data:/data \
  --shm-size=2gb \
  virustotal-scraper:latest \
  /data/sample.exe
```

### Multiple files

```bash
docker run --rm \
  -v $(pwd)/json:/app/json \
  -v $(pwd)/data:/data \
  --shm-size=2gb \
  virustotal-scraper:latest \
  /data/file1.exe /data/file2.exe
```

## Performance Notes

- **Browser approach:** 20-60 seconds per file (includes analysis time)
- **API approach:** 1-5 seconds per lookup (depends on rate limits)
- **Bulk API:** <1 second for hash lookups (no rate limits, quick check only)

## Limitations

- **Browser approach:** Slower, higher resource usage, requires Chromium
- **API approach:** Subject to VT rate limits (4 req/min for full reports)
- **Bulk API:** Returns only detection count, not full details
- **Public API keys:** Limited rate, rotate frequently

## Architecture

### vt_scraper.py

Headless browser automation using `nodriver`:

1. Start Chromium in headless mode
2. Upload file via `fetch()` API
3. Navigate to results page
4. Poll DOM for analysis status (Shadow DOM aware)
5. Extract results via JavaScript
6. Save to JSON

**Pros:** Minimal requests, DOM parsing avoids API rate limits, Shadow DOM support
**Cons:** Slower, higher memory usage

### vt_api.py

HTTP API wrapper with multiple strategies:

1. **Upload mode:** POST to `/ui/files`, poll `/ui/analyses/{id}`
2. **Lookup mode:** GET from `/ui/files/{hash}`
3. **Bulk mode:** POST to Sysinternals partner API (no rate limits)
4. **API v3 mode:** Official VT API v3 with key rotation
5. **Browser mode:** DOM parsing for rate limit bypass

**Pros:** Fast, flexible, multiple fallback strategies
**Cons:** Subject to API rate limits

## Development

### Install dependencies

```bash
pip install nodriver httpx
```

### Code quality

```bash
ruff check --fix
ruff format
```

### Run tests

Currently no test suite. Contributions welcome!

## Troubleshooting

### "Chrome path not found"

Ensure Chromium is installed:

- **Linux:** `apt-get install chromium`
- **macOS:** `brew install chromium`
- **Windows:** Download from [chromium.org](https://download-chromium.appspot.com/)

Or set `CHROME_PATH` environment variable.

### Rate limited

- Use `--bulk` flag for quick hash checks (no limits)
- Use `--browser` flag for full reports via DOM parsing
- Wait 60+ seconds before retry
- Use different API keys if available

### Proxy errors

- Verify proxy format: `socks5://user:pass@host:port`
- Check proxy credentials and connectivity
- Ensure proxy supports CONNECT tunneling for HTTPS

### File too large

VirusTotal has file size limits:
- Free: 256 MB
- Premium: 500 MB

## License

MIT

## Disclaimer

This tool is for educational and authorized security research only. Ensure you have permission before scanning files you don't own. Respect VirusTotal's terms of service.

## Contributing

Issues and pull requests welcome. Please:

1. Use `ruff check` and `ruff format` before submitting
2. Add docstrings to new functions
3. Update README for significant changes
