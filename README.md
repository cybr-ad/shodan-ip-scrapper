# Shodan IP Address Collector & Scraper

A robust helper script for collecting IP addresses from Shodan search queries and saving them into `collected-ip.txt`. 

It supports two modes:
1. **Web Session Scraper**: Uses an authenticated browser session cookie (`polito`) to parse Shodan web search result pages.
2. **Official Shodan API** *(Recommended & ToS Compliant)*: Uses the official Shodan API library and your Shodan API key to fetch results without HTML scraping or Cloudflare bot blocks.

---

## Features

- **Interactive or CLI Execution**: Run without arguments for a guided prompt, or pass CLI flags for automation.
- **Polite Rate Limiting**: Built-in 2.5s delay between requests to avoid server flooding.
- **Session Expiration & Redirect Detection**: Automatically stops cleanly if the session cookie expires, redirects to `/account/login`, or if account limits are reached.
- **Strict IP Validation**: Validates all captured strings with Python's standard `ipaddress` library (supports both IPv4 and IPv6) to eliminate false positives.
- **Immediate Disk Flushing**: IPs are appended and synced to disk in real-time, ensuring no collected data is lost if interrupted (Ctrl+C).
- **Cross-Platform Launchers**: Includes `run.bat` for Windows and `run.sh` for Linux/macOS.

---

## Quick Start

### Windows
Double-click `run.bat` or run in Command Prompt / PowerShell:
```cmd
run.bat
```
*(Automatically checks for Python and installs missing dependencies).*

### Linux / macOS
Make the script executable and run:
```bash
chmod +x run.sh
./run.sh
```

### Direct Python Execution
```bash
pip install -r requirements.txt
python shodan_scraper.py
```

---

## Command Line Usage (Non-Interactive)

You can bypass interactive prompts by passing arguments directly:

```bash
# Web Scraper mode with cookie:
python shodan_scraper.py -m web -q "port:53,88,135" -c "polito=s%3A..." --pages 5

# Web Scraper mode with custom delay and output file:
python shodan_scraper.py -m web -q "apache" -c "s%3A..." --delay 3.0 -o my_ips.txt

# Official API mode (recommended):
python shodan_scraper.py -m api -q "port:445 country:US" -k "YOUR_SHODAN_API_KEY" --pages 3
```

### CLI Arguments Reference
| Flag | Description | Default |
|------|-------------|---------|
| `-m`, `--mode` | Collection mode (`web` or `api`) | `web` |
| `-q`, `--query` | Shodan search query string | Prompted |
| `-c`, `--cookie` | Shodan `polito` session cookie or full Cookie header | None |
| `-k`, `--api-key` | Shodan API key (can also use `SHODAN_API_KEY` env var) | None |
| `-p`, `--pages` | Maximum pages to fetch (`0` for all available) | `10` |
| `-d`, `--delay` | Seconds between requests | `2.5` (web), `1.0` (api) |
| `-o`, `--output` | Destination output file | `collected-ip.txt` |

---

## How to Extract Your Browser Session Cookie (`polito`)

If using the **Web Session Scraper** mode to view results under your account:

1. Open your browser and log into **[https://www.shodan.io](https://www.shodan.io)**.
2. Press `F12` (or right-click anywhere and select **Inspect**) to open Developer Tools.
3. Locate your cookies based on your browser:
   - **Google Chrome / Brave / Edge**: Go to the **Application** tab -> expand **Storage** -> **Cookies** -> click `https://www.shodan.io`.
   - **Mozilla Firefox**: Go to the **Storage** tab -> expand **Cookies** -> click `https://www.shodan.io`.
   - **Safari**: Go to **Develop** -> **Show Web Inspector** -> **Storage** tab -> **Cookies**.
4. In the table, find the cookie with the Name **`polito`**.
5. Double-click its **Value** and copy it (it usually looks like `s%3A...` or a URL-encoded string).
6. When prompted by the script, paste the value. The script accepts:
   - Just the value: `s%3Aabc...`
   - Key=Value: `polito=s%3Aabc...`
   - The entire header: `Cookie: polito=s%3Aabc...; __cf_bm=...`

---

## ⚠️ Security Caveats for Session Cookies

> [!WARNING]
> **Protect Your Session Cookie:**
> - The `polito` cookie is a bearer credential that grants full access to your Shodan account, including stored credits, membership privileges, billing details, and saved queries.
> - **Never** commit your cookie to GitHub, paste it in public forums, or share it.
> - If you accidentally expose your cookie, log out of Shodan immediately in your browser; logging out revokes the session on Shodan's authentication backend.

---

## ⚖️ Shodan Terms of Service & Cloudflare Considerations

### Why Web Scraping Is Problematic on Shodan:
1. **Terms of Service (ToS)**: Shodan's Terms of Service explicitly prohibit automated web crawling and screen scraping of its web interface (`https://www.shodan.io/terms`).
2. **Cloudflare Bot Management**: Shodan employs Cloudflare to detect automated HTTP clients. Cloudflare inspects TLS fingerprints (JA3/JA4) and HTTP request headers. Scripts using basic HTTP libraries (`requests`, `urllib`) can be blocked with `403 Forbidden` or Cloudflare challenge pages (Turnstile).
3. **Web Search Pagination Caps**: Shodan's web interface restricts pagination:
   - Anonymous (guest): Typically restricted to page 1.
   - Free logged-in accounts: Typically restricted to page 2 (showing *"Please upgrade your account to view more results"* on page 3).
   - Only paid membership/enterprise accounts have extended web pagination.

### The Official API Alternative (Recommended):
Shodan provides an official REST API specifically built for automated querying:
- **Zero Cloudflare blocking**: Designed for automated clients.
- **Structured JSON**: No brittle HTML parsing.
- **Compliant**: 100% compliant with Shodan terms.
- **How to use**: Log in to [account.shodan.io](https://account.shodan.io), grab your API key from the dashboard, and select **Option [2]** in this tool!
