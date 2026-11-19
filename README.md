# Shodan IP Address Collector

Collects IP addresses from Shodan search results and saves them to `collected-ip.txt` (one IP per line).

## Quick Start

### Windows
Double-click `run.bat` or run:
```cmd
run.bat
```

### Linux / macOS
```bash
chmod +x run.sh
./run.sh
```

---

## Two Modes

| Mode | Flag | Auth needed | Best for |
|------|------|-------------|----------|
| **Web Scraper** | `-m web` | `polito` session cookie | Free accounts, no API key needed |
| **Official API** | `-m api` | Shodan API key | Paid accounts with query credits (recommended) |

---

## How to Provide Your Session Cookie (Web Mode)

Shodan **requires** a logged-in session for web searches. Without it you get:
> *"Search usage limit reached. Please create a free account."*

### Option A: Cookie-Editor Extension (Easiest)

1. Install **Cookie-Editor** extension in your browser.
2. Go to https://www.shodan.io and log in.
3. Click the Cookie-Editor icon → **Export** → **JSON**.
4. Save the exported file as **`cookies.json`** in this folder (next to `shodan_scraper.py`).
5. Run the script — it auto-detects `cookies.json`.

### Option B: Browser DevTools

1. Log in to https://www.shodan.io
2. Press **F12** → **Application** (Chrome/Edge) or **Storage** (Firefox)
3. Expand **Cookies** → click `https://www.shodan.io`
4. Find the cookie named **`polito`** → copy its **Value**
5. Either:
   - Paste it when the script prompts, **or**
   - Put it in `credential.json`:
     ```json
     {
       "api_key": "",
       "cookie": "polito=YOUR_COOKIE_VALUE_HERE"
     }
     ```

### Option C: Pass on Command Line

```bash
python shodan_scraper.py -m web -q "port:445" -c "polito=s%3Aabc..."
```

---

## Credential Loading Priority

The script looks for credentials in this order:

1. **Command-line flags** (`-c` for cookie, `-k` for API key)
2. **`credential.json`** in the script directory
3. **`cookies.json`** in the script directory (Cookie-Editor JSON export)
4. **Interactive prompt** (if running without flags)

---

## Examples

```bash
# Interactive mode (prompts for everything)
python shodan_scraper.py

# Web scraper, 5 pages, auto-load cookie from cookies.json
python shodan_scraper.py -m web -q "port:53,88,135" -p 5

# Web scraper, unlimited pages, 5s delay
python shodan_scraper.py -m web -q "apache" -p 0 -d 5

# Official API mode
python shodan_scraper.py -m api -q "port:445 country:US" -k YOUR_API_KEY -p 3

# Custom output file
python shodan_scraper.py -m web -q "nginx" -o my-ips.txt
```

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-m` | Mode: `web` or `api` | `web` |
| `-q` | Shodan search query | prompted |
| `-c` | Session cookie string | auto-detected |
| `-k` | Shodan API key | auto-detected |
| `-p` | Max pages (0 = unlimited) | `10` |
| `-d` | Delay between requests (seconds) | `2.5` (web) / `1.0` (api) |
| `-o` | Output file path | `collected-ip.txt` |

---

## Security Warning

> **Never share or commit session cookies or API keys.**
> The `polito` cookie grants full access to your Shodan account.
> If exposed, log out of Shodan immediately to revoke the session.

## Shodan Terms of Service

- **Web scraping** Shodan's HTML interface may violate their Terms of Service.
- The **Official API** (`-m api`) is the recommended, fully compliant method.
- Get your API key at https://account.shodan.io
