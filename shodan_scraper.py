#!/usr/bin/env python3
"""
Shodan IP Address Collector
Collects IP addresses from Shodan search results and saves them to a file.

Supports two modes:
  1. Web Scraper  - Parses Shodan web pages (authenticated via session cookie)
  2. Official API - Uses the Shodan Python library (authenticated via API key)

Usage:
  Interactive:   python shodan_scraper.py
  Web mode:      python shodan_scraper.py -m web -q "port:445" -p 5
  API mode:      python shodan_scraper.py -m api -q "port:445" -k YOUR_KEY
"""

import sys
import os
import re
import json
import time
import argparse
import ipaddress
import urllib.parse
from typing import List, Set, Dict

import requests
from bs4 import BeautifulSoup

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------
class C:
    H  = '\033[95m'
    B  = '\033[94m'
    CN = '\033[96m'
    G  = '\033[92m'
    Y  = '\033[93m'
    R  = '\033[91m'
    X  = '\033[0m'
    BO = '\033[1m'


def _win_ansi():
    if os.name == 'nt':
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_ulong()
            if k.GetConsoleMode(h, ctypes.byref(m)):
                k.SetConsoleMode(h, m.value | 0x0004)
        except Exception:
            pass


def banner():
    print(f"""{C.CN}{C.BO}
========================================================================
                     SHODAN IP ADDRESS COLLECTOR
========================================================================{C.X}
  Output     : collected-ip.txt (default)
  Features   : Pagination, Rate-Limiting, Cookie / API Key auth,
               IPv4+IPv6 validation, real-time file sync
========================================================================
""")


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
def _is_valid_cookie_value(val: str) -> bool:
    """Checks if a cookie string looks like a real token rather than empty or placeholder."""
    val = val.strip()
    if not val:
        return False
    if len(val) < 8:
        return False
    if val in ("YOUR_SESSION_COOKIE", "YOUR_COOKIE_VALUE_HERE", "polito=YOUR_SESSION_COOKIE"):
        return False
    return True


def load_credential_file(path: str = "credential.json") -> dict:
    """
    Load credential.json or cookies.json.
    Returns dict with 'api_key' and/or 'cookie'.
    Supports:
      - {"api_key": "...", "cookie": "..."}
      - Cookie-Editor JSON array: [{"name": "polito", "value": "..."}, ...]
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out = {}

    # 1. Try specified path (credential.json)
    p = os.path.join(script_dir, path)
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                # Cookie-Editor JSON array pasted directly into credential.json
                cookies_list = []
                for item in data:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        val = str(item["value"]).strip()
                        if _is_valid_cookie_value(val):
                            cookies_list.append(f"{item['name']}={val}")
                if cookies_list:
                    out["cookie"] = "; ".join(cookies_list)
                else:
                    print(f"{C.Y}[!] Notice: 'polito' cookie in {path} has an empty or invalid value.{C.X}")
            elif isinstance(data, dict):
                if data.get("api_key") and data["api_key"] not in ("", "YOUR_SHODAN_API_KEY"):
                    out["api_key"] = data["api_key"].strip()
                if data.get("cookie"):
                    val = data["cookie"].strip()
                    if _is_valid_cookie_value(val):
                        out["cookie"] = val
                    else:
                        print(f"{C.Y}[!] Notice: 'cookie' in {path} has an empty or placeholder value.{C.X}")
        except Exception:
            pass

    # 2. If no valid cookie found yet, try cookies.json (Cookie-Editor export file)
    if "cookie" not in out:
        cookies_path = os.path.join(script_dir, "cookies.json")
        if os.path.isfile(cookies_path):
            try:
                with open(cookies_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    cookies_list = []
                    for item in data:
                        if isinstance(item, dict) and "name" in item and "value" in item:
                            val = str(item["value"]).strip()
                            if _is_valid_cookie_value(val):
                                cookies_list.append(f"{item['name']}={val}")
                    if cookies_list:
                        out["cookie"] = "; ".join(cookies_list)
                        print(f"{C.G}[i] Automatically loaded valid session cookies from cookies.json{C.X}")
            except Exception:
                pass

    return out


def parse_cookie_string(raw: str) -> Dict[str, str]:
    """Turn user input into a {name: value} cookie dict.

    Accepts:
      - raw polito value                   s%3Aabc...
      - name=value                         polito=s%3Aabc...
      - full header                        Cookie: polito=s%3Aabc...; __cf_bm=xyz
      - Cookie-Editor JSON export          [{"name":"polito","value":"..."}]
      - our credential.json snippet        {"cookie":"polito=..."}
    """
    raw = raw.strip()
    if not raw:
        return {}

    # If wrapped in quotes: "..." or '...'
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1].strip()

    # Try JSON (Cookie-Editor list or our dict)
    if raw.startswith("[") or raw.startswith("{"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, list):
                cookies = {}
                for item in obj:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        val = str(item["value"]).strip()
                        if _is_valid_cookie_value(val):
                            cookies[item["name"]] = val
                if cookies:
                    return cookies
            if isinstance(obj, dict):
                if "cookie" in obj:
                    return parse_cookie_string(str(obj["cookie"]))
                res = {}
                for k, v in obj.items():
                    val = str(v).strip()
                    if _is_valid_cookie_value(val):
                        res[str(k)] = val
                return res
        except json.JSONDecodeError:
            pass

    # Strip "Cookie:" prefix
    if raw.lower().startswith("cookie:"):
        raw = raw[7:].strip()

    cookies: Dict[str, str] = {}
    if "=" in raw:
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and _is_valid_cookie_value(v):
                    cookies[k] = v
    else:
        if _is_valid_cookie_value(raw):
            cookies["polito"] = raw

    return cookies


def read_multiline_cookie_input() -> str:
    """Reads cookie input from terminal stdin, cleanly handling multi-line pasted JSON."""
    first_line = sys.stdin.readline()
    if not first_line:
        return ""
    line = first_line.strip()
    if (line.startswith("[") and not line.endswith("]")) or (line.startswith("{") and not line.endswith("}")):
        end_char = "]" if line.startswith("[") else "}"
        lines = [line]
        while True:
            next_line = sys.stdin.readline()
            if not next_line:
                break
            clean = next_line.strip()
            lines.append(clean)
            if clean.endswith(end_char):
                break
        return "\n".join(lines)
    return line


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------
_HOST_IP_RE = re.compile(r'/host/([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})')
_HOST_IPV6_RE = re.compile(r'/host/([0-9a-fA-F:]+)')
_EXT_IP_RE = re.compile(r'href=["\']https?://([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})')


def extract_ips(html: str) -> List[str]:
    """Extract validated IP addresses from raw Shodan HTML."""
    seen: Set[str] = set()
    result: List[str] = []

    # Strategy 1: regex on raw text for /host/<ipv4>
    for m in _HOST_IP_RE.finditer(html):
        ip = m.group(1)
        if ip not in seen:
            try:
                ipaddress.ip_address(ip)
                seen.add(ip)
                result.append(ip)
            except ValueError:
                pass

    # Strategy 2: IPv6 hosts
    for m in _HOST_IPV6_RE.finditer(html):
        ip = m.group(1)
        if ip not in seen and ":" in ip:
            try:
                ipaddress.ip_address(ip)
                seen.add(ip)
                result.append(ip)
            except ValueError:
                pass

    # Strategy 3: Result headings or external links href="http://<ip>:<port>"
    if not result:
        for m in _EXT_IP_RE.finditer(html):
            ip = m.group(1)
            if ip not in seen:
                try:
                    ipaddress.ip_address(ip)
                    seen.add(ip)
                    result.append(ip)
                except ValueError:
                    pass

    # Strategy 4: fallback — BS4
    if not result:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/host/"):
                    ip = href[6:].split("/")[0].split("?")[0].split("#")[0].strip()
                    if ip not in seen:
                        try:
                            ipaddress.ip_address(ip)
                            seen.add(ip)
                            result.append(ip)
                        except ValueError:
                            pass
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _load_existing(path: str) -> Set[str]:
    """Load already-collected IPs from file to avoid duplicates."""
    existing: Set[str] = set()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        existing.add(ip)
            if existing:
                print(f"{C.B}[i] Loaded {len(existing)} existing IPs from {path}{C.X}")
        except Exception:
            pass
    return existing


# ---------------------------------------------------------------------------
# Web scraper
# ---------------------------------------------------------------------------
def scrape_web(query: str, cookie_str: str, max_pages: int,
               delay: float, output: str) -> int:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.shodan.io/",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    })

    cookies = parse_cookie_string(cookie_str)
    if cookies:
        session.cookies.update(cookies)
        print(f"{C.G}[+] Session cookies loaded: {', '.join(cookies.keys())}{C.X}")
    else:
        print(f"{C.Y}[!] No valid cookie loaded — running as guest (pagination blocked on page 2).{C.X}")

    all_ips = _load_existing(output)
    saved = 0
    eq = urllib.parse.quote_plus(query)
    page = 1

    print(f"\n{C.BO}[*] Query : {C.CN}{query}{C.X}")
    print(f"[*] Delay : {delay}s   Max pages: {'unlimited' if max_pages <= 0 else max_pages}")
    print(f"[*] Output: {os.path.abspath(output)}\n")

    with open(output, "a", encoding="utf-8") as fout:
        while True:
            if 0 < max_pages < page:
                print(f"\n{C.G}[+] Reached page limit ({max_pages}). Done.{C.X}")
                break

            if page > 1 and delay > 0:
                time.sleep(delay)

            url = f"https://www.shodan.io/search?query={eq}&page={page}"
            print(f"{C.B}[*] Page {page}...{C.X}  {url}")

            resp = None
            for attempt in range(1, 4):
                try:
                    resp = session.get(url, timeout=30, allow_redirects=True)
                except requests.RequestException as e:
                    if attempt == 3:
                        print(f"{C.R}[!] Network error: {e}{C.X}")
                        resp = None
                        break
                    time.sleep(3)
                    continue

                # Check for transient Shodan 500 server error
                if resp.status_code == 500 or (resp.status_code == 200 and "oops, something went wrong" in resp.text.lower()):
                    if attempt < 3:
                        wait_sec = attempt * 5
                        print(f"{C.Y}[!] Shodan server busy ('Oops, something went wrong'). Retrying page {page} in {wait_sec}s (attempt {attempt}/3)...{C.X}")
                        time.sleep(wait_sec)
                        continue
                break

            if resp is None:
                break

            # --- error handling ---
            if resp.status_code == 429:
                print(f"{C.R}[!] Rate-limited (HTTP 429). Stopping cleanly.{C.X}")
                break
            if resp.status_code in (401, 403):
                low = resp.text.lower()
                if any(w in low for w in ("cloudflare", "challenge", "turnstile")):
                    print(f"{C.R}[!] Cloudflare challenge on page {page}.{C.X}")
                else:
                    print(f"{C.R}[!] HTTP {resp.status_code} — access denied / session expired.{C.X}")
                break
            if resp.status_code != 200:
                print(f"{C.R}[!] HTTP {resp.status_code}. Stopping.{C.X}")
                break
            if "/account/login" in resp.url.lower():
                print(f"{C.R}[!] Redirected to login — cookie expired or invalid.{C.X}")
                break

            body = resp.text
            low = body.lower()

            # Check Shodan auth requirement message (happens on page 2 without valid login)
            if "log in to access more results" in low or "create a shodan account and log in" in low:
                print(f"\n{C.R}[!] Shodan Auth Required on Page {page}:{C.X}")
                print(f"{C.YELLOW}    'Please create a Shodan account and log in to access more results.'{C.X}")
                print(f"{C.YELLOW}    -> Your session cookie was missing, invalid, or expired.{C.X}")
                print(f"{C.YELLOW}    -> Shodan allows guest searches on Page 1, but requires a logged-in cookie for Page 2+.{C.X}")
                print(f"{C.YELLOW}    -> Please copy your real 'polito' cookie from Cookie-Editor and paste it.{C.X}")
                break

            # Check search usage limit
            if "search usage limit reached" in low:
                print(f"\n{C.R}[!] Shodan says: 'Search usage limit reached'.{C.X}")
                print(f"{C.Y}    You MUST provide a valid session cookie (polito) to continue.{C.X}")
                break

            # Check query no results
            if "no results found" in low and page == 1:
                print(f"{C.Y}[i] No results found for this query.{C.X}")
                break

            # Check account tier limit (free registered accounts can only access pages 1 and 2)
            if (
                "upgrade your account to view more results" in low
                or "upgrade your account" in low
                or "purchase a shodan membership" in low
                or "more than 2 pages of results" in low
            ):
                print(f"\n{C.Y}[i] Shodan free account limit reached on Page {page}:{C.X}")
                print(f"{C.Y}    'Please purchase a Shodan membership to access more than 2 pages of results.'{C.X}")
                print(f"{C.Y}    Free registered accounts are restricted to 2 pages (20 results) on the web UI.{C.X}")
                print(f"{C.Y}    All available results ({len(all_ips)} IPs) have been collected into your file!{C.X}")
                break

            # --- extract IPs ---
            page_ips = extract_ips(body)
            if not page_ips:
                if page == 1:
                    print(f"{C.Y}[i] Zero IPs detected on page 1. The session cookie may be invalid or missing.{C.X}")
                else:
                    print(f"{C.Y}[i] No more IPs detected on page {page}. End of available results.{C.X}")
                break

            new = []
            for ip in page_ips:
                if ip not in all_ips:
                    all_ips.add(ip)
                    new.append(ip)
                    fout.write(ip + "\n")
                    saved += 1
            fout.flush()
            os.fsync(fout.fileno())

            print(f"{C.G}[+] Page {page}: {len(page_ips)} IPs "
                  f"({len(new)} new unique) | total collected: {len(all_ips)}{C.X}")
            page += 1

    return saved


# ---------------------------------------------------------------------------
# Official API
# ---------------------------------------------------------------------------
def scrape_api(query: str, api_key: str, max_pages: int,
               delay: float, output: str) -> int:
    if not SHODAN_AVAILABLE:
        print(f"{C.R}[!] 'shodan' library not installed. Run: pip install shodan{C.X}")
        return 0
    if not api_key:
        api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        print(f"{C.R}[!] No API key provided.{C.X}")
        return 0

    api = shodan_lib.Shodan(api_key)
    try:
        info = api.info()
        print(f"{C.G}[+] API authenticated.  "
              f"Query credits: {info.get('query_credits','?')}  "
              f"Scan credits: {info.get('scan_credits','?')}{C.X}")
        if info.get("query_credits", 1) == 0:
            print(f"{C.Y}[!] Warning: 0 query credits remaining — search queries may fail.{C.X}")
    except shodan_lib.APIError as e:
        print(f"{C.R}[!] API auth error: {e}{C.X}")
        return 0

    all_ips = _load_existing(output)
    saved = 0
    page = 1

    print(f"\n{C.BO}[*] Query : {C.CN}{query}{C.X}")
    print(f"[*] Output: {os.path.abspath(output)}\n")

    with open(output, "a", encoding="utf-8") as fout:
        while True:
            if 0 < max_pages < page:
                print(f"\n{C.G}[+] Reached page limit ({max_pages}).{C.X}")
                break
            if page > 1 and delay > 0:
                time.sleep(delay)

            print(f"{C.B}[*] API page {page}...{C.X}")
            try:
                results = api.search(query, page=page)
            except shodan_lib.APIError as e:
                msg = str(e).lower()
                if any(w in msg for w in ("invalid", "empty", "no results")):
                    print(f"{C.Y}[i] End of results: {e}{C.X}")
                elif "credits" in msg:
                    print(f"{C.R}[!] Insufficient credits: {e}{C.X}")
                elif "rate" in msg:
                    print(f"{C.R}[!] Rate limit: {e}{C.X}")
                else:
                    print(f"{C.R}[!] API error: {e}{C.X}")
                break

            matches = results.get("matches", [])
            total = results.get("total", 0)
            if not matches:
                print(f"{C.Y}[i] No more matches (page {page}).{C.X}")
                break

            new = []
            for m in matches:
                ip = m.get("ip_str")
                if ip and ip not in all_ips:
                    try:
                        ipaddress.ip_address(ip)
                        all_ips.add(ip)
                        new.append(ip)
                        fout.write(ip + "\n")
                        saved += 1
                    except ValueError:
                        pass
            fout.flush()
            os.fsync(fout.fileno())

            print(f"{C.G}[+] Page {page}: {len(matches)} results "
                  f"({len(new)} new) | total unique: {len(all_ips)} "
                  f"(API total: {total}){C.X}")

            if len(matches) < 100:
                print(f"{C.G}[i] Last page received.{C.X}")
                break
            page += 1

    return saved


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
def interactive():
    banner()

    # Auto-load credentials
    creds = load_credential_file()

    print(f"{C.BO}Select mode:{C.X}")
    print(f"  {C.CN}[1]{C.X} Web Scraper  (cookie-based, parses Shodan search)")
    print(f"  {C.G}[2]{C.X} Official API (recommended, uses Shodan API key)")
    choice = input("\nChoice (1/2, default 1): ").strip()
    if choice not in ("1", "2"):
        choice = "1"

    # Query
    while True:
        query = input(f"\n{C.BO}Shodan query{C.X} (e.g. port:53,88,135): ").strip()
        if query:
            break
        print(f"{C.Y}[!] Query cannot be empty.{C.X}")

    output = input(f"\nOutput file (default: collected-ip.txt): ").strip() or "collected-ip.txt"

    if choice == "1":
        # --- Web mode ---
        print(f"\n{C.BO}--- Session Cookie ---{C.X}")
        print("How to get it:")
        print("  Option 1: Cookie-Editor extension -> Export As -> JSON or Header String")
        print("  Option 2: F12 -> Application -> Cookies -> shodan.io -> copy 'polito' value")

        cookie_val = ""
        if creds.get("cookie"):
            print(f"\n{C.G}[i] Found valid cookie in credential.json / cookies.json — using it automatically.{C.X}")
            cookie_val = creds["cookie"]
        else:
            print("\nPaste cookie (Header String or Cookie-Editor JSON), or press Enter for guest:")
            print("> ", end="", flush=True)
            cookie_val = read_multiline_cookie_input()

        pages_in = input("\nMax pages (default 10, 0=unlimited): ").strip()
        try:
            max_pages = int(pages_in) if pages_in else 10
        except ValueError:
            max_pages = 10

        delay_in = input("Delay in seconds (default 2.5): ").strip()
        try:
            delay = float(delay_in) if delay_in else 2.5
        except ValueError:
            delay = 2.5

        saved = scrape_web(query, cookie_val, max_pages, delay, output)

    else:
        # --- API mode ---
        if creds.get("api_key"):
            print(f"\n{C.G}[i] Found API key in credential.json — using it automatically.{C.X}")
            api_key = creds["api_key"]
        else:
            api_key = input("\nShodan API key: ").strip()

        pages_in = input("\nMax pages (default 10, 0=unlimited): ").strip()
        try:
            max_pages = int(pages_in) if pages_in else 10
        except ValueError:
            max_pages = 10

        delay_in = input("Delay in seconds (default 1.0): ").strip()
        try:
            delay = float(delay_in) if delay_in else 1.0
        except ValueError:
            delay = 1.0

        saved = scrape_api(query, api_key, max_pages, delay, output)

    print(f"\n{C.CN}{'='*72}{C.X}")
    print(f"{C.G}{C.BO}[+] Done! {saved} new unique IPs saved.{C.X}")
    print(f"[*] File: {C.BO}{os.path.abspath(output)}{C.X}")
    print(f"{C.CN}{'='*72}{C.X}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    _win_ansi()

    parser = argparse.ArgumentParser(
        description="Collect IPs from Shodan searches.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python shodan_scraper.py                                      # interactive
  python shodan_scraper.py -m web -q "apache" -p 5              # web, 5 pages
  python shodan_scraper.py -m api -q "port:445" -k KEY -p 0     # API, all pages
""")
    parser.add_argument("-m", "--mode", choices=["web", "api"])
    parser.add_argument("-q", "--query")
    parser.add_argument("-c", "--cookie", default="")
    parser.add_argument("-k", "--api-key", default="")
    parser.add_argument("-p", "--pages", type=int, default=10)
    parser.add_argument("-d", "--delay", type=float, default=None)
    parser.add_argument("-o", "--output", default="collected-ip.txt")

    if len(sys.argv) == 1:
        interactive()
        return

    args = parser.parse_args()
    creds = load_credential_file()

    if not args.cookie and creds.get("cookie"):
        args.cookie = creds["cookie"]
    if not args.api_key and creds.get("api_key"):
        args.api_key = creds["api_key"]

    if not args.query:
        args.query = input("Shodan query: ").strip()
        if not args.query:
            print("No query provided.")
            return

    mode = args.mode or "web"
    if mode == "web":
        delay = args.delay if args.delay is not None else 2.5
        saved = scrape_web(args.query, args.cookie, args.pages, delay, args.output)
    else:
        delay = args.delay if args.delay is not None else 1.0
        saved = scrape_api(args.query, args.api_key, args.pages, delay, args.output)

    print(f"\n{C.G}[+] Done. {saved} new IPs -> {args.output}{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted. Saved IPs remain in the output file.{C.X}")
        sys.exit(0)
