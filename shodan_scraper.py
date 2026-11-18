#!/usr/bin/env python3
"""
Shodan IP Address Collector & Scraper
Author: Assistant
Description:
    Collects IP addresses from Shodan search queries and writes them
    one-per-line to a file (default: collected-ip.txt).
    Supports:
    1. Web Session Scraper: Uses authenticated browser session cookies (polito)
       with HTML parsing and polite rate limiting.
    2. Official Shodan API: Uses official Shodan API Key (recommended & ToS compliant).
"""

import sys
import os
import re
import time
import argparse
import ipaddress
import urllib.parse
from typing import List, Set, Dict, Optional, Tuple

import requests
from bs4 import BeautifulSoup

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


# ANSI color codes for terminal formatting
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def enable_windows_ansi():
    """Enable ANSI escape sequences on Windows consoles if supported."""
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
========================================================================
                     SHODAN IP ADDRESS COLLECTOR
========================================================================{Colors.RESET}
  Target File: collected-ip.txt
  Features   : Pagination, Rate-Limiting, Session Expiration Detection,
               IPv4/IPv6 Validation, Real-Time File Sync
========================================================================
"""
    print(banner)


def parse_cookie_input(cookie_input: str) -> Dict[str, str]:
    """
    Parses various cookie input formats:
    - Raw value: 's%3Aabc123...'
    - Key=Value: 'polito=s%3Aabc123...'
    - Header line: 'Cookie: polito=s%3Aabc123...; __cf_bm=xyz'
    """
    cookie_input = cookie_input.strip()
    if not cookie_input:
        return {}

    # Strip header prefix if user pasted the entire "Cookie: ..." header
    if cookie_input.lower().startswith("cookie:"):
        cookie_input = cookie_input[7:].strip()

    cookies: Dict[str, str] = {}
    if "=" in cookie_input:
        parts = cookie_input.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
    else:
        # User pasted just the 'polito' session cookie value
        cookies["polito"] = cookie_input

    return cookies


def extract_ips_from_html(html_content: str) -> List[str]:
    """
    Extracts valid IP addresses (IPv4 and IPv6) from Shodan search result HTML.
    Targets host links (/host/<ip>) and search-result title elements.
    Validates each candidate with the ipaddress module to prevent false positives.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    extracted: List[str] = []
    seen: Set[str] = set()

    # Strategy 1: Find all /host/<ip> anchor links (primary Shodan format)
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if href.startswith("/host/"):
            # Clean off trailing paths, parameters, or hashes
            potential_ip = href[len("/host/"):].split("/")[0].split("?")[0].split("#")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(potential_ip)
                if potential_ip not in seen:
                    seen.add(potential_ip)
                    extracted.append(potential_ip)
            except ValueError:
                continue

    # Strategy 2: Search within result titles/headings if /host/ links were altered
    if not extracted:
        ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for elem in soup.find_all(class_=re.compile(r"title|heading|ip")):
            text = elem.get_text(strip=True)
            match = ip_regex.search(text)
            if match:
                potential_ip = match.group(0)
                try:
                    ipaddress.ip_address(potential_ip)
                    if potential_ip not in seen:
                        seen.add(potential_ip)
                        extracted.append(potential_ip)
                except ValueError:
                    continue

    return extracted


def scrape_shodan_web(
    query: str,
    cookie_str: str = "",
    max_pages: int = 10,
    delay: float = 2.5,
    output_path: str = "collected-ip.txt"
) -> int:
    """
    Scrapes Shodan web search results page by page using a session cookie.
    Handles polite rate limiting, redirects, session expiration, and Cloudflare alerts.
    """
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

    cookies = parse_cookie_input(cookie_str)
    if cookies:
        session.cookies.update(cookies)
        print(f"{Colors.GREEN}[+] Loaded session cookies: {', '.join(cookies.keys())}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] No cookie provided. Querying as anonymous/guest (Shodan typically restricts pagination to 1 page).{Colors.RESET}")

    all_collected_ips: Set[str] = set()
    total_saved_this_run = 0

    # Ensure output directory exists
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Load existing IPs from file if file exists (to prevent writing duplicates)
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        all_collected_ips.add(ip)
            if all_collected_ips:
                print(f"{Colors.BLUE}[i] Existing {output_path} loaded with {len(all_collected_ips)} IPs. Appending new unique entries.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Could not read existing output file: {e}{Colors.RESET}")

    encoded_query = urllib.parse.quote_plus(query)
    current_page = 1

    print(f"\n{Colors.BOLD}[*] Starting Web Scrape for query: {Colors.CYAN}{query}{Colors.RESET}")
    print(f"[*] Delay between pages: {delay}s | Max pages: {'Unlimited' if max_pages <= 0 else max_pages}")
    print(f"[*] Output destination : {os.path.abspath(output_path)}\n")

    with open(output_path, "a", encoding="utf-8") as out_file:
        while True:
            if max_pages > 0 and current_page > max_pages:
                print(f"\n{Colors.GREEN}[+] Reached configured maximum page limit ({max_pages}). Stopping cleanly.{Colors.RESET}")
                break

            # Polite rate limiting between requests
            if current_page > 1 and delay > 0:
                time.sleep(delay)

            url = f"https://www.shodan.io/search?query={encoded_query}&page={current_page}"
            print(f"{Colors.BLUE}[*] Fetching Page {current_page}...{Colors.RESET} ({url})")

            try:
                response = session.get(url, timeout=20, allow_redirects=True)
            except requests.exceptions.RequestException as e:
                print(f"{Colors.RED}[!] Network error fetching page {current_page}: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Stopping run cleanly. All previously collected IPs are saved.{Colors.RESET}")
                break

            # 1. Check Rate Limiting (HTTP 429)
            if response.status_code == 429:
                print(f"\n{Colors.RED}[!] HTTP 429 (Too Many Requests): Shodan rate limit reached.{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Rate limit encountered. Stopping cleanly to prevent IP ban.{Colors.RESET}")
                break

            # 2. Check Auth / Access Denial (HTTP 401 / 403)
            if response.status_code in (401, 403):
                text_lower = response.text.lower()
                if "cloudflare" in text_lower or "challenge" in text_lower or "turnstile" in text_lower or "attention required" in text_lower:
                    print(f"\n{Colors.RED}[!] HTTP {response.status_code}: Cloudflare bot protection / challenge triggered.{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] Cloudflare blocked the automated browser session.")
                    print(f"[!] Tip: To avoid Cloudflare scraping blocks, use Shodan's official API mode (-m api).{Colors.RESET}")
                else:
                    print(f"\n{Colors.RED}[!] HTTP {response.status_code}: Access Forbidden / Unauthorized.{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] The session cookie may be invalid, expired, or access is blocked.{Colors.RESET}")
                break

            # 3. Check for unexpected HTTP status
            if response.status_code != 200:
                print(f"\n{Colors.RED}[!] Received HTTP {response.status_code}. Stopping.{Colors.RESET}")
                break

            # 4. Check for redirects to login page (Session Expired mid-run)
            current_url = response.url.lower()
            if "/account/login" in current_url or "/login" in current_url:
                print(f"\n{Colors.RED}[!] Redirected to login page: {response.url}{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Your Shodan session cookie has expired or is invalid.")
                print(f"[!] Please log in to https://shodan.io in your browser and refresh your cookie.{Colors.RESET}")
                break

            # 5. Check response content for account/auth limitations
            body_lower = response.text.lower()
            if "please log in to view search results" in body_lower or "you must be logged in to search" in body_lower:
                print(f"\n{Colors.RED}[!] Shodan requires an authenticated session for this query.{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Provide a valid 'polito' session cookie to access results.{Colors.RESET}")
                break

            if "please upgrade your account to view more results" in body_lower or "upgrade your account" in body_lower:
                print(f"\n{Colors.YELLOW}[i] Shodan account limit reached: 'Please upgrade your account to view more results'.")
                print(f"[i] Free/standard accounts are restricted to viewing initial result pages on the web interface.{Colors.RESET}")
                break

            if "no results found" in body_lower and current_page == 1:
                print(f"\n{Colors.YELLOW}[i] Shodan reported no results found for query: '{query}'.{Colors.RESET}")
                break

            # 6. Extract IP addresses from page HTML
            page_ips = extract_ips_from_html(response.text)

            if not page_ips:
                print(f"{Colors.YELLOW}[i] No IP addresses detected on page {current_page}. End of available results.{Colors.RESET}")
                break

            # Append new IPs to file in real-time
            new_ips = []
            for ip in page_ips:
                if ip not in all_collected_ips:
                    all_collected_ips.add(ip)
                    new_ips.append(ip)
                    out_file.write(f"{ip}\n")
                    total_saved_this_run += 1

            # Flush immediately to disk so data is never lost if interrupted
            out_file.flush()
            os.fsync(out_file.fileno())

            print(f"{Colors.GREEN}[+] Page {current_page}: Found {len(page_ips)} IPs ({len(new_ips)} new unique) | Total: {len(all_collected_ips)}{Colors.RESET}")

            current_page += 1

    return total_saved_this_run


def run_official_api(
    query: str,
    api_key: str,
    max_pages: int = 10,
    delay: float = 1.0,
    output_path: str = "collected-ip.txt"
) -> int:
    """
    Queries Shodan using the official Shodan API library (recommended & ToS compliant).
    """
    if not SHODAN_AVAILABLE:
        print(f"{Colors.RED}[!] The 'shodan' python library is not installed.{Colors.RESET}")
        print(f"Run: pip install shodan")
        return 0

    api_key = api_key.strip()
    if not api_key:
        api_key = os.environ.get("SHODAN_API_KEY", "").strip()

    if not api_key:
        print(f"{Colors.RED}[!] No Shodan API Key provided. Set SHODAN_API_KEY or enter your key.{Colors.RESET}")
        return 0

    api = shodan.Shodan(api_key)

    # Verify API key and query credits
    try:
        account_info = api.info()
        print(f"{Colors.GREEN}[+] Authenticated to Shodan Official API!{Colors.RESET}")
        print(f"    Query Credits Available: {account_info.get('query_credits', 'N/A')}")
        print(f"    Scan Credits Available : {account_info.get('scan_credits', 'N/A')}")
    except shodan.APIError as e:
        print(f"{Colors.RED}[!] Shodan API Authentication Error: {e}{Colors.RESET}")
        return 0

    all_collected_ips: Set[str] = set()
    total_saved_this_run = 0

    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        all_collected_ips.add(ip)
            if all_collected_ips:
                print(f"{Colors.BLUE}[i] Existing {output_path} loaded with {len(all_collected_ips)} IPs. Appending new unique entries.{Colors.RESET}")
        except Exception:
            pass

    current_page = 1
    print(f"\n{Colors.BOLD}[*] Starting Official API Query: {Colors.CYAN}{query}{Colors.RESET}")
    print(f"[*] Output destination: {os.path.abspath(output_path)}\n")

    with open(output_path, "a", encoding="utf-8") as out_file:
        while True:
            if max_pages > 0 and current_page > max_pages:
                print(f"\n{Colors.GREEN}[+] Reached configured maximum page limit ({max_pages}). Stopping.{Colors.RESET}")
                break

            if current_page > 1 and delay > 0:
                time.sleep(delay)

            print(f"{Colors.BLUE}[*] Requesting Page {current_page} via API...{Colors.RESET}")
            try:
                results = api.search(query, page=current_page)
            except shodan.APIError as e:
                err_msg = str(e).lower()
                if "invalid page" in err_msg or "empty" in err_msg or "no results" in err_msg:
                    print(f"{Colors.YELLOW}[i] End of API results: {e}{Colors.RESET}")
                elif "credits" in err_msg:
                    print(f"{Colors.RED}[!] API Error: Insufficient query credits ({e}). Stopping.{Colors.RESET}")
                elif "rate limit" in err_msg:
                    print(f"{Colors.RED}[!] API Rate Limit Hit ({e}). Stopping cleanly.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Shodan API Error: {e}{Colors.RESET}")
                break

            matches = results.get("matches", [])
            total_matches = results.get("total", 0)

            if not matches:
                if current_page == 1:
                    print(f"{Colors.YELLOW}[i] No matches found for query: '{query}'{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[i] No more matches on page {current_page}. Reached end of results.{Colors.RESET}")
                break

            new_ips = []
            for match in matches:
                ip_str = match.get("ip_str")
                if ip_str:
                    try:
                        ipaddress.ip_address(ip_str)
                        if ip_str not in all_collected_ips:
                            all_collected_ips.add(ip_str)
                            new_ips.append(ip_str)
                            out_file.write(f"{ip_str}\n")
                            total_saved_this_run += 1
                    except ValueError:
                        continue

            out_file.flush()
            os.fsync(out_file.fileno())

            print(f"{Colors.GREEN}[+] Page {current_page}: Found {len(matches)} results ({len(new_ips)} new unique) | Total: {len(all_collected_ips)} (API Reported Total: {total_matches}){Colors.RESET}")

            # If fewer than 100 results returned by page, this was the last page
            if len(matches) < 100:
                print(f"{Colors.GREEN}[i] Received final page ({len(matches)} results < 100). Completed.{Colors.RESET}")
                break

            current_page += 1

    return total_saved_this_run


def interactive_menu():
    """Runs the interactive console wizard if no CLI arguments are supplied."""
    print_banner()

    print(f"{Colors.BOLD}Select Collection Mode:{Colors.RESET}")
    print(f"  {Colors.CYAN}[1]{Colors.RESET} Web Session Scraper (HTML Parser via Browser Session Cookie)")
    print(f"  {Colors.GREEN}[2]{Colors.RESET} Official Shodan API  (Recommended & ToS Compliant, uses API Key)")
    print()

    mode_choice = input("Enter choice (1 or 2, default: 1): ").strip()
    if mode_choice not in ("1", "2"):
        mode_choice = "1"

    print()
    # Prompt for Shodan Query with validation
    while True:
        query = input(f"{Colors.BOLD}Enter Shodan Search Query{Colors.RESET} (e.g. port:53,88,135 or apache): ").strip()
        if query:
            break
        print(f"{Colors.YELLOW}[!] Query cannot be empty. Please enter a valid Shodan query.{Colors.RESET}")

    output_path = input(f"\nEnter Output File (default: collected-ip.txt): ").strip()
    if not output_path:
        output_path = "collected-ip.txt"

    if mode_choice == "1":
        print(f"\n{Colors.BOLD}--- Web Session Cookie (Optional for 1 page, Required for pagination) ---{Colors.RESET}")
        print("How to get it:")
        print("  1. Log in to https://www.shodan.io in your browser.")
        print("  2. Press F12 to open Developer Tools.")
        print("  3. Navigate to 'Application' (Chrome/Edge) or 'Storage' (Firefox) -> 'Cookies'.")
        print("  4. Select 'https://www.shodan.io' and copy the value of the 'polito' cookie.")
        print(f"{Colors.YELLOW}Security Note: Never share or publish session cookies; they grant full account access.{Colors.RESET}")
        cookie_val = input("\nPaste 'polito' cookie value or full Cookie header (press Enter to skip): ").strip()

        pages_input = input("\nMax pages to scrape (default: 10, enter 0 for unlimited): ").strip()
        try:
            max_pages = int(pages_input) if pages_input else 10
        except ValueError:
            max_pages = 10

        delay_input = input("Delay between requests in seconds (default: 2.5): ").strip()
        try:
            delay = float(delay_input) if delay_input else 2.5
        except ValueError:
            delay = 2.5

        saved = scrape_shodan_web(
            query=query,
            cookie_str=cookie_val,
            max_pages=max_pages,
            delay=delay,
            output_path=output_path
        )
    else:
        print(f"\n{Colors.BOLD}--- Official Shodan API Key ---{Colors.RESET}")
        print("How to get it:")
        print("  1. Log in to https://account.shodan.io")
        print("  2. Copy your API Key displayed on the dashboard.")
        api_key = input("\nEnter your Shodan API Key: ").strip()

        pages_input = input("\nMax pages to query (default: 10, enter 0 for unlimited): ").strip()
        try:
            max_pages = int(pages_input) if pages_input else 10
        except ValueError:
            max_pages = 10

        delay_input = input("Delay between requests in seconds (default: 1.0): ").strip()
        try:
            delay = float(delay_input) if delay_input else 1.0
        except ValueError:
            delay = 1.0

        saved = run_official_api(
            query=query,
            api_key=api_key,
            max_pages=max_pages,
            delay=delay,
            output_path=output_path
        )

    print(f"\n{Colors.CYAN}========================================================================{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}[v] Finished! New unique IPs added this run: {saved}{Colors.RESET}")
    print(f"[*] Check your output file: {Colors.BOLD}{os.path.abspath(output_path)}{Colors.RESET}")
    print(f"{Colors.CYAN}========================================================================{Colors.RESET}")


def main():
    enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Collect IP addresses from Shodan search queries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive Mode:
    python shodan_scraper.py

  Web Scraper Mode with Cookie:
    python shodan_scraper.py -m web -q "port:53,88,135" -c "polito=s%3A..." --pages 5

  Official API Mode:
    python shodan_scraper.py -m api -q "port:445" -k "YOUR_API_KEY" --pages 3
        """
    )
    parser.add_argument("-m", "--mode", choices=["web", "api"], help="Mode: 'web' (scraper) or 'api' (official API)")
    parser.add_argument("-q", "--query", help="Shodan search query (e.g. port:53,88,135)")
    parser.add_argument("-c", "--cookie", default="", help="Shodan session cookie (polito) for web mode")
    parser.add_argument("-k", "--api-key", default="", help="Shodan API key for api mode")
    parser.add_argument("-p", "--pages", type=int, default=10, help="Maximum number of pages to fetch (0 for all)")
    parser.add_argument("-d", "--delay", type=float, default=None, help="Polite delay between requests in seconds")
    parser.add_argument("-o", "--output", default="collected-ip.txt", help="Output file path (default: collected-ip.txt)")

    # If no arguments were given on command line, launch interactive mode
    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()

    if not args.query:
        print_banner()
        while True:
            args.query = input(f"{Colors.BOLD}Enter Shodan Search Query: {Colors.RESET}").strip()
            if args.query:
                break
            print(f"{Colors.YELLOW}[!] Query cannot be empty.{Colors.RESET}")

    mode = args.mode or "web"

    if mode == "web":
        delay = args.delay if args.delay is not None else 2.5
        saved = scrape_shodan_web(
            query=args.query,
            cookie_str=args.cookie,
            max_pages=args.pages,
            delay=delay,
            output_path=args.output
        )
    else:
        delay = args.delay if args.delay is not None else 1.0
        saved = run_official_api(
            query=args.query,
            api_key=args.api_key,
            max_pages=args.pages,
            delay=delay,
            output_path=args.output
        )

    print(f"\n{Colors.GREEN}[v] Done. {saved} new unique IPs saved to {args.output}{Colors.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user. Exiting cleanly. Saved IPs remain intact in output file.{Colors.RESET}")
        sys.exit(0)
