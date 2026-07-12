#!/usr/bin/env python3
"""
OSINT Footprint Analyzer - v0.1 (ugly, functional, no overdesign)

Given a username, email, or domain, dumps whatever public footprint info
we can grab. This is a first pass -- straight-line code, minimal error
handling beyond "don't crash", output to console + optional JSON dump.

Usage:
    python3 osint_footprint.py --username johndoe
    python3 osint_footprint.py --domain example.com
    python3 osint_footprint.py --email john@example.com
    python3 osint_footprint.py --username johndoe --domain example.com --email john@example.com --out results.json
"""

import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime

import requests

TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Footprint-Analyzer/0.1)"}

# --- platform list for username enumeration -------------------------------
# format: name -> (url_template, "not found" indicator string OR None if status code is enough)
PLATFORMS = {
    "GitHub":      "https://github.com/{u}",
    "Twitter/X":   "https://x.com/{u}",
    "Instagram":   "https://www.instagram.com/{u}/",
    "Reddit":      "https://www.reddit.com/user/{u}",
    "TikTok":      "https://www.tiktok.com/@{u}",
    "GitLab":      "https://gitlab.com/{u}",
    "Medium":      "https://medium.com/@{u}",
    "Pinterest":   "https://www.pinterest.com/{u}/",
    "Steam":       "https://steamcommunity.com/id/{u}",
    "HackerNews":  "https://news.ycombinator.com/user?id={u}",
    "Keybase":     "https://keybase.io/{u}",
    "Dev.to":      "https://dev.to/{u}",
    "YouTube":     "https://www.youtube.com/@{u}",
    "Twitch":      "https://www.twitch.tv/{u}",
    "Docker Hub":  "https://hub.docker.com/u/{u}",
}


def check_username(username):
    print(f"\n[*] Checking username '{username}' across {len(PLATFORMS)} platforms...")
    found = []
    for name, url_template in PLATFORMS.items():
        url = url_template.format(u=username)
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            # crude heuristic: 200 = probably exists, 404 = doesn't. some sites lie, whatever, v0.1.
            if r.status_code == 200:
                print(f"    [+] {name:12s} FOUND     {url}")
                found.append({"platform": name, "url": url, "status": r.status_code})
            elif r.status_code == 404:
                print(f"    [-] {name:12s} not found")
            else:
                print(f"    [?] {name:12s} status={r.status_code} (unclear) {url}")
        except requests.exceptions.RequestException as e:
            print(f"    [!] {name:12s} error: {e.__class__.__name__}")
        time.sleep(0.3)  # don't hammer, be polite
    return found


def check_domain(domain):
    print(f"\n[*] Domain recon for '{domain}'...")
    result = {}

    # DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        print(f"    [+] Resolves to: {ip}")
        result["ip"] = ip
    except socket.gaierror:
        print("    [-] Could not resolve domain")
        result["ip"] = None

    # WHOIS - try python-whois if installed, else skip gracefully
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
        result["registrar"] = str(w.registrar) if w.registrar else None
        result["creation_date"] = str(w.creation_date)
        result["expiration_date"] = str(w.expiration_date)
        result["name_servers"] = w.name_servers
        print(f"    [+] Registrar: {result['registrar']}")
        print(f"    [+] Created:   {result['creation_date']}")
        print(f"    [+] Expires:   {result['expiration_date']}")
    except ImportError:
        print("    [!] python-whois not installed, skipping WHOIS. Run: pip install python-whois")
        result["whois"] = "SKIPPED - install python-whois"
    except Exception as e:
        print(f"    [!] WHOIS lookup failed: {e}")
        result["whois_error"] = str(e)

    # basic security headers check on the site
    try:
        r = requests.get(f"https://{domain}", headers=HEADERS, timeout=TIMEOUT)
        sec_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                       "X-Frame-Options", "X-Content-Type-Options"]
        present = {h: r.headers.get(h) for h in sec_headers if h in r.headers}
        missing = [h for h in sec_headers if h not in r.headers]
        result["security_headers_present"] = present
        result["security_headers_missing"] = missing
        print(f"    [+] Security headers present: {list(present.keys())}")
        if missing:
            print(f"    [-] Security headers missing: {missing}")
    except requests.exceptions.RequestException as e:
        print(f"    [!] Could not fetch site headers: {e}")

    return result


def check_email(email):
    print(f"\n[*] Email checks for '{email}'...")
    result = {"email": email}

    # sanity check format
    valid = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))
    result["format_valid"] = valid
    print(f"    [{'+' if valid else '-'}] Format valid: {valid}")

    if not valid:
        return result

    domain = email.split("@")[1]
    # does the domain even have mail servers
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange) for r in mx]
        result["mx_records"] = mx_hosts
        print(f"    [+] MX records found: {mx_hosts}")
    except ImportError:
        print("    [!] dnspython not installed, skipping MX check. Run: pip install dnspython")
        result["mx_check"] = "SKIPPED - install dnspython"
    except Exception as e:
        print(f"    [-] No MX records / lookup failed: {e}")
        result["mx_records"] = []

    # breach check - HIBP now requires a paid API key, so this is a stub.
    # fill in HIBP_API_KEY below if you have one.
    HIBP_API_KEY = None
    if HIBP_API_KEY:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={**HEADERS, "hibp-api-key": HIBP_API_KEY},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                breaches = [b["Name"] for b in r.json()]
                result["breaches"] = breaches
                print(f"    [!] BREACHED in: {breaches}")
            elif r.status_code == 404:
                print("    [+] No known breaches (HIBP)")
                result["breaches"] = []
            else:
                print(f"    [?] HIBP returned status {r.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"    [!] HIBP check failed: {e}")
    else:
        print("    [i] Skipping breach check - no HIBP API key set (it's a paid API now).")
        print("    [i] Manually check: https://haveibeenpwned.com/")
        result["breaches"] = "MANUAL_CHECK_REQUIRED"

    return result


def generate_dorks(username=None, domain=None, email=None):
    """Just spits out useful google dorks for manual follow-up. No API calls."""
    dorks = []
    if username:
        dorks += [
            f'"{username}" site:pastebin.com',
            f'"{username}" site:github.com',
            f'intext:"{username}" filetype:pdf',
        ]
    if domain:
        dorks += [
            f'site:{domain} filetype:pdf',
            f'site:{domain} inurl:admin',
            f'site:{domain} intext:"password"',
            f'site:pastebin.com "{domain}"',
            f'site:linkedin.com "{domain}"',
        ]
    if email:
        dorks += [
            f'"{email}" site:pastebin.com',
            f'"{email}" -site:{email.split("@")[1] if "@" in email else ""}',
        ]
    return dorks


def main():
    parser = argparse.ArgumentParser(description="OSINT Footprint Analyzer v0.1")
    parser.add_argument("--username", help="username to search across platforms")
    parser.add_argument("--domain", help="domain to recon")
    parser.add_argument("--email", help="email to check")
    parser.add_argument("--out", help="save results to JSON file", default=None)
    args = parser.parse_args()

    if not any([args.username, args.domain, args.email]):
        parser.print_help()
        sys.exit(1)

    report = {
        "generated_at": datetime.now().isoformat() + "Z",
        "target": {
            "username": args.username,
            "domain": args.domain,
            "email": args.email,
        },
    }

    if args.username:
        report["username_results"] = check_username(args.username)

    if args.domain:
        report["domain_results"] = check_domain(args.domain)

    if args.email:
        report["email_results"] = check_email(args.email)

    dorks = generate_dorks(args.username, args.domain, args.email)
    if dorks:
        print("\n[*] Suggested manual Google dorks:")
        for d in dorks:
            print(f"    {d}")
        report["suggested_dorks"] = dorks

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.out}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
