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
# format: name -> {"url": template, "reliable": bool}, where {u} is replaced
# with the target username.
#
# "reliable" reflects how each platform serves pages:
#
# reliable=True  = server-rendered. A missing profile gets a real HTTP 404
# from the server itself, so the status code is a trustworthy signal.
#
# reliable=False = JavaScript single-page app (SPA). The server returns the
# same 200 "app shell" for ANY url, real or fake - the actual "does this
# user exist" check happens client-side via JS after the page loads, which
# requests.get() never executes. Confirmed empirically: a deliberately
# fake Instagram username still returned 200. For these platforms a 200
# is NOT evidence the account exists - only an explicit 404 counts as
# real signal here.
#
# One dict instead of two: adding a platform means adding one entry here,
# not remembering which of two collections it belongs in. Also leaves room
# to add more per-platform metadata later (e.g. expected_status, notes)
# without restructuring again.
PLATFORMS = {
    "GitHub":      {"url": "https://github.com/{u}",                    "reliable": True},
    "Reddit":      {"url": "https://www.reddit.com/user/{u}",           "reliable": True},
    "GitLab":      {"url": "https://gitlab.com/{u}",                    "reliable": True},
    "Medium":      {"url": "https://medium.com/@{u}",                   "reliable": True},
    "Steam":       {"url": "https://steamcommunity.com/id/{u}",         "reliable": True},
    "HackerNews":  {"url": "https://news.ycombinator.com/user?id={u}",  "reliable": True},
    "Keybase":     {"url": "https://keybase.io/{u}",                    "reliable": True},
    "Dev.to":      {"url": "https://dev.to/{u}",                        "reliable": True},
    "Docker Hub":  {"url": "https://hub.docker.com/u/{u}",              "reliable": True},
    "Twitter/X":   {"url": "https://x.com/{u}",                         "reliable": False},
    "Instagram":   {"url": "https://www.instagram.com/{u}/",            "reliable": False},
    "TikTok":      {"url": "https://www.tiktok.com/@{u}",               "reliable": False},
    "Pinterest":   {"url": "https://www.pinterest.com/{u}/",            "reliable": False},
    "YouTube":     {"url": "https://www.youtube.com/@{u}",              "reliable": False},
    "Twitch":      {"url": "https://www.twitch.tv/{u}",                 "reliable": False},
}


def check_username(username):
    print(f"\n[*] Checking username '{username}' across {len(PLATFORMS)} platforms...")
    # every platform lands in exactly one bucket - nothing gets silently dropped anymore.
    results = {"found": [], "not_found": [], "unclear": [], "error": []}
    for name, platform_info in PLATFORMS.items():
        url = platform_info["url"].format(u=username)
        is_reliable = platform_info["reliable"]
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            entry = {"platform": name, "url": url, "status": r.status_code}
            if r.status_code == 404:
                # a real 404 is trustworthy on every platform, reliable or not
                print(f"    [-] {name:12s} not found")
                results["not_found"].append(entry)
            elif r.status_code == 200 and is_reliable:
                print(f"    [+] {name:12s} FOUND     {url}")
                results["found"].append(entry)
            elif r.status_code == 200 and not is_reliable:
                # SPA platform: 200 just means "the app loaded", not "user exists"
                print(f"    [?] {name:12s} status=200 but SPA platform - not confirmed, verify manually  {url}")
                entry["reason"] = "SPA platform: HTTP 200 does not confirm account existence"
                results["unclear"].append(entry)
            else:
                # unclear = could be a block (403), rate limit, redirect quirk, etc.
                # NOT the same as "not found" - the account may well exist, we just can't tell.
                # give a specific reason per known status code so downstream logic
                # (risk scoring, correlation) doesn't have to re-derive it from a raw number.
                if r.status_code == 403:
                    reason = "HTTP 403 Forbidden - likely anti-bot block, not evidence of absence"
                elif r.status_code == 429:
                    reason = "HTTP 429 Too Many Requests - rate limited, try again later"
                elif 500 <= r.status_code < 600:
                    reason = f"HTTP {r.status_code} - platform server error, not related to this username"
                else:
                    reason = f"HTTP {r.status_code} - unrecognized status, not confirmed absent"
                print(f"    [?] {name:12s} status={r.status_code} (unclear - {reason}) {url}")
                entry["reason"] = reason
                results["unclear"].append(entry)
        except requests.exceptions.RequestException as e:
            print(f"    [!] {name:12s} error: {e.__class__.__name__}")
            results["error"].append({
                "platform": name,
                "url": url,
                "reason": f"Request failed: {e.__class__.__name__}",
            })
        time.sleep(0.3)  # don't hammer, be polite
    return results


def check_subdomains(domain):
    """
    Passive subdomain enumeration via crt.sh (Certificate Transparency logs).
    Every HTTPS cert issued gets publicly logged - we're just reading those
    logs, never touching the target's own infrastructure directly.

    Returns a dict, not a bare list - an empty subdomains list should only
    ever mean "genuinely found none", never "the lookup failed". success/
    reason distinguish "we looked and found nothing" from "we couldn't
    look" (rate limited, service down, network error, bad response), same
    philosophy as the found/not_found/unclear/error split in
    check_username().
    """
    print(f"\n[*] Searching Certificate Transparency logs for '{domain}' subdomains...")
    # status starts as None: we may fail before ever getting an HTTP response
    # at all (e.g. connection error), in which case there's no status code to
    # report - that's meaningfully different from "we got a bad status code".
    result = {"success": False, "status": None, "source": "crt.sh", "reason": None, "subdomains": []}
    try:
        # crt.sh can be slow under load, give it more room than our normal TIMEOUT
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, headers=HEADERS, timeout=15)
        result["status"] = r.status_code  # got a response, so we always have a status now

        # inspect the status ourselves instead of raise_for_status(), so we
        # can give a specific reason per case rather than one generic
        # "HTTPError" for every non-2xx response.
        if r.status_code == 429:
            result["reason"] = "HTTP 429 Too Many Requests - crt.sh rate limited us, try again later"
            print(f"    [!] {result['reason']}")
            return result
        elif r.status_code == 503:
            result["reason"] = "HTTP 503 Service Unavailable - crt.sh is temporarily down"
            print(f"    [!] {result['reason']}")
            return result
        elif r.status_code != 200:
            result["reason"] = f"HTTP {r.status_code} - unexpected response from crt.sh"
            print(f"    [!] {result['reason']}")
            return result

        entries = r.json()
        subdomains = set()
        for entry in entries:
            # name_value can contain multiple names separated by newlines
            # (one cert can cover several subdomains via SAN)
            names = entry.get("name_value", "").split("\n")
            for name in names:
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]  # strip wildcard prefix
                if name.endswith(domain):
                    subdomains.add(name)

        subdomains_list = sorted(subdomains)
        result["success"] = True
        result["subdomains"] = subdomains_list
        print(f"    [+] Found {len(subdomains_list)} unique subdomains")
        for s in subdomains_list[:20]:  # don't flood the console on huge results
            print(f"        {s}")
        if len(subdomains_list) > 20:
            print(f"        ... and {len(subdomains_list) - 20} more (see JSON output)")
        return result

    except requests.exceptions.RequestException as e:
        result["reason"] = f"Request failed: {e.__class__.__name__}"
        print(f"    [!] crt.sh request failed: {result['reason']}")
        return result
    except ValueError as e:
        # crt.sh returns HTML instead of JSON when it's overloaded/rate limiting
        result["reason"] = f"crt.sh returned a non-JSON response (likely overloaded): {e}"
        print(f"    [!] {result['reason']}")
        return result


def _normalize_whois_value(value):
    """
    python-whois is inconsistent about return types: some registrars give a
    single value (str/datetime) for a field, others give a list containing
    the same field repeated across multiple WHOIS records for that domain.
    Without this, str(value) on a list produces an ugly
    "[datetime.datetime(...), datetime.datetime(...)]" string instead of a
    clean date. Normalize to a single value (the first entry) so callers
    never have to guess which shape they're getting.
    """
    if isinstance(value, list):
        return value[0] if value else None
    return value


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
        registrar = _normalize_whois_value(w.registrar)
        creation_date = _normalize_whois_value(w.creation_date)
        expiration_date = _normalize_whois_value(w.expiration_date)
        result["registrar"] = str(registrar) if registrar else None
        result["creation_date"] = str(creation_date) if creation_date else None
        result["expiration_date"] = str(expiration_date) if expiration_date else None
        result["name_servers"] = w.name_servers  # naturally a list already, left as-is
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

    # subdomain enumeration via Certificate Transparency logs
    result["subdomains"] = check_subdomains(domain)

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


# --- exposure risk scoring --------------------------------------------------
# Data-driven on purpose: tuning the score later means editing this dict,
# not hunting through if/elif branches. Each rule has a point value, a
# human-readable description, and a recommendation - so the final report
# explains both *why* it landed on a given number and *what to do about it*,
# which is most of what an HTML report needs to write itself later.
RISK_RULES = {
    "hibp_breach": {
        "points": 30,
        "description": "Email found in a known data breach (HaveIBeenPwned)",
        "recommendation": "Change the password on this account and anywhere it was reused; enable 2FA.",
    },
    "no_hsts": {
        "points": 10,
        "description": "Domain does not enforce HTTPS (missing Strict-Transport-Security)",
        "recommendation": "Enable Strict-Transport-Security to force HTTPS on all connections.",
    },
    "no_csp": {
        "points": 8,
        "description": "Domain has no Content-Security-Policy header (weaker XSS protection)",
        "recommendation": "Add a Content-Security-Policy header to restrict what scripts/resources can load.",
    },
    "no_xfo": {
        "points": 5,
        "description": "Domain has no X-Frame-Options header (clickjacking risk)",
        "recommendation": "Add X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking.",
    },
    "no_xcto": {
        "points": 5,
        "description": "Domain has no X-Content-Type-Options header",
        "recommendation": "Add X-Content-Type-Options: nosniff to stop MIME-type sniffing attacks.",
    },
    "many_subdomains": {
        "points": 6,
        "threshold": 10,  # fires when discovered subdomain count exceeds this
        "description": "More than 10 subdomains discovered (larger attack surface)",
        "recommendation": "Audit subdomains for ones that are stale, forgotten, or shouldn't be public.",
    },
    "large_username_footprint": {
        "points": 2,          # per confirmed account
        "max_points": 10,     # capped so 5+ accounts don't dominate the score
        "description": "Username confirmed on multiple platforms (2 pts each, capped at 10)",
        "recommendation": "Review privacy settings on these accounts; consider whether all need to be public.",
    },
}

# headers to rule-name mapping, used to walk security_headers_missing generically
# instead of one hardcoded if-check per header
_HEADER_RULES = {
    "Strict-Transport-Security": "no_hsts",
    "Content-Security-Policy": "no_csp",
    "X-Frame-Options": "no_xfo",
    "X-Content-Type-Options": "no_xcto",
}

# score -> severity label. Ranges are upper-bound-inclusive, checked in order.
SEVERITY_BANDS = [
    (20, "Low"),
    (40, "Medium"),
    (70, "High"),
    (100, "Critical"),
]


def get_severity(score):
    for upper_bound, label in SEVERITY_BANDS:
        if score <= upper_bound:
            return label
    return "Critical"  # safety net, shouldn't be reachable since score is capped at 100


def calculate_risk(report):
    """
    Turns the raw recon findings already sitting in `report` into a single
    0-100 exposure score plus a severity label and a breakdown of exactly
    which rules fired and why. Never re-fetches anything - purely reads what
    check_username(), check_domain(), and check_email() already collected.

    Named calculate_risk rather than compute_risk_score because this does
    more than arithmetic: it evaluates conditions, records which rules
    triggered, and builds the structured explanation alongside the number.
    """
    triggered = []
    total = 0

    def fire(rule_name, points=None):
        nonlocal total
        rule = RISK_RULES[rule_name]
        pts = points if points is not None else rule["points"]
        triggered.append({
            "rule": rule_name,
            "points": pts,
            "description": rule["description"],
            "recommendation": rule["recommendation"],
        })
        total += pts

    username_results = report.get("username_results")
    domain_results = report.get("domain_results")
    email_results = report.get("email_results")

    # --- email: confirmed breach ---
    if email_results:
        breaches = email_results.get("breaches")
        if isinstance(breaches, list) and len(breaches) > 0:
            fire("hibp_breach")

    # --- domain: missing security headers, one rule per header ---
    if domain_results:
        missing = domain_results.get("security_headers_missing", [])
        for header, rule_name in _HEADER_RULES.items():
            if header in missing:
                fire(rule_name)

        # --- domain: large subdomain count (only counts a REAL lookup,
        # a failed crt.sh call has success=False and shouldn't score at all) ---
        subdomain_info = domain_results.get("subdomains", {})
        if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
            threshold = RISK_RULES["many_subdomains"]["threshold"]
            if len(subdomain_info.get("subdomains", [])) > threshold:
                fire("many_subdomains")

    # --- username: footprint size, capped ---
    if username_results:
        found_count = len(username_results.get("found", []))
        if found_count > 0:
            rule = RISK_RULES["large_username_footprint"]
            points = min(found_count * rule["points"], rule["max_points"])
            fire("large_username_footprint", points=points)

    total = min(total, 100)
    return {
        "score": total,
        "max_score": 100,
        "severity": get_severity(total),
        "triggered_rules": triggered,
    }


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

    # risk score is computed last - it only reads what's already in `report`,
    # so it naturally reflects whichever checks were actually run
    risk = calculate_risk(report)
    report["risk_assessment"] = risk
    print(f"\n[*] Exposure risk score: {risk['score']}/{risk['max_score']} ({risk['severity']})")
    if risk["triggered_rules"]:
        for t in risk["triggered_rules"]:
            print(f"    +{t['points']:<3} {t['description']}")
    else:
        print("    No risk factors triggered.")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.out}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()