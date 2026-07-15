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
import html
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import quote as url_quote

import requests

TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Footprint-Analyzer/0.1)"}

# --- platform list for username enumeration -------------------------------
# format: name -> {"url": template, "reliable": bool, "not_found_text": str|None}
# where {u} is replaced with the target username.
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
# "not_found_text" (optional) = a string that appears in the page body when
# the account does NOT exist, even though the platform still returns HTTP
# 200. Some "reliable" platforms aren't fully reliable on status code alone
# - they serve a real 200 page that just happens to say "user not found"
# in the content. When set, a 200 response is only trusted as a real FOUND
# if this text is absent; if present, it gets reclassified as not_found
# despite the 200. Sourced from the Sherlock project's actively maintained
# platform-detection database (github.com/sherlock-project/sherlock),
# cross-checked rather than guessed, since a wrong string here just
# reintroduces the same false-positive problem in a sneakier form. Left
# unset (None) for platforms we haven't verified this way yet - status
# code is still used as-is for those rather than guessing at content.
#
# "requires_og_title" (optional, default False) = a different shape of the
# same problem: instead of a "not found" phrase appearing, a MISSING piece
# of content signals absence. Medium serves a 200 for every URL, real or
# fake, but only populates the <meta property="og:title"> tag with the
# person's name when the profile is real - a fake user gets no og:title
# tag at all. Verified empirically by comparing a known-real profile
# against a deliberately fake one side by side (real: og:title =
# "Patricia Torvalds - Medium"; fake: og:title absent entirely).
#
# One dict instead of two: adding a platform means adding one entry here,
# not remembering which of two collections it belongs in.
PLATFORMS = {
    "GitHub":      {"url": "https://github.com/{u}",                    "reliable": True, "not_found_text": None},
    # Reddit: DOWNGRADED to unreliable after investigation. Sherlock's
    # documented not_found_text ("Sorry, nobody on Reddit goes by that
    # name.") no longer applies - confirmed empirically that Reddit now
    # serves the SAME "Please wait for verification" bot-check interstitial
    # for BOTH a known-real username (torvalds) and a fake one, with nearly
    # identical body length (8438 vs 8442 bytes). That means a 200 from
    # Reddit currently confirms nothing - same practical problem as the SPA
    # platforms below, just manifesting as an anti-bot wall instead of a JS
    # app shell. Moved here rather than left as a broken "reliable" check.
    "Reddit":      {"url": "https://www.reddit.com/user/{u}",           "reliable": False, "not_found_text": None},
    # GitLab: investigated, no content-check added on purpose. GitLab sits
    # behind Cloudflare bot protection that frequently 403s plain
    # requests.get() calls - confirmed this happens even for a KNOWN-REAL
    # username (yukihiro-matz) and persists well after waiting, not just a
    # short burst-rate cooldown. That means we often can't see real page
    # content to check in the first place, so a not_found_text/og_title
    # check can't be reliably built or verified right now. This is fine:
    # our existing 403 handling already reports these as "unclear" rather
    # than a false FOUND, which is the honest answer. Expect GitLab to
    # show up as unclear more often than other reliable platforms.
    "GitLab":      {"url": "https://gitlab.com/{u}",                    "reliable": True, "not_found_text": None},
    "Medium":      {"url": "https://medium.com/@{u}",                   "reliable": True, "not_found_text": None, "requires_og_title": True},
    "Steam":       {"url": "https://steamcommunity.com/id/{u}",         "reliable": True, "not_found_text": "The specified profile could not be found"},
    "HackerNews":  {"url": "https://news.ycombinator.com/user?id={u}",  "reliable": True, "not_found_text": None},
    "Keybase":     {"url": "https://keybase.io/{u}",                    "reliable": True, "not_found_text": None},
    "Dev.to":      {"url": "https://dev.to/{u}",                        "reliable": True, "not_found_text": None},
    "Docker Hub":  {"url": "https://hub.docker.com/u/{u}",              "reliable": True, "not_found_text": None},
    "Twitter/X":   {"url": "https://x.com/{u}",                         "reliable": False, "not_found_text": None},
    "Instagram":   {"url": "https://www.instagram.com/{u}/",            "reliable": False, "not_found_text": None},
    "TikTok":      {"url": "https://www.tiktok.com/@{u}",               "reliable": False, "not_found_text": None},
    "Pinterest":   {"url": "https://www.pinterest.com/{u}/",            "reliable": False, "not_found_text": None},
    "YouTube":     {"url": "https://www.youtube.com/@{u}",              "reliable": False, "not_found_text": None},
    "Twitch":      {"url": "https://www.twitch.tv/{u}",                 "reliable": False, "not_found_text": None},
}


MAX_RETRIES = 2       # retry attempts after the initial request, on 429 only
MAX_BACKOFF_WAIT = 15  # cap how long we'll ever sleep for one retry, seconds


def _get_with_retry(url, max_retries=MAX_RETRIES, extra_headers=None):
    """
    Wraps requests.get with retry-on-429 behavior. Prefers the server's own
    Retry-After header when present (it knows its own rate limits better
    than we can guess); falls back to exponential backoff (1s, 2s, 4s...)
    when the header is absent. Every other status code (200, 404, 403,
    5xx, etc.) is returned immediately on the first try - retrying those
    wouldn't help, they're not rate-limit signals.

    extra_headers merges on top of the module-level HEADERS (e.g. HIBP's
    api-key header) without every caller needing its own retry loop.
    """
    headers = {**HEADERS, **(extra_headers or {})}
    attempt = 0
    while True:
        r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code != 429 or attempt >= max_retries:
            return r

        retry_after = r.headers.get("Retry-After")
        if retry_after is not None:
            try:
                wait = min(float(retry_after), MAX_BACKOFF_WAIT)
            except ValueError:
                # Retry-After can also be an HTTP date string rather than a
                # number of seconds - not worth parsing that for v0.2, just
                # fall back to backoff instead of guessing at the date format
                wait = min(2 ** attempt, MAX_BACKOFF_WAIT)
        else:
            wait = min(2 ** attempt, MAX_BACKOFF_WAIT)

        print(f"        (rate limited, retrying in {wait:.1f}s...)")
        time.sleep(wait)
        attempt += 1


def check_username(username):
    print(f"\n[*] Checking username '{username}' across {len(PLATFORMS)} platforms...")
    # every platform lands in exactly one bucket - nothing gets silently dropped anymore.
    results = {"found": [], "not_found": [], "unclear": [], "error": []}
    for name, platform_info in PLATFORMS.items():
        url = platform_info["url"].format(u=username)
        is_reliable = platform_info["reliable"]
        try:
            r = _get_with_retry(url)
            entry = {"platform": name, "url": url, "status": r.status_code}
            # r.history is non-empty whenever a redirect happened - surface it
            # rather than silently following, since the final URL sometimes
            # differs meaningfully (e.g. GitHub normalizes case: JohnDoe -> johndoe)
            if r.history:
                entry["redirected_to"] = r.url
            if r.status_code == 404:
                # a real 404 is trustworthy on every platform, reliable or not
                print(f"    [-] {name:12s} not found")
                results["not_found"].append(entry)
            elif r.status_code == 200 and is_reliable:
                not_found_text = platform_info.get("not_found_text")
                needs_og_title = platform_info.get("requires_og_title", False)
                if not_found_text and not_found_text in r.text:
                    # status said "found", but the page content itself says
                    # otherwise - trust the content, not the status code.
                    print(f"    [-] {name:12s} not found (200 status, but page content confirms no such user)")
                    entry["reason"] = "HTTP 200 but page content matched known 'not found' text"
                    results["not_found"].append(entry)
                elif needs_og_title and 'property="og:title"' not in r.text:
                    # inverse case: absence of a piece of content signals
                    # absence of the account, not presence of "not found" text
                    print(f"    [-] {name:12s} not found (200 status, but no og:title meta tag - generic shell page)")
                    entry["reason"] = "HTTP 200 but no og:title meta tag present (profile shell, not a real user page)"
                    results["not_found"].append(entry)
                else:
                    print(f"    [+] {name:12s} FOUND     {url}")
                    results["found"].append(entry)
            elif r.status_code == 200 and not is_reliable:
                # this platform is marked unreliable because a 200 here doesn't
                # confirm anything - could be a JS SPA serving the same app
                # shell for any URL (Instagram, TikTok, etc), or a bot-check/
                # verification wall served regardless of username (Reddit,
                # confirmed empirically). Either way, the status code alone
                # can't distinguish a real account from a fake one here.
                print(f"    [?] {name:12s} status=200 but this platform can't be reliably checked - not confirmed, verify manually  {url}")
                entry["reason"] = "Platform marked unreliable: HTTP 200 does not confirm account existence here"
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
            time.sleep(0.3)  # don't hammer, be polite - only between actual completed requests
        except requests.exceptions.RequestException as e:
            # no pacing sleep here: a timeout/connection failure already burned
            # up to TIMEOUT seconds with no successful hit on the server, so
            # there's nothing left to be "polite" about waiting on
            print(f"    [!] {name:12s} error: {e.__class__.__name__}")
            results["error"].append({
                "platform": name,
                "url": url,
                "reason": f"Request failed: {e.__class__.__name__}",
            })
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


def check_dns_records(domain):
    """
    Looks up A, AAAA, MX, NS, TXT, and CNAME records for the domain via
    dnspython. Each record type is queried independently - a domain
    legitimately might not have some of these (e.g. no CNAME on an apex
    domain, no AAAA if IPv6 isn't configured), so a missing record type
    is normal, not an error. Only NXDOMAIN (the domain doesn't exist at
    all) or a missing dnspython install stop the whole lookup early.
    """
    print(f"\n[*] Looking up DNS records for '{domain}'...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {rtype: [] for rtype in record_types}

    try:
        import dns.resolver
    except ImportError:
        print("    [!] dnspython not installed, skipping DNS record lookup. Run: pip install dnspython")
        return {"skipped": True, "reason": "dnspython not installed", **results}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            values = sorted(str(r) for r in answers)
            results[rtype] = values
            print(f"    [+] {rtype:6s} ({len(values)}): {', '.join(values)}")
        except dns.resolver.NXDOMAIN:
            # domain doesn't exist at all - every other record type will
            # fail the same way, no point querying the rest
            print(f"    [-] Domain does not exist (NXDOMAIN)")
            results["nxdomain"] = True
            break
        except dns.resolver.NoAnswer:
            # this record type genuinely doesn't exist for this domain -
            # normal, not an error (e.g. most domains have no CNAME on the apex)
            print(f"    [ ] {rtype:6s}: none")
        except dns.resolver.NoNameservers:
            print(f"    [!] {rtype:6s}: no nameservers responded")
        except Exception as e:
            print(f"    [!] {rtype:6s}: lookup failed ({e.__class__.__name__})")

    return results


def check_domain(domain):
    print(f"\n[*] Domain recon for '{domain}'...")
    result = {}

    # DNS records - A, AAAA, MX, NS, TXT, CNAME
    dns_records = check_dns_records(domain)
    result["dns_records"] = dns_records
    # keep "ip" for backward compatibility with anything reading the old
    # single-A-record shape - just the first A record, if any
    result["ip"] = dns_records.get("A", [None])[0] if dns_records.get("A") else None

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

        # registrant contact fields - often redacted by privacy proxies, but
        # when present these are exactly what the correlation engine needs
        # to link a domain back to a specific person. w.emails can return a
        # single string, a list, or None depending on the registrar's WHOIS
        # format, so normalize to a list here rather than in the caller.
        registrant_name = _normalize_whois_value(w.name)
        registrant_org = _normalize_whois_value(w.org)
        emails = w.emails
        if emails is None:
            registrant_emails = []
        elif isinstance(emails, list):
            registrant_emails = emails
        else:
            registrant_emails = [emails]
        result["registrant_name"] = str(registrant_name) if registrant_name else None
        result["registrant_org"] = str(registrant_org) if registrant_org else None
        result["registrant_emails"] = registrant_emails

        print(f"    [+] Registrar: {result['registrar']}")
        print(f"    [+] Created:   {result['creation_date']}")
        print(f"    [+] Expires:   {result['expiration_date']}")
        if result["registrant_name"]:
            print(f"    [+] Registrant name: {result['registrant_name']}")
        if result["registrant_org"]:
            print(f"    [+] Registrant org:  {result['registrant_org']}")
        if registrant_emails:
            print(f"    [+] Registrant email(s): {', '.join(registrant_emails)}")
    except ImportError:
        print("    [!] python-whois not installed, skipping WHOIS. Run: pip install python-whois")
        result["whois"] = "SKIPPED - install python-whois"
    except Exception as e:
        print(f"    [!] WHOIS lookup failed: {e}")
        result["whois_error"] = str(e)

    # basic security headers check on the site
    try:
        r = _get_with_retry(f"https://{domain}")
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


def check_email(email, hibp_api_key=None):
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
    except dns.resolver.NXDOMAIN:
        print(f"    [-] Domain '{domain}' does not exist (NXDOMAIN) - this email cannot be valid")
        result["mx_records"] = []
        result["mx_error"] = "domain does not exist"
    except dns.resolver.NoAnswer:
        print(f"    [-] No MX records for '{domain}' - domain exists but can't receive mail")
        result["mx_records"] = []
    except Exception as e:
        print(f"    [!] MX lookup failed: {e.__class__.__name__}: {e}")
        result["mx_records"] = []
        result["mx_error"] = f"{e.__class__.__name__}: {e}"

    # breach check via HaveIBeenPwned. Requires a paid API key - pass one via
    # --hibp-key or the HIBP_API_KEY environment variable. Same success/
    # status/reason shape used elsewhere in this tool (check_subdomains),
    # so a skipped check, a real "no breaches" result, and a failed check
    # are all distinguishable rather than collapsed into one ambiguous value.
    hibp = {"checked": False, "status": None, "reason": None, "breaches": []}
    if hibp_api_key:
        try:
            r = _get_with_retry(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                extra_headers={"hibp-api-key": hibp_api_key},
            )
            hibp["status"] = r.status_code
            if r.status_code == 200:
                breaches = [
                    {
                        "name": b.get("Name"),
                        "title": b.get("Title"),
                        "breach_date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in r.json()
                ]
                hibp["checked"] = True
                hibp["breaches"] = breaches
                print(f"    [!] BREACHED in {len(breaches)} known breach(es):")
                for b in breaches:
                    print(f"        - {b['title']} ({b['breach_date']}) - exposed: {', '.join(b['data_classes'])}")
            elif r.status_code == 404:
                hibp["checked"] = True
                hibp["breaches"] = []
                print("    [+] No known breaches (HIBP)")
            elif r.status_code == 401:
                hibp["reason"] = "Invalid or expired HIBP API key (401 Unauthorized)"
                print(f"    [!] {hibp['reason']}")
            elif r.status_code == 429:
                hibp["reason"] = "Still rate limited by HIBP after retries - try again later"
                print(f"    [!] {hibp['reason']}")
            else:
                hibp["reason"] = f"Unexpected HIBP status {r.status_code}"
                print(f"    [?] {hibp['reason']}")
        except requests.exceptions.RequestException as e:
            hibp["reason"] = f"Request failed: {e.__class__.__name__}"
            print(f"    [!] HIBP check failed: {hibp['reason']}")
    else:
        hibp["reason"] = "No HIBP API key provided"
        print("    [i] Skipping breach check - pass --hibp-key or set the HIBP_API_KEY environment variable.")
        print("    [i] Manually check: https://haveibeenpwned.com/")

    result["hibp"] = hibp
    return result


def _dms_to_decimal(dms):
    """Converts EXIF's (degrees, minutes, seconds) GPS format to a single decimal number."""
    degrees, minutes, seconds = dms
    return float(degrees) + float(minutes) / 60.0 + float(seconds) / 3600.0


def extract_exif(image_path):
    """
    Reads EXIF metadata from a local image: camera make/model, creation
    timestamp, software used, and GPS coordinates if present. Local file
    only, not a URL - downloading arbitrary images is a different, riskier
    feature (fetching untrusted remote files) that isn't in scope here.

    Many images have no EXIF at all by the time you get them - social
    media platforms, messaging apps, and screenshot tools routinely strip
    it either for privacy or because it was never there to begin with.
    That's reported as a normal outcome, not an error.
    """
    print(f"\n[*] Extracting EXIF metadata from '{image_path}'...")
    result = {
        "file": image_path, "has_exif": False, "format": None, "dimensions": None,
        "camera_make": None, "camera_model": None, "created": None, "software": None,
        "gps": None, "warnings": [],
    }

    try:
        from PIL import Image, ExifTags
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        print("    [!] Pillow not installed, skipping EXIF extraction. Run: pip install Pillow")
        result["warnings"].append("Pillow not installed")
        return result

    try:
        img = Image.open(image_path)
    except FileNotFoundError:
        print(f"    [!] File not found: {image_path}")
        result["warnings"].append("File not found")
        return result
    except Exception as e:
        print(f"    [!] Could not open image: {e.__class__.__name__}: {e}")
        result["warnings"].append(f"Could not open image: {e.__class__.__name__}: {e}")
        return result

    result["format"] = img.format
    result["dimensions"] = f"{img.width}x{img.height}"

    exif_data = img.getexif()
    if not exif_data:
        print("    [-] No EXIF data present (common - many platforms strip it on upload/re-save)")
        result["warnings"].append("No EXIF data found in this image")
        return result

    result["has_exif"] = True
    # exif values can include raw bytes (e.g. MakerNote, thumbnails) that
    # aren't JSON-serializable - convert those to a short description
    # instead of the raw blob so the report doesn't break or bloat.
    tags = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, tag_id)
        if isinstance(value, bytes):
            value = f"<binary data, {len(value)} bytes>"
        tags[tag_name] = value

    # getexif() only returns the top-level (0th IFD) tags - Make/Model/
    # Software live there, but DateTimeOriginal and other detailed shooting
    # info live in the "Exif" sub-IFD, same nested-pointer structure as GPS.
    try:
        exif_ifd = exif_data.get_ifd(ExifTags.IFD.Exif)
        for tag_id, value in exif_ifd.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                value = f"<binary data, {len(value)} bytes>"
            tags[tag_name] = value
    except Exception:
        pass  # no Exif sub-IFD present - fine, just means less detail available

    result["camera_make"] = tags.get("Make")
    result["camera_model"] = tags.get("Model")
    result["created"] = tags.get("DateTimeOriginal") or tags.get("DateTime")
    result["software"] = tags.get("Software")

    print(f"    [+] Format: {result['format']}, Dimensions: {result['dimensions']}")
    if result["camera_make"] or result["camera_model"]:
        print(f"    [+] Camera: {result['camera_make']} {result['camera_model']}")
    if result["created"]:
        print(f"    [+] Created: {result['created']}")
    if result["software"]:
        print(f"    [+] Software: {result['software']}")

    # GPS lives in a nested IFD (Image File Directory), not the top-level tags
    try:
        gps_ifd = exif_data.get_ifd(ExifTags.IFD.GPSInfo)
        if gps_ifd:
            gps_tags = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat, lat_ref = gps_tags.get("GPSLatitude"), gps_tags.get("GPSLatitudeRef")
            lon, lon_ref = gps_tags.get("GPSLongitude"), gps_tags.get("GPSLongitudeRef")
            if lat and lon:
                lat_deg = _dms_to_decimal(lat)
                if lat_ref == "S":
                    lat_deg = -lat_deg
                lon_deg = _dms_to_decimal(lon)
                if lon_ref == "W":
                    lon_deg = -lon_deg
                result["gps"] = {
                    "latitude": round(lat_deg, 6),
                    "longitude": round(lon_deg, 6),
                    "maps_url": f"https://www.google.com/maps?q={lat_deg:.6f},{lon_deg:.6f}",
                }
                print(f"    [!] GPS location found: {lat_deg:.6f}, {lon_deg:.6f}")
                print(f"        {result['gps']['maps_url']}")
    except Exception as e:
        result["warnings"].append(f"GPS parsing failed: {e.__class__.__name__}")

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


# --- identifier correlation engine ------------------------------------------
# Cross-references the identifiers the user supplied (username/domain/email)
# against data the other checks already collected, to surface direct
# ownership/identity links a human analyst would otherwise have to spot by
# hand (e.g. "this domain's WHOIS email is the same email you're
# investigating"). Deliberately narrow for v1: every rule here requires a
# direct, literal match between two independently-supplied identifiers.
# Weaker heuristics (e.g. "photo timestamp is close to the domain's
# registration date") are left out on purpose, so every finding is backed by
# real evidence rather than a guess. Makes no network requests of its own -
# purely reads what check_username()/check_domain()/check_email() already
# collected in `report`.
def correlate_findings(report):
    findings = []
    target = report.get("target", {})
    username = target.get("username")
    domain = target.get("domain")
    email_results = report.get("email_results") or {}
    domain_results = report.get("domain_results") or {}

    email = email_results.get("email")

    # --- email's domain matches the domain being scanned ---
    if email and email_results.get("format_valid") and domain and "@" in email:
        email_domain = email.split("@", 1)[1].lower()
        scanned_domain = domain.lower()
        if email_domain == scanned_domain or email_domain.endswith("." + scanned_domain):
            findings.append({
                "type": "email_domain_matches_scanned_domain",
                "confidence": "High",
                "description": (
                    f"The investigated email '{email}' is hosted on '{domain}' - "
                    f"the domain being scanned is the same one backing this email address."
                ),
            })

    # --- username appears as an exact subdomain label ---
    if username and domain:
        subdomain_info = domain_results.get("subdomains", {})
        if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
            username_lower = username.lower()
            domain_lower = domain.lower()
            matched_subs = []
            for sub in subdomain_info.get("subdomains", []):
                if sub == domain_lower:
                    continue  # the apex domain itself, not a subdomain label
                label = sub[:-(len(domain_lower) + 1)] if sub.endswith("." + domain_lower) else sub
                leftmost_label = label.split(".")[0]
                if leftmost_label == username_lower:
                    matched_subs.append(sub)
            if matched_subs:
                findings.append({
                    "type": "username_in_subdomains",
                    "confidence": "High",
                    "description": (
                        f"Subdomain(s) {', '.join(matched_subs)} match the username "
                        f"'{username}' exactly - likely a personal or user-specific subdomain."
                    ),
                })

    # --- WHOIS registrant email matches the investigated email directly ---
    registrant_emails = domain_results.get("registrant_emails") or []
    if email and any(email.lower() == e.lower() for e in registrant_emails):
        findings.append({
            "type": "whois_registrant_email_matches_target_email",
            "confidence": "High",
            "description": (
                f"WHOIS registrant contact for '{domain}' lists the email '{email}' "
                f"directly - this domain is very likely registered by the same person "
                f"under investigation."
            ),
        })

    # --- WHOIS registrant name/org contains the username ---
    # Weaker than the exact-match rules above (registrant name/org are free
    # text, so a substring hit isn't as ironclad as an exact email or
    # subdomain match) - rated Medium rather than High for that reason.
    if username:
        username_lower = username.lower()
        for label, value in (
            ("name", domain_results.get("registrant_name")),
            ("organization", domain_results.get("registrant_org")),
        ):
            if value and username_lower in value.lower():
                findings.append({
                    "type": "whois_registrant_matches_username",
                    "confidence": "Medium",
                    "description": (
                        f"WHOIS registrant {label} for '{domain}' ('{value}') contains "
                        f"the username '{username}' - possible link, but registrant "
                        f"fields are free text so this is weaker evidence than an exact "
                        f"email or subdomain match."
                    ),
                })

    return findings


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
        hibp = email_results.get("hibp", {})
        if hibp.get("checked") and len(hibp.get("breaches", [])) > 0:
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


# --- HTML report generation -------------------------------------------------
# Turns the same `report` dict everything else already populates into a
# single self-contained HTML file - inline CSS only, no external requests,
# no JS framework, so it opens and reads correctly offline with nothing but
# a browser. Deliberately built last: every other check feeds it, so this is
# the piece that actually turns raw recon output into something that reads
# like an assessment.
#
# Every value that originated from an external source (WHOIS text,
# subdomains, breach titles, redirect targets) goes through html.escape()
# before being embedded - none of that text is under our control, and this
# is a security tool, so treating it as untrusted by default is the right
# default even though it's just rendered to a local file.
#
# Colors are CSS variable references, not raw hex, so a single severity/
# confidence value renders correctly in both light and dark mode without
# the Python side needing to know which theme is active.
_SEVERITY_COLORS = {
    "Low": "var(--sev-low)", "Medium": "var(--sev-medium)",
    "High": "var(--sev-high)", "Critical": "var(--sev-critical)",
}
_CONFIDENCE_COLORS = {
    "High": "var(--conf-high)", "Medium": "var(--conf-medium)", "Low": "var(--conf-low)",
}
_SECTION_LABELS = {
    "risk": "Assessment", "correlations": "Correlations", "username": "Username",
    "domain": "Domain", "email": "Email", "exif": "Image", "dorks": "Dorks",
}

_REPORT_CSS = """
:root {
  --bg: #f2f4f1; --panel: #fbfcfa; --hairline: #d7dcd3; --fg: #16211f; --muted: #5c6960;
  --accent: #0f6e5c; --ok: #2f9e44; --bad: #b42318;
  --sev-low: #2f9e44; --sev-medium: #b8860b; --sev-high: #c2610c; --sev-critical: #b42318;
  --conf-high: #0f6e5c; --conf-medium: #b8860b; --conf-low: #5c6960;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101513; --panel: #171d1b; --hairline: #2a332f; --fg: #e7ece9; --muted: #93a39b;
    --accent: #35b897; --ok: #51cf66; --bad: #ff6b6b;
    --sev-low: #51cf66; --sev-medium: #e0b341; --sev-high: #ff922b; --sev-critical: #ff6b6b;
    --conf-high: #35b897; --conf-medium: #e0b341; --conf-low: #93a39b;
  }
}
:root[data-theme="dark"] {
  --bg: #101513; --panel: #171d1b; --hairline: #2a332f; --fg: #e7ece9; --muted: #93a39b;
  --accent: #35b897; --ok: #51cf66; --bad: #ff6b6b;
  --sev-low: #51cf66; --sev-medium: #e0b341; --sev-high: #ff922b; --sev-critical: #ff6b6b;
  --conf-high: #35b897; --conf-medium: #e0b341; --conf-low: #93a39b;
}
:root[data-theme="light"] {
  --bg: #f2f4f1; --panel: #fbfcfa; --hairline: #d7dcd3; --fg: #16211f; --muted: #5c6960;
  --accent: #0f6e5c; --ok: #2f9e44; --bad: #b42318;
  --sev-low: #2f9e44; --sev-medium: #b8860b; --sev-high: #c2610c; --sev-critical: #b42318;
  --conf-high: #0f6e5c; --conf-medium: #b8860b; --conf-low: #5c6960;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); line-height: 1.55; font-family: var(--sans); font-size: 15px; }
a { color: var(--accent); }
a:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.report {
  max-width: 1080px; margin: 0 auto; padding: 2.5rem 1.5rem 5rem;
  display: grid; grid-template-columns: 250px 1fr; gap: 2.25rem; align-items: start;
}
.sidebar {
  position: sticky; top: 2rem; background: var(--panel); border: 1px solid var(--hairline);
  border-radius: 8px; padding: 1.5rem;
}
.wordmark { font-family: var(--mono); font-weight: 700; font-size: 1rem; letter-spacing: 0.01em; }
.wordmark .sub {
  display: block; font-weight: 500; color: var(--muted); font-size: 0.66rem;
  letter-spacing: 0.14em; text-transform: uppercase; margin-top: 0.25rem;
}
.identity { margin: 1.25rem 0; display: flex; flex-direction: column; gap: 0.5rem; }
.identity-row { display: flex; justify-content: space-between; gap: 0.75rem; }
.identity-row .k {
  font-family: var(--mono); color: var(--muted); text-transform: uppercase;
  font-size: 0.64rem; letter-spacing: 0.07em; padding-top: 0.2rem; white-space: nowrap;
}
.identity-row .v { text-align: right; font-weight: 600; font-size: 0.85rem; word-break: break-word; }
.gauge-block { border-top: 1px solid var(--hairline); padding-top: 1.25rem; margin-top: 0.25rem; }
.gauge { position: relative; width: 92px; height: 92px; margin: 0 auto; }
.gauge svg { width: 100%; height: 100%; }
.gauge-track { stroke: var(--hairline); stroke-width: 2.5; fill: none; }
.gauge-fill { stroke-width: 2.5; stroke-linecap: round; fill: none; }
.gauge-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.gauge-value .num { font-family: var(--mono); font-weight: 700; font-size: 1.3rem; font-variant-numeric: tabular-nums; }
.gauge-value .max { font-size: 0.6rem; color: var(--muted); margin-top: -0.15rem; }
.gauge-caption { text-align: center; margin-top: 0.6rem; }
.severity-pill {
  display: inline-block; color: #fff; font-family: var(--mono); font-weight: 600;
  font-size: 0.68rem; letter-spacing: 0.05em; text-transform: uppercase;
  padding: 0.2rem 0.6rem; border-radius: 3px;
}
.no-score { color: var(--muted); font-size: 0.85rem; text-align: center; padding: 1rem 0; margin: 0; }
.toc { display: flex; flex-direction: column; gap: 0.15rem; margin-top: 1.25rem; padding-top: 1.25rem; border-top: 1px solid var(--hairline); }
.toc-label { font-family: var(--mono); font-size: 0.64rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.4rem; }
.toc a { color: var(--fg); text-decoration: none; font-size: 0.85rem; padding: 0.25rem 0 0.25rem 0.6rem; border-left: 2px solid transparent; margin-left: -0.6rem; }
.toc a:hover, .toc a:focus-visible { border-left-color: var(--accent); color: var(--accent); }
.meta { font-size: 0.72rem; color: var(--muted); margin-top: 1.25rem; }
.main { display: flex; flex-direction: column; gap: 1.5rem; min-width: 0; }
.panel { background: var(--panel); border: 1px solid var(--hairline); border-radius: 8px; padding: 1.5rem 1.75rem; scroll-margin-top: 1.5rem; }
.panel h2 {
  margin: 0 0 1.1rem; font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.09em; color: var(--muted);
  display: flex; align-items: center; gap: 0.55rem;
}
.panel h2::before { content: ""; width: 0.42rem; height: 0.42rem; border-radius: 50%; flex-shrink: 0; background: var(--dot, var(--hairline)); }
.panel h3 { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; margin: 1.25rem 0 0.6rem; font-weight: 600; }
.panel h3:first-of-type { margin-top: 0; }
.muted { color: var(--muted); }
.small { font-size: 0.83rem; }
.ok { color: var(--ok); }
.bad { color: var(--bad); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
table.kv td, table.rules td { padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--hairline); vertical-align: top; text-align: left; }
table.kv tr:last-child td, table.rules tr:last-child td { border-bottom: none; }
table.kv td:first-child { color: var(--muted); width: 32%; white-space: nowrap; font-size: 0.82rem; }
table.rules td.pts { font-family: var(--mono); font-weight: 700; width: 3.25rem; font-variant-numeric: tabular-nums; }
ul { padding-left: 1.1rem; margin: 0.5rem 0; }
ul.platform-list, ul.subdomain-list, ul.dorks, ul.breaches, ul.findings, ul.headers { list-style: none; padding-left: 0; margin: 0; }
ul.platform-list li, ul.subdomain-list li { padding: 0.4rem 0; border-bottom: 1px solid var(--hairline); font-size: 0.88rem; }
ul.platform-list li:last-child, ul.subdomain-list li:last-child { border-bottom: none; }
ul.platform-list a { color: var(--fg); text-decoration: none; font-weight: 600; }
ul.platform-list a:hover, ul.platform-list a:focus-visible { color: var(--accent); text-decoration: underline; }
li.finding { display: flex; gap: 0.65rem; align-items: flex-start; padding: 0.5rem 0; border-bottom: 1px solid var(--hairline); font-size: 0.88rem; }
li.finding:last-child { border-bottom: none; }
.badge {
  display: inline-block; color: #fff; font-family: var(--mono); font-size: 0.66rem; font-weight: 700;
  letter-spacing: 0.03em; text-transform: uppercase; padding: 0.2rem 0.5rem; border-radius: 3px;
  white-space: nowrap; margin-top: 0.1rem;
}
ul.headers li { padding: 0.2rem 0; font-size: 0.88rem; }
details summary { cursor: pointer; color: var(--muted); font-size: 0.82rem; margin-top: 0.75rem; font-family: var(--mono); text-transform: uppercase; letter-spacing: 0.04em; }
details[open] summary { margin-bottom: 0.5rem; }
li.breach { border-bottom: 1px solid var(--hairline); padding: 0.6rem 0; font-size: 0.88rem; }
li.breach:last-child { border-bottom: none; }
@media (max-width: 860px) {
  .report { grid-template-columns: 1fr; }
  .sidebar { position: static; }
}
@media print {
  body { background: #fff; color: #000; }
  .report { grid-template-columns: 200px 1fr; }
  .sidebar { position: static; break-inside: avoid; }
  .toc { display: none; }
  .panel { break-inside: avoid; }
}
"""


def _panel(section_id, title, body_html, dot_color=None):
    dot_style = f' style="--dot:{dot_color}"' if dot_color else ""
    return f'<section class="panel" id="{section_id}"><h2{dot_style}>{html.escape(title)}</h2>{body_html}</section>'


def _html_sidebar(report, nav_html):
    target = report.get("target", {})
    rows = "".join(
        f'<div class="identity-row"><span class="k">{label}</span><span class="v">{html.escape(str(value))}</span></div>'
        for label, key in (("username", "username"), ("domain", "domain"), ("email", "email"), ("image", "image"))
        for value in [target.get(key)] if value
    )

    risk = report.get("risk_score")
    if risk:
        score = risk.get("score", 0)
        max_score = risk.get("max_score", 100)
        severity = risk.get("severity", "Low")
        color = _SEVERITY_COLORS.get(severity, "var(--conf-low)")
        pct = max(0, min(100, int(100 * score / max_score) if max_score else 0))
        gauge_html = f"""
        <div class="gauge-block">
          <div class="gauge">
            <svg viewBox="0 0 36 36">
              <circle class="gauge-track" cx="18" cy="18" r="15.9155" />
              <circle class="gauge-fill" cx="18" cy="18" r="15.9155"
                      stroke-dasharray="{pct} {100 - pct}" transform="rotate(-90 18 18)"
                      style="stroke:{color}" />
            </svg>
            <div class="gauge-value"><span class="num">{score}</span><span class="max">/ {max_score}</span></div>
          </div>
          <div class="gauge-caption"><span class="severity-pill" style="background:{color}">{html.escape(severity)}</span></div>
        </div>
        """
    else:
        gauge_html = '<div class="gauge-block"><p class="no-score">Not scored</p></div>'

    generated_at = html.escape(str(report.get("generated_at", "")))
    return f"""
    <aside class="sidebar">
      <div class="wordmark">OSINT FOOTPRINT<span class="sub">Analyzer &middot; Report</span></div>
      <div class="identity">{rows}</div>
      {gauge_html}
      <nav class="toc">
        <span class="toc-label">Contents</span>
        {nav_html}
      </nav>
      <div class="meta">Generated {generated_at}</div>
    </aside>
    """


def _html_risk_section(risk):
    if not risk:
        return ""
    severity = risk.get("severity", "Low")
    color = _SEVERITY_COLORS.get(severity, "var(--conf-low)")
    triggered = risk.get("triggered_rules", [])
    if triggered:
        rows = "".join(
            f'<tr><td class="pts">+{html.escape(str(t["points"]))}</td>'
            f'<td>{html.escape(t["description"])}'
            f'<div class="muted small">{html.escape(t["recommendation"])}</div></td></tr>'
            for t in triggered
        )
        body = f'<div class="table-wrap"><table class="rules">{rows}</table></div>'
    else:
        body = '<p class="muted">No risk factors triggered.</p>'
    return _panel("risk", "Exposure Assessment", body, dot_color=color)


def _html_correlations_section(correlations):
    if correlations is None:
        return ""
    if not correlations:
        body = '<p class="muted">No direct correlations found between the supplied identifiers.</p>'
        return _panel("correlations", "Identifier Correlations", body)
    items = "".join(
        f'<li class="finding"><span class="badge" '
        f'style="background:{_CONFIDENCE_COLORS.get(c["confidence"], "var(--conf-low)")}">'
        f'{html.escape(c["confidence"])}</span><span>{html.escape(c["description"])}</span></li>'
        for c in correlations
    )
    body = f'<ul class="findings">{items}</ul>'
    return _panel("correlations", "Identifier Correlations", body, dot_color="var(--accent)")


def _html_username_section(results):
    if not results:
        return ""

    def render_group(entries):
        if not entries:
            return '<p class="muted small">None</p>'
        items = []
        for e in entries:
            platform = html.escape(e.get("platform", ""))
            url = html.escape(e.get("url", ""))
            notes = []
            if e.get("reason"):
                notes.append(html.escape(e["reason"]))
            if e.get("redirected_to"):
                notes.append(f'redirected to {html.escape(e["redirected_to"])}')
            notes_html = f'<div class="muted small">{" &middot; ".join(notes)}</div>' if notes else ""
            items.append(f'<li><a href="{url}" target="_blank" rel="noopener">{platform}</a>{notes_html}</li>')
        return f'<ul class="platform-list">{"".join(items)}</ul>'

    found = results.get("found", [])
    unclear = results.get("unclear", [])
    not_found = results.get("not_found", [])
    errors = results.get("error", [])
    errors_html = f'<details><summary>Errors ({len(errors)})</summary>{render_group(errors)}</details>' if errors else ""

    body = f"""
      <h3>Found ({len(found)})</h3>
      {render_group(found)}
      <details>
        <summary>Unclear ({len(unclear)})</summary>
        {render_group(unclear)}
      </details>
      <details>
        <summary>Not found ({len(not_found)})</summary>
        {render_group(not_found)}
      </details>
      {errors_html}
    """
    return _panel("username", "Username Footprint", body)


def _html_domain_section(results):
    if not results:
        return ""

    dns_records = results.get("dns_records", {})
    dns_note = ""
    if dns_records.get("skipped"):
        dns_note = f'<p class="muted small">{html.escape(str(dns_records.get("reason", "")))}</p>'
    elif dns_records.get("nxdomain"):
        dns_note = '<p class="bad small">Domain does not exist (NXDOMAIN)</p>'

    def _dns_value_cell(values):
        return html.escape(", ".join(values)) if values else '<span class="muted">none</span>'

    dns_rows = "".join(
        f'<tr><td>{html.escape(rtype)}</td><td>{_dns_value_cell(values)}</td></tr>'
        for rtype, values in dns_records.items()
        if rtype not in ("nxdomain", "skipped", "reason")
    )

    whois_note = ""
    if results.get("whois"):
        whois_note = f'<p class="muted small">{html.escape(str(results["whois"]))}</p>'
    elif results.get("whois_error"):
        whois_note = f'<p class="muted small">WHOIS lookup failed: {html.escape(str(results["whois_error"]))}</p>'

    whois_rows = ""
    for label, key in (
        ("Registrar", "registrar"), ("Created", "creation_date"), ("Expires", "expiration_date"),
        ("Registrant name", "registrant_name"), ("Registrant org", "registrant_org"),
    ):
        value = results.get(key)
        if value:
            whois_rows += f"<tr><td>{label}</td><td>{html.escape(str(value))}</td></tr>"
    registrant_emails = results.get("registrant_emails") or []
    if registrant_emails:
        whois_rows += f'<tr><td>Registrant email(s)</td><td>{html.escape(", ".join(registrant_emails))}</td></tr>'
    whois_html = f'<div class="table-wrap"><table class="kv">{whois_rows}</table></div>' if whois_rows else whois_note

    present = results.get("security_headers_present", {})
    missing = results.get("security_headers_missing", [])
    headers_items = "".join(f'<li class="ok">&check; {html.escape(h)}</li>' for h in present)
    headers_items += "".join(f'<li class="bad">&cross; {html.escape(h)}</li>' for h in missing)
    headers_html = f'<ul class="headers">{headers_items}</ul>' if headers_items else ""

    subdomain_info = results.get("subdomains", {})
    sub_html = ""
    if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
        sub_list = subdomain_info.get("subdomains", [])
        items = "".join(f"<li>{html.escape(s)}</li>" for s in sub_list)
        sub_html = (
            f'<details><summary>Subdomains ({len(sub_list)})</summary>'
            f'<ul class="subdomain-list">{items}</ul></details>'
        )
    elif isinstance(subdomain_info, dict) and subdomain_info.get("reason"):
        sub_html = f'<p class="muted small">Subdomain lookup unavailable: {html.escape(subdomain_info["reason"])}</p>'

    body = f"""
      <h3>DNS Records</h3>
      {dns_note}
      <div class="table-wrap"><table class="kv">{dns_rows}</table></div>
      <h3>WHOIS</h3>
      {whois_html}
      <h3>Security Headers</h3>
      {headers_html}
      {sub_html}
    """
    return _panel("domain", "Domain Recon", body)


def _html_email_section(results):
    if not results:
        return ""
    email_raw = results.get("email", "")
    valid = results.get("format_valid")
    mx = results.get("mx_records", [])
    hibp = results.get("hibp", {})
    dot = None

    if hibp.get("checked"):
        breaches = hibp.get("breaches", [])
        if breaches:
            dot = "var(--sev-high)"
            items = "".join(
                f'<li class="breach"><strong>{html.escape(b.get("title", ""))}</strong> '
                f'<span class="muted small">({html.escape(b.get("breach_date", ""))})</span>'
                f'<div class="muted small">Exposed: {html.escape(", ".join(b.get("data_classes", [])))}</div></li>'
                for b in breaches
            )
            hibp_html = f'<p class="bad">Breached in {len(breaches)} known breach(es):</p><ul class="breaches">{items}</ul>'
        else:
            hibp_html = '<p class="ok">No known breaches (HaveIBeenPwned)</p>'
    else:
        reason = hibp.get("reason") or "Not checked"
        hibp_html = f'<p class="muted">Breach check skipped: {html.escape(reason)}</p>'

    body = f"""
      <p>Format valid: {"&check; yes" if valid else "&cross; no"}</p>
      {f'<p>MX records: {html.escape(", ".join(mx))}</p>' if mx else ""}
      {hibp_html}
    """
    return _panel("email", f"Email: {email_raw}", body, dot_color=dot)


def _html_exif_section(results):
    if not results:
        return ""
    if not results.get("has_exif"):
        file_name = html.escape(str(results.get("file", "")))
        body = f'<p class="muted">No EXIF data present in \'{file_name}\'.</p>'
        return _panel("exif", "Image Metadata (EXIF)", body)

    rows = ""
    for label, key in (
        ("Format", "format"), ("Dimensions", "dimensions"), ("Camera make", "camera_make"),
        ("Camera model", "camera_model"), ("Created", "created"), ("Software", "software"),
    ):
        value = results.get(key)
        if value:
            rows += f"<tr><td>{label}</td><td>{html.escape(str(value))}</td></tr>"

    gps = results.get("gps")
    dot = None
    gps_html = ""
    if gps:
        dot = "var(--sev-high)"
        maps_url = html.escape(gps["maps_url"])
        gps_html = (
            f'<p class="bad">GPS location found: {gps["latitude"]}, {gps["longitude"]} - '
            f'<a href="{maps_url}" target="_blank" rel="noopener">view on map</a></p>'
        )

    body = f'<div class="table-wrap"><table class="kv">{rows}</table></div>{gps_html}'
    return _panel("exif", "Image Metadata (EXIF)", body, dot_color=dot)


def _html_dorks_section(dorks):
    if not dorks:
        return ""
    items = "".join(
        f'<li><a href="https://www.google.com/search?q={url_quote(d)}" target="_blank" rel="noopener">'
        f'{html.escape(d)}</a></li>'
        for d in dorks
    )
    body = f'<ul class="dorks">{items}</ul>'
    return _panel("dorks", "Suggested Manual Dorks", body)


def generate_html_report(report):
    section_defs = [
        ("risk", _html_risk_section(report.get("risk_score"))),
        ("correlations", _html_correlations_section(report.get("correlations"))),
        ("username", _html_username_section(report.get("username_results"))),
        ("domain", _html_domain_section(report.get("domain_results"))),
        ("email", _html_email_section(report.get("email_results"))),
        ("exif", _html_exif_section(report.get("exif_results"))),
        ("dorks", _html_dorks_section(report.get("suggested_dorks"))),
    ]
    present = [sid for sid, content in section_defs if content]
    nav_html = "".join(f'<a href="#{sid}">{_SECTION_LABELS[sid]}</a>' for sid in present)
    main_content = "\n".join(content for _, content in section_defs if content)
    sidebar = _html_sidebar(report, nav_html)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Footprint Report</title>
<style>
{_REPORT_CSS}
</style>
</head>
<body>
<div class="report">
{sidebar}
<main class="main">
{main_content}
</main>
</div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="OSINT Footprint Analyzer v0.1")
    parser.add_argument("--username", help="username to search across platforms")
    parser.add_argument("--domain", help="domain to recon")
    parser.add_argument("--email", help="email to check")
    parser.add_argument("--image", help="path to a local image file for EXIF metadata extraction")
    parser.add_argument("--hibp-key", help="HaveIBeenPwned API key for live breach checking "
                                            "(or set the HIBP_API_KEY environment variable instead, "
                                            "so the key never ends up typed into shell history or a script)")
    parser.add_argument("--out", help="save results to JSON file", default=None)
    parser.add_argument("--html", help="save a self-contained HTML report to this path", default=None)
    args = parser.parse_args()

    if not any([args.username, args.domain, args.email, args.image]):
        parser.print_help()
        sys.exit(1)

    # CLI flag takes precedence if both are set, but the env var is the
    # recommended path - it never ends up in shell history or a committed script
    hibp_api_key = args.hibp_key or os.environ.get("HIBP_API_KEY")

    report = {
        "generated_at": datetime.now().isoformat() + "Z",
        "target": {
            "username": args.username,
            "domain": args.domain,
            "email": args.email,
            "image": args.image,
        },
    }

    if args.username:
        report["username_results"] = check_username(args.username)

    if args.domain:
        report["domain_results"] = check_domain(args.domain)

    if args.email:
        report["email_results"] = check_email(args.email, hibp_api_key=hibp_api_key)

    if args.image:
        report["exif_results"] = extract_exif(args.image)

    # correlation runs after all data collection, purely analyzing what's
    # already in `report` - no new requests, so it naturally covers whichever
    # combination of username/domain/email was actually supplied
    correlations = correlate_findings(report)
    report["correlations"] = correlations
    if correlations:
        print("\n[*] Identifier correlations found:")
        for c in correlations:
            print(f"    [{c['confidence']:6s}] {c['description']}")
    else:
        print("\n[*] No direct identifier correlations found.")

    dorks = generate_dorks(args.username, args.domain, args.email)
    if dorks:
        print("\n[*] Suggested manual Google dorks:")
        for d in dorks:
            print(f"    {d}")
        report["suggested_dorks"] = dorks

    # risk score is computed last - it only reads what's already in `report`,
    # so it naturally reflects whichever checks were actually run
    risk = calculate_risk(report)
    report["risk_score"] = risk
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

    if args.html:
        with open(args.html, "w") as f:
            f.write(generate_html_report(report))
        print(f"[+] HTML report saved to {args.html}")

    print("\n[*] Done.")


if __name__ == "__main__":





    main()