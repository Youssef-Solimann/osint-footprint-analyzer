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
import os
import re
import sys
import time
from datetime import datetime

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

    print("\n[*] Done.")


if __name__ == "__main__":
    main()