"""
Shared infrastructure used by every recon module: the HTTP retry wrapper,
the constants it depends on, and the dork-generation helper (which doesn't
belong to any single recon type since it reads from all three).
"""

import time

import requests

TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Footprint-Analyzer/0.1)"}

MAX_RETRIES = 2       # retry attempts after the initial request, on 429 only
MAX_BACKOFF_WAIT = 15  # cap how long we'll ever sleep for one retry, seconds


def get_with_retry(url, max_retries=MAX_RETRIES, extra_headers=None):
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
