# OSINT Footprint Analyzer

A CLI tool for gathering publicly available information about a username, domain, or email address — built as a hands-on OSINT reconnaissance project.

> **Status: active development.** Core recon features are solid and content-verified where it matters; correlation engine, EXIF extraction, and HTML reporting are still ahead (see Roadmap below).

## What it does

- **Username enumeration** — checks for account existence across 15 platforms (GitHub, X, Instagram, Reddit, TikTok, GitLab, Medium, Pinterest, Steam, Hacker News, Keybase, Dev.to, YouTube, Twitch, Docker Hub), with a two-tier trust model (see below)
- **Domain recon** — DNS resolution, WHOIS lookup (registrar, creation/expiry dates, nameservers), missing security header checks (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), and passive subdomain enumeration via Certificate Transparency logs (crt.sh)
- **Email checks** — format validation, MX record lookup, and a breach-check stub (wired up for the HaveIBeenPwned API, disabled by default since HIBP now requires a paid key)
- **Exposure risk score** — a 0–100 score with a Low/Medium/High/Critical severity label, computed from a data-driven rule set (breach found, missing security headers, large subdomain count, large public username footprint), each finding paired with a recommendation
- **Google dork generation** — outputs relevant manual-search queries for further investigation
- **JSON export** — save full results to a file for later reference or reporting

## How username detection actually works

A plain HTTP status code (`200` = found, `404` = not found) is not trustworthy on its own — several platforms return `200` for accounts that don't exist, or block scripted requests entirely regardless of whether the account is real. Rather than take status codes at face value everywhere, each platform is checked and classified individually:

- **Reliable, status-code-only** (GitHub, HackerNews, Keybase, Dev.to, Docker Hub) — server-rendered pages, a real 404 comes back for missing accounts, status code alone is trustworthy.
- **Reliable, content-verified** (Steam, Medium) — the platform can return a `200` even for accounts that don't exist, so the response body is checked for a specific "not found" indicator (Steam) or the presence/absence of expected profile metadata (Medium's `og:title` tag) before trusting the result.
- **Unreliable / can't be confirmed via plain HTTP** (Twitter/X, Instagram, TikTok, Pinterest, YouTube, Twitch, Reddit, GitLab) — either a JavaScript single-page app that serves the same generic shell for any URL, real or fake (confirmed empirically: a deliberately fake Instagram username still returned 200), or a platform sitting behind bot-detection that blocks or challenges plain scripted requests regardless of username (Reddit currently serves the same "please wait for verification" interstitial for both real and fake usernames; GitLab's Cloudflare protection frequently 403s plain requests even for known-real accounts). These are always reported as `unclear`, never a false `found`.

This isn't a static list — Reddit, for example, used to be checkable via a documented "not found" message (per the [Sherlock project](https://github.com/sherlock-project/sherlock)'s detection database), but empirical testing found that check no longer works against Reddit's current frontend, so it was moved to the unreliable tier rather than left silently wrong. Every result includes a `reason` field explaining exactly why it landed in `unclear`, so nothing is a black box.

## Installation

```bash
git clone https://github.com/Youssef-Solimann/osint-footprint-analyzer.git
cd osint-footprint-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

92 tests covering the pure logic (risk scoring, correlation engine, WHOIS/EXIF parsing) and the networked checks (username enumeration, DNS, WHOIS, HIBP) via mocked requests — nothing hits the network during the test run.

## Usage

```bash
# check a single target type
python3 osint_footprint.py --username johndoe
python3 osint_footprint.py --domain example.com
python3 osint_footprint.py --email john@example.com

# combine targets and save to a file
python3 osint_footprint.py --username johndoe --domain example.com --email john@example.com --out results.json
```

## Example output

```
[*] Checking username 'johndoe' across 15 platforms...
    [+] GitHub       FOUND     https://github.com/johndoe
    [-] Reddit       not found
    [?] Twitter/X    status=200 but this platform can't be reliably checked - not confirmed, verify manually
    [-] Steam        not found (200 status, but page content confirms no such user)

[*] Domain recon for 'example.com'...
    [+] Resolves to: 93.184.216.34
    [+] Registrar: Reserved Domain
    [-] Security headers missing: ['Content-Security-Policy']
    [+] Found 12 unique subdomains

[*] Exposure risk score: 18/100 (Low)
    +10  Domain does not enforce HTTPS (missing Strict-Transport-Security)
    +8   Domain has no Content-Security-Policy header (weaker XSS protection)

[*] Suggested manual Google dorks:
    "johndoe" site:pastebin.com
    site:example.com filetype:pdf
```

## Known limitations

- **No rate limiting beyond a flat delay** — sequential requests with a fixed 0.3s pause between them, no exponential backoff or `Retry-After` handling on 429 yet.
- **HIBP breach checking is disabled by default** — requires a paid API key. Manual check recommended at [haveibeenpwned.com](https://haveibeenpwned.com/) until this is added.
- **GitLab is frequently unreachable via plain scripted requests** — sits behind aggressive Cloudflare bot protection that 403s even known-real accounts under normal conditions; expect it to show up as `unclear` more often than other platforms.
- **Subdomain enumeration is passive-only** (Certificate Transparency logs) — it will miss subdomains that never had a public HTTPS certificate issued.
- **No EXIF/metadata extraction, correlation engine, or HTML report yet** — see Roadmap.

## Roadmap

- [ ] Per-platform content checks to reduce false positives
- [ ] Concurrent requests (currently sequential)
- [ ] HTML report output for portfolio/writeup use
- [ ] Optional HIBP integration once API key is available

## Tech stack

Python 3, `requests`, `python-whois`, `dnspython`

## Disclaimer

Built for educational and authorized reconnaissance purposes only (CTF practice, personal footprint auditing, portfolio development). Don't use this against targets you don't have permission to investigate.