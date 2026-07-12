# OSINT Footprint Analyzer

A CLI tool for gathering publicly available information about a username, domain, or email address — built as a hands-on OSINT reconnaissance project.

> **Status: early development.** This is a first working version. Expect rough edges, especially around false positives in platform detection (see Known Limitations below).

## What it does

- **Username enumeration** — checks for account existence across 15+ platforms (GitHub, X, Instagram, Reddit, TikTok, GitLab, Medium, Pinterest, Steam, Hacker News, Keybase, Dev.to, YouTube, Twitch, Docker Hub)
- **Domain recon** — DNS resolution, WHOIS lookup (registrar, creation/expiry dates, nameservers), and a check for missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- **Email checks** — format validation, MX record lookup, and a breach-check stub (wired up for the HaveIBeenPwned API, disabled by default since HIBP now requires a paid key)
- **Google dork generation** — outputs relevant manual-search queries for further investigation
- **JSON export** — save full results to a file for later reference or reporting

## Installation

```bash
git clone https://github.com/Youssef-Solimann/osint-footprint-analyzer.git
cd osint-footprint-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

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
    [?] Twitter/X    status=403 (unclear) https://x.com/johndoe

[*] Domain recon for 'example.com'...
    [+] Resolves to: 93.184.216.34
    [+] Registrar: Reserved Domain
    [-] Security headers missing: ['Content-Security-Policy']

[*] Suggested manual Google dorks:
    "johndoe" site:pastebin.com
    site:example.com filetype:pdf
```

## Known limitations (v0.1)

- **Platform detection is a naive heuristic** — HTTP 200 = "found", 404 = "not found". Some platforms return 200 for "user not found" pages, and some block scripted requests with 403 regardless of whether the account exists. This produces false positives/unclear results and needs per-platform content checks in a future version.
- **No rate limiting beyond a flat delay** — sequential requests with a fixed 0.3s pause between them, no exponential backoff.
- **HIBP breach checking is disabled by default** — requires a paid API key. Manual check recommended at [haveibeenpwned.com](https://haveibeenpwned.com/) until this is added.
- **WHOIS/MX checks degrade silently** if `python-whois` / `dnspython` aren't installed rather than erroring out clearly.

## Roadmap

- [ ] Per-platform content checks to reduce false positives
- [ ] Concurrent requests (currently sequential)
- [ ] HTML report output for portfolio/writeup use
- [ ] Optional HIBP integration once API key is available

## Tech stack

Python 3, `requests`, `python-whois`, `dnspython`

## Disclaimer

Built for educational and authorized reconnaissance purposes only (CTF practice, personal footprint auditing, portfolio development). Don't use this against targets you don't have permission to investigate.
