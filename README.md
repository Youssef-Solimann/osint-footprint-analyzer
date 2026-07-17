# OSINT Footprint Analyzer

A CLI tool for gathering publicly available information about a username, domain, email address, or photo — and turning it into an assessment, not just a data dump.

> **Status: v1.1.0.** Username enumeration, domain recon, email/breach checks, EXIF/GPS extraction, an identifier correlation engine, exposure risk scoring, and a self-contained HTML report are all in place, backed by a 161-test suite. See Roadmap below for what's deliberately left for later.

## What it does

- **Username enumeration** — checks for account existence across 15 platforms concurrently (GitHub, X, Instagram, Reddit, TikTok, GitLab, Medium, Pinterest, Steam, Hacker News, Keybase, Dev.to, YouTube, Twitch, Docker Hub), with a two-tier trust model (see below)
- **Domain recon** — DNS resolution, WHOIS (registrar, dates, registrant, name servers), security headers, SPF/DMARC, technology fingerprinting (Cloudflare, Nginx, GitHub Pages, etc.), certificate issuer/validity, `robots.txt`/`security.txt`, HTTP redirect chains, and passive subdomain enumeration via Certificate Transparency logs (crt.sh)
- **Email checks** — format validation, MX record lookup, and a live HaveIBeenPwned breach check (requires a paid API key; degrades gracefully without one)
- **EXIF/GPS extraction** — camera make/model, timestamps, software, and GPS coordinates from a local photo, including HEIC/HEIF (the default format for iPhone photos)
- **Identifier correlation engine** — cross-references the username/domain/email you supply against each other's data to surface direct ownership links (e.g. "this domain's WHOIS registrant email is the exact email you're investigating"). Evidence-based only — every rule requires a literal match, no fuzzy heuristics, and it skips itself entirely when fewer than two identifiers are supplied rather than reporting a foregone "no correlations found"
- **Exposure risk score** — a 0–100 score with a Low/Medium/High/Critical severity label, computed from a data-driven rule set (breach found, missing security headers, large subdomain count, large public username footprint, GPS coordinates embedded in a photo), each finding paired with a plain-language recommendation
- **Self-contained HTML report** — dark/light aware, an executive summary you can scan in 30 seconds, a highlighted GPS warning box, long values (a full CSP header, a joined TXT record list) collapsed behind an expandable disclosure instead of dumping hundreds of characters into the page
- **Google dork generation** — outputs relevant manual-search queries for further investigation
- **JSON export** — save full results to a file for later reference or reporting

## How username detection actually works

A plain HTTP status code (`200` = found, `404` = not found) is not trustworthy on its own — several platforms return `200` for accounts that don't exist, or block scripted requests entirely regardless of whether the account is real. Rather than take status codes at face value everywhere, each platform is checked and classified individually:

- **Reliable, status-code-only** (GitHub, HackerNews, Keybase, Dev.to, Docker Hub) — server-rendered pages, a real 404 comes back for missing accounts, status code alone is trustworthy.
- **Reliable, content-verified** (Steam, Medium) — the platform can return a `200` even for accounts that don't exist, so the response body is checked for a specific "not found" indicator (Steam) or the presence/absence of expected profile metadata (Medium's `og:title` tag) before trusting the result.
- **Unreliable / can't be confirmed via plain HTTP** (Twitter/X, Instagram, TikTok, Pinterest, YouTube, Twitch, Reddit, GitLab) — either a JavaScript single-page app that serves the same generic shell for any URL, real or fake (confirmed empirically: a deliberately fake Instagram username still returned 200), or a platform sitting behind bot-detection that blocks or challenges plain scripted requests regardless of username (Reddit currently serves the same "please wait for verification" interstitial for both real and fake usernames; GitLab's Cloudflare protection frequently 403s plain requests even for known-real accounts). These are always reported as `unclear`, never a false `found`.

This isn't a static list — Reddit, for example, used to be checkable via a documented "not found" message (per the [Sherlock project](https://github.com/sherlock-project/sherlock)'s detection database), but empirical testing found that check no longer works against Reddit's current frontend, so it was moved to the unreliable tier rather than left silently wrong. Every result includes a `reason` field explaining exactly why it landed in `unclear`, so nothing is a black box.

Results are split into four buckets — `found` / `unclear` / `not_found` / `error` — rather than a binary found/not-found, so the report never has to pretend certainty it doesn't have.

## Identifier correlation engine

Given more than one identifier, the engine cross-references them for direct, literal evidence of ownership:

- The investigated email's domain matches the domain being scanned
- The username appears as an exact subdomain label (`username.domain.com`)
- The domain's WHOIS registrant email matches the investigated email
- The domain's WHOIS registrant name/organization contains the username (rated lower confidence — free text, not an exact match)

Deliberately narrow on purpose: weaker heuristics (e.g. "a photo's timestamp is close to the domain's registration date") are left out, so every finding is backed by real evidence rather than a guess. It also correctly reports nothing when a domain uses WHOIS privacy protection (GoDaddy's "Domains By Proxy," for example) — no registrant data means no correlation, not a fabricated one.

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
python3 osint_footprint.py --image photo.heic

# combine targets, save JSON and an HTML report
python3 osint_footprint.py \
  --username johndoe --domain example.com --email john@example.com --image photo.jpg \
  --out results.json --html report.html

# HIBP breach checking needs a paid API key - pass it directly or via env var
python3 osint_footprint.py --email john@example.com --hibp-key YOUR_KEY
export HIBP_API_KEY=YOUR_KEY && python3 osint_footprint.py --email john@example.com
```

Any of `--username` / `--domain` / `--email` / `--image` can be omitted — every section of the report (and the risk score, and the correlation engine) adapts to whichever combination was actually supplied.

## Example output

```
[*] Checking username 'johndoe' across 15 platforms...
    [+] GitHub       FOUND     https://github.com/johndoe
    [-] Reddit       not found
    [?] Twitter/X    status=200 but this platform can't be reliably checked - not confirmed, verify manually
    [-] Steam        not found (200 status, but page content confirms no such user)

[*] Domain recon for 'example.com'...
    [+] Registrar: Reserved Domain
    [-] Security headers missing: ['Content-Security-Policy']
    [+] SPF record found
    [-] DMARC record not found
    [+] Found 12 unique subdomains

[*] Identifier correlations found:
    [High  ] The investigated email 'john@example.com' is hosted on 'example.com' - the domain being scanned is the same one backing this email address.

[*] Exposure risk score: 18/100 (Low)
    +10  Domain does not enforce HTTPS (missing Strict-Transport-Security)
         -> Enable Strict-Transport-Security to force HTTPS on all connections.
    +8   Domain has no Content-Security-Policy header (weaker XSS protection)
         -> Add a Content-Security-Policy header to restrict what scripts/resources can load.

[*] Suggested manual Google dorks:
    "johndoe" site:pastebin.com
    site:example.com filetype:pdf

[+] Results saved to results.json
[+] HTML report saved to report.html
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

161 tests: pure logic (risk scoring, correlation engine, WHOIS/EXIF parsing), every networked check via mocked `requests`/`dns.resolver`/`whois` (nothing hits the network during a test run), the HTML report renderer, and a full end-to-end integration test that runs the real `main()` — real argparse, real file writing — with every module wired together as a live invocation would be.

## Architecture

```
osint_footprint.py   CLI entry point (argparse, orchestration)
utils.py             HTTP retry/backoff, shared constants, dork generation
username.py          Platform list + username enumeration
domain.py            DNS, WHOIS, security headers, SPF/DMARC, fingerprinting, subdomains
email_check.py       Format validation, MX, HIBP breach check
exif.py               EXIF/GPS extraction (incl. HEIC/HEIF)
correlation.py        Identifier correlation engine
risk.py               Exposure risk scoring
report.py             HTML report generation
tests/                One test file per module above, plus a full integration test
```

Each recon module reads/writes into one shared `report` dict; `risk.py` and `report.py` only ever read what the other modules already collected, so neither one fires a new network request. `correlation.py` and `risk.py` are pure functions with no I/O at all.

## Known limitations

- **HIBP breach checking requires a paid API key** — manual check recommended at [haveibeenpwned.com](https://haveibeenpwned.com/) if one isn't available.
- **DKIM is not checked** — it lives under a selector-specific hostname (`selector._domainkey.domain.com`) with no way to know a domain's selector without prior knowledge, so any check would just be guessing at common selector names rather than reporting a real result. SPF and DMARC are checked.
- **GitLab is frequently unreachable via plain scripted requests** — sits behind aggressive Cloudflare bot protection that 403s even known-real accounts under normal conditions; expect it to show up as `unclear` more often than other platforms.
- **Subdomain enumeration is passive-only** (Certificate Transparency logs) — it will miss subdomains that never had a public HTTPS certificate issued.
- **Domain recon requests are still sequential** — only username enumeration was moved to a thread pool so far.

## Roadmap

- [ ] Concurrent domain recon requests (`ThreadPoolExecutor`)
- [ ] Favicon hashing for Shodan-style fingerprinting
- [ ] Config file for tunable constants (timeouts, retry limits, risk weights)
- [ ] `--verbose`/`--quiet` logging levels in place of flat `print()`

## Tech stack

Python 3, `requests`, `python-whois`, `dnspython`, `Pillow` + `pillow-heif`, `pytest` (dev)

## Disclaimer

Built for educational and authorized reconnaissance purposes only (CTF practice, personal footprint auditing, portfolio development). Don't use this against targets you don't have permission to investigate.
