# OSINT Footprint Analyzer

*Evidence-driven OSINT reconnaissance with exposure risk scoring and self-contained HTML reporting.*

A CLI tool for gathering publicly available information about a username, domain, email address, or photo — and turning it into an assessment, not just a data dump.

> **Status: v1.1.0.** Username enumeration, domain recon, email/breach checks, EXIF/GPS extraction, an identifier correlation engine, exposure risk scoring, and a self-contained HTML report are all in place, backed by a 163-test suite. See Roadmap below for what's deliberately left for later.

## What it does

- **Username enumeration** — checks account existence across 17 platforms concurrently (GitHub, X, Instagram, Reddit, TikTok, GitLab, LinkedIn, Medium, Pinterest, Steam, Hacker News, Keybase, Dev.to, YouTube, Twitch, Docker Hub, Telegram), using a two-tier trust model (see below)
- **Domain recon** — DNS, WHOIS (registrar, dates, registrant, name servers), security headers, SPF/DMARC, technology fingerprinting (Cloudflare, Nginx, GitHub Pages, etc.), certificate issuer/validity, `robots.txt`/`security.txt`, redirect chains, and passive subdomain enumeration via Certificate Transparency logs (crt.sh)
- **Email checks** — format validation, MX lookup, and a live HaveIBeenPwned breach check (paid API key; degrades gracefully without one)
- **EXIF/GPS extraction** — camera make/model, timestamps, software, and GPS coordinates from a photo, including HEIC/HEIF (iPhone's default format)
- **Identifier correlation engine** — cross-references the username/domain/email you supply for direct ownership links (e.g. a domain's WHOIS registrant email matching the investigated email). Evidence-based only — every rule requires a literal match, and it skips itself entirely when fewer than two identifiers are supplied rather than reporting a foregone "no correlations found"
- **Exposure risk score** — a 0–100 score (Low/Medium/High/Critical) from a data-driven rule set — breach found, missing security headers, large subdomain/username footprint, GPS in a photo — each finding paired with a plain-language recommendation
- **Self-contained HTML report** — dark/light aware, a 30-second executive summary, a highlighted GPS warning box, and long values (a full CSP header, a joined TXT record list) collapsed behind an expandable disclosure instead of dumped raw
- **Google dork generation** — outputs relevant manual-search queries for further investigation
- **JSON export** — save full results to a file for later reference or reporting

## How username detection actually works

A plain HTTP status code (`200` = found, `404` = not found) is not trustworthy on its own — several platforms return `200` for accounts that don't exist, or block scripted requests entirely regardless of whether the account is real. Rather than take status codes at face value everywhere, each platform is checked and classified individually:

- **Reliable, status-code-only** (GitHub, HackerNews, Keybase, Dev.to, Docker Hub) — server-rendered pages, a real 404 comes back for missing accounts, status code alone is trustworthy.
- **Reliable, content-verified** (Steam, Medium, Telegram) — the platform can return a `200` even for accounts that don't exist, so the response body is checked for a specific "not found" indicator (Steam's not-found text, Telegram's `noindex` robots meta tag) or the presence/absence of expected profile metadata (Medium's `og:title` tag) before trusting the result.
- **Unreliable / can't be confirmed via plain HTTP** (Twitter/X, Instagram, TikTok, Pinterest, YouTube, Twitch, Reddit, GitLab, LinkedIn) — either a JavaScript single-page app that serves the same generic shell for any URL, real or fake (confirmed empirically: a deliberately fake Instagram username still returned 200), or a platform sitting behind bot-detection that blocks or challenges plain scripted requests regardless of username (Reddit currently serves the same "please wait for verification" interstitial for both real and fake usernames; GitLab's Cloudflare protection frequently 403s plain requests even for known-real accounts; LinkedIn's custom anti-bot status code flipped a known-real profile to a false "not found" 4 out of 5 times in a tight burst test, despite looking like a clean signal in an initial spaced-out check). These are always reported as `unclear`, never a false `found`.

This isn't a static list — Reddit, for example, used to be checkable via a documented "not found" message (per the [Sherlock project](https://github.com/sherlock-project/sherlock)'s detection database), but empirical testing found that check no longer works against Reddit's current frontend, so it was moved to the unreliable tier rather than left silently wrong. Any `unclear` or `error` result — and any `not_found` result reached via content matching rather than a plain 404 — carries a machine-readable `reason` field explaining exactly why, so nothing is a black box.

Results are split into four buckets — `found` / `unclear` / `not_found` / `error` — rather than a binary found/not-found, so the report never has to pretend certainty it doesn't have.

## Identifier correlation engine

Given more than one identifier, the engine cross-references them for direct, literal evidence of ownership:

- The investigated email's domain matches the domain being scanned
- The username appears as an exact subdomain label (`username.domain.com`)
- The domain's WHOIS registrant email matches the investigated email
- The domain's WHOIS registrant name/organization contains the username (rated lower confidence — free text, not an exact match)

Deliberately narrow on purpose: weaker heuristics (e.g. "a photo's timestamp is close to the domain's registration date") are left out, so every finding is backed by real evidence rather than a guess. It also correctly reports nothing when a domain uses WHOIS privacy protection (GoDaddy's "Domains By Proxy," for example) — no registrant data means no correlation, not a fabricated one.

## Installation

Requires Python 3.11+.

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
[*] Checking username 'johndoe' across 17 platforms...
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

## Performance

- Username checks across all 17 platforms run concurrently via a `ThreadPoolExecutor` (`username.py`) — a full scan takes roughly one request's round trip instead of stacking 17 sequential ones.
- Every HTTP request retries on `429 Too Many Requests` with exponential backoff (or the server's own `Retry-After` header when present), capped at a maximum wait (`utils.py`).
- Domain recon is still sequential — see Roadmap.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

A comprehensive 163-test suite covering unit, integration, and report-generation behavior: pure logic (risk scoring, correlation engine, WHOIS/EXIF parsing), every networked check via mocked `requests`/`dns.resolver`/`whois` (nothing hits the network during a test run), the HTML report renderer, CLI output wiring in `osint_footprint.py`, and a full end-to-end integration test that runs the real `main()` — real argparse, real file writing — with every module wired together as a live invocation would be.

## Known limitations

- **HIBP breach checking requires a paid API key** — manual check recommended at [haveibeenpwned.com](https://haveibeenpwned.com/) if one isn't available.
- **DKIM is not checked** — it lives under a selector-specific hostname (`selector._domainkey.domain.com`) with no way to know a domain's selector without prior knowledge, so any check would just be guessing at common selector names rather than reporting a real result. SPF and DMARC are checked.
- **GitLab is frequently unreachable via plain scripted requests** — sits behind aggressive Cloudflare bot protection that 403s even known-real accounts under normal conditions; expect it to show up as `unclear` more often than other platforms.
- **Subdomain enumeration is passive-only** (Certificate Transparency logs) — it will miss subdomains that never had a public HTTPS certificate issued.
- **Domain recon requests are still sequential** — only username enumeration was moved to a thread pool so far.

## Roadmap

- [ ] Concurrent domain recon requests (`ThreadPoolExecutor`)
- [ ] `--verbose`/`--quiet` logging levels in place of flat `print()`
- [ ] Config file for tunable constants (timeouts, retry limits, risk weights)
- [ ] Favicon hashing for Shodan-style fingerprinting

## Tech stack

Python 3 (stdlib `concurrent.futures`, `argparse`), `requests`, `python-whois`, `dnspython`, `Pillow` + `pillow-heif`, `pytest` (dev)

## Disclaimer

Built for educational and authorized reconnaissance purposes only (CTF practice, personal footprint auditing, portfolio development). Don't use this against targets you don't have permission to investigate.