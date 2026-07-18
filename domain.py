"""Domain reconnaissance: DNS, WHOIS, security headers, subdomain enumeration."""

import concurrent.futures

import requests

import utils

# name -> (header to inspect, substring to match in its value, or None if the
# header's mere presence is the signal). Data-driven for the same reason
# PLATFORMS is: adding a fingerprint means adding one entry, not a new
# if-branch. Deliberately reuses whatever headers the security-headers
# request already fetched rather than making another request.
_TECH_SIGNALS = [
    ("Cloudflare", "Server", "cloudflare"),
    ("Cloudflare", "CF-RAY", None),
    ("Nginx", "Server", "nginx"),
    ("Apache", "Server", "apache"),
    ("Microsoft IIS", "Server", "microsoft-iis"),
    ("GitHub Pages", "Server", "github.com"),
    ("Varnish", "Via", "varnish"),
    ("Vercel", "Server", "vercel"),
    ("AWS CloudFront", "Via", "cloudfront"),
    ("Fastly", "Server", "fastly"),
    ("Google Frontend", "Server", "gws"),
]


def _fingerprint_technologies(headers):
    detected = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for tech, header_name, value_substr in _TECH_SIGNALS:
        value = headers_lower.get(header_name.lower())
        if value is None:
            continue
        if value_substr is None or value_substr.lower() in value.lower():
            detected.add(tech)
    return sorted(detected)


def check_subdomains(domain, _print=print):
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

    Also surfaces the most recently issued certificate's issuer and
    validity window - crt.sh's response already includes this per entry,
    so it's free once we're already parsing the response for subdomains.

    _print defaults to the builtin print but check_domain passes a
    line-collecting substitute instead, since this now runs concurrently
    with the domain's other checks - printing directly here would
    interleave with their output the same way check_username() had to
    guard against for concurrent platform checks.
    """
    _print(f"\n[*] Searching Certificate Transparency logs for '{domain}' subdomains...")
    # status starts as None: we may fail before ever getting an HTTP response
    # at all (e.g. connection error), in which case there's no status code to
    # report - that's meaningfully different from "we got a bad status code".
    result = {
        "success": False, "status": None, "source": "crt.sh", "reason": None,
        "subdomains": [], "latest_certificate": None,
    }
    try:
        # crt.sh can be slow under load, give it more room than our normal TIMEOUT
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, headers=utils.HEADERS, timeout=15)
        result["status"] = r.status_code  # got a response, so we always have a status now

        # inspect the status ourselves instead of raise_for_status(), so we
        # can give a specific reason per case rather than one generic
        # "HTTPError" for every non-2xx response.
        if r.status_code == 429:
            result["reason"] = "HTTP 429 Too Many Requests - crt.sh rate limited us, try again later"
            _print(f"    [!] {result['reason']}")
            return result
        elif r.status_code == 503:
            result["reason"] = "HTTP 503 Service Unavailable - crt.sh is temporarily down"
            _print(f"    [!] {result['reason']}")
            return result
        elif r.status_code != 200:
            result["reason"] = f"HTTP {r.status_code} - unexpected response from crt.sh"
            _print(f"    [!] {result['reason']}")
            return result

        entries = r.json()
        subdomains = set()
        latest_cert = None
        for entry in entries:
            # crt.sh dates are ISO 8601 ("2024-05-01T00:00:00") - they sort
            # correctly as plain strings, no need to parse into datetimes
            # just to find the most recent one.
            not_before = entry.get("not_before")
            if not_before and (latest_cert is None or not_before > latest_cert["not_before"]):
                latest_cert = {
                    "issuer": entry.get("issuer_name"),
                    "not_before": not_before,
                    "not_after": entry.get("not_after"),
                }

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
        result["latest_certificate"] = latest_cert
        _print(f"    [+] Found {len(subdomains_list)} unique subdomains")
        if latest_cert:
            _print(f"    [+] Latest certificate issued by {latest_cert['issuer']}, valid {latest_cert['not_before']} to {latest_cert['not_after']}")
        for s in subdomains_list[:20]:  # don't flood the console on huge results
            _print(f"        {s}")
        if len(subdomains_list) > 20:
            _print(f"        ... and {len(subdomains_list) - 20} more (see JSON output)")
        return result

    except requests.exceptions.RequestException as e:
        result["reason"] = f"Request failed: {e.__class__.__name__}"
        _print(f"    [!] crt.sh request failed: {result['reason']}")
        return result
    except ValueError as e:
        # crt.sh returns HTML instead of JSON when it's overloaded/rate limiting
        result["reason"] = f"crt.sh returned a non-JSON response (likely overloaded): {e}"
        _print(f"    [!] {result['reason']}")
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


def check_dns_records(domain, _print=print):
    """
    Looks up A, AAAA, MX, NS, TXT, and CNAME records for the domain via
    dnspython. Each record type is queried independently - a domain
    legitimately might not have some of these (e.g. no CNAME on an apex
    domain, no AAAA if IPv6 isn't configured), so a missing record type
    is normal, not an error. Only NXDOMAIN (the domain doesn't exist at
    all) or a missing dnspython install stop the whole lookup early.

    _print defaults to the builtin print but check_domain passes a
    line-collecting substitute instead, since this now runs concurrently
    with the domain's other checks (see check_subdomains for why).
    """
    _print(f"\n[*] Looking up DNS records for '{domain}'...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {rtype: [] for rtype in record_types}

    try:
        import dns.resolver
    except ImportError:
        _print("    [!] dnspython not installed, skipping DNS record lookup. Run: pip install dnspython")
        return {"skipped": True, "reason": "dnspython not installed", **results}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            values = sorted(str(r) for r in answers)
            results[rtype] = values
            _print(f"    [+] {rtype:6s} ({len(values)}): {', '.join(values)}")
        except dns.resolver.NXDOMAIN:
            # domain doesn't exist at all - every other record type will
            # fail the same way, no point querying the rest
            _print("    [-] Domain does not exist (NXDOMAIN)")
            results["nxdomain"] = True
            break
        except dns.resolver.NoAnswer:
            # this record type genuinely doesn't exist for this domain -
            # normal, not an error (e.g. most domains have no CNAME on the apex)
            _print(f"    [ ] {rtype:6s}: none")
        except dns.resolver.NoNameservers:
            _print(f"    [!] {rtype:6s}: no nameservers responded")
        except Exception as e:
            _print(f"    [!] {rtype:6s}: lookup failed ({e.__class__.__name__})")

    return results


def _check_email_security(domain, txt_records, _print=print):
    """
    SPF lives in the domain's own TXT records (already fetched by
    check_dns_records) - just look for the v=spf1 marker. DMARC lives at
    a separate _dmarc.<domain> TXT record, so it needs one extra lookup.

    DKIM is deliberately not checked here - it lives under a
    selector-specific hostname (selector._domainkey.<domain>), and
    there's no way to know a domain's selector without prior knowledge,
    so any check here would just be guessing at common selector names
    rather than reporting a real result.

    _print defaults to the builtin print but check_domain passes a
    line-collecting substitute instead, since this now runs concurrently
    with the domain's other checks (see check_subdomains for why).
    """
    spf_record = next(
        (t.strip('"') for t in txt_records if t.strip('"').lower().startswith("v=spf1")),
        None,
    )
    result = {"spf": spf_record is not None, "spf_record": spf_record, "dmarc": False, "dmarc_record": None}

    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rec in answers:
            txt = str(rec).strip('"')
            if txt.lower().startswith("v=dmarc1"):
                result["dmarc"] = True
                result["dmarc_record"] = txt
                break
    except ImportError:
        pass  # dnspython missing is already reported by check_dns_records
    except Exception:
        pass  # no DMARC record, or the lookup failed - either way, "not found"

    _print(f"    [{'+' if result['spf'] else '-'}] SPF record {'found' if result['spf'] else 'not found'}")
    _print(f"    [{'+' if result['dmarc'] else '-'}] DMARC record {'found' if result['dmarc'] else 'not found'}")
    return result


def check_well_known(domain):
    """
    robots.txt and security.txt are both plain-text files a site is
    expected to publish at a fixed, well-known path - reading them isn't
    scanning anything, just requesting pages the site itself intended to
    be public. robots.txt's Disallow entries are useful OSINT precisely
    because a site is listing the paths it doesn't want crawled/indexed
    (often /admin, /internal, /staging).
    """
    result = {"robots_disallow": [], "security_txt": None}

    try:
        r = utils.get_with_retry(f"https://{domain}/robots.txt")
        if r.status_code == 200:
            disallow = [
                line.split(":", 1)[1].strip()
                for line in r.text.splitlines()
                if line.strip().lower().startswith("disallow:")
            ]
            result["robots_disallow"] = [d for d in disallow if d]
    except requests.exceptions.RequestException:
        pass

    try:
        r = utils.get_with_retry(f"https://{domain}/.well-known/security.txt")
        if r.status_code == 200 and r.text.strip():
            result["security_txt"] = r.text.strip()
    except requests.exceptions.RequestException:
        pass

    return result


def _check_whois(domain, _print=print):
    """
    WHOIS lookup, extracted out of check_domain so it can run in its own
    thread. _print defaults to the builtin print but check_domain passes a
    line-collecting substitute instead (see check_subdomains for why).
    """
    result = {}
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

        _print(f"    [+] Registrar: {result['registrar']}")
        _print(f"    [+] Created:   {result['creation_date']}")
        _print(f"    [+] Expires:   {result['expiration_date']}")
        if result["registrant_name"]:
            _print(f"    [+] Registrant name: {result['registrant_name']}")
        if result["registrant_org"]:
            _print(f"    [+] Registrant org:  {result['registrant_org']}")
        if registrant_emails:
            _print(f"    [+] Registrant email(s): {', '.join(registrant_emails)}")
    except ImportError:
        _print("    [!] python-whois not installed, skipping WHOIS. Run: pip install python-whois")
        result["whois"] = "SKIPPED - install python-whois"
    except Exception as e:
        _print(f"    [!] WHOIS lookup failed: {e}")
        result["whois_error"] = str(e)
    return result


def _check_security_headers(domain, _print=print):
    """
    Security headers, redirect chain, and technology fingerprinting - all
    read off the same single request to the site's root, extracted out of
    check_domain so it can run in its own thread. _print defaults to the
    builtin print but check_domain passes a line-collecting substitute
    instead (see check_subdomains for why).
    """
    result = {}
    try:
        r = utils.get_with_retry(f"https://{domain}")
        sec_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                       "X-Frame-Options", "X-Content-Type-Options"]
        present = {h: r.headers.get(h) for h in sec_headers if h in r.headers}
        missing = [h for h in sec_headers if h not in r.headers]
        result["security_headers_present"] = present
        result["security_headers_missing"] = missing
        _print(f"    [+] Security headers present: {list(present.keys())}")
        if missing:
            _print(f"    [-] Security headers missing: {missing}")

        # r.history holds every hop before the final response - only
        # present when a redirect actually happened (e.g. http -> https -> www)
        if r.history:
            result["redirect_chain"] = [h.url for h in r.history] + [r.url]
            _print(f"    [+] Redirect chain: {' -> '.join(result['redirect_chain'])}")

        technologies = _fingerprint_technologies(r.headers)
        if technologies:
            result["technologies"] = technologies
            _print(f"    [+] Technologies detected: {', '.join(technologies)}")
    except requests.exceptions.RequestException as e:
        _print(f"    [!] Could not fetch site headers: {e}")
    return result


def _line_collector():
    """
    Returns a print-alike callable plus the list it appends to, instead of
    writing straight to stdout. check_domain runs several checks
    concurrently and flushes each one's lines together, in a fixed order,
    once that check's future resolves - otherwise interleaved output from
    several threads printing at once would come out garbled, the same
    problem check_username() solves for its 17 concurrent platform checks.
    """
    lines = []

    def _print(*args, **kwargs):
        lines.append(kwargs.get("sep", " ").join(str(a) for a in args))

    return _print, lines


def check_domain(domain):
    print(f"\n[*] Domain recon for '{domain}'...")
    result = {}

    dns_print, dns_lines = _line_collector()
    whois_print, whois_lines = _line_collector()
    headers_print, headers_lines = _line_collector()
    subdomains_print, subdomains_lines = _line_collector()
    email_print, email_lines = _line_collector()

    # DNS, WHOIS, security headers, well-known files, and subdomains are
    # all independent of each other - only email security depends on the
    # DNS TXT records, so it's submitted once those are back rather than
    # upfront with the rest.
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        dns_future = executor.submit(check_dns_records, domain, dns_print)
        whois_future = executor.submit(_check_whois, domain, whois_print)
        headers_future = executor.submit(_check_security_headers, domain, headers_print)
        wellknown_future = executor.submit(check_well_known, domain)
        subdomains_future = executor.submit(check_subdomains, domain, subdomains_print)

        dns_records = dns_future.result()
        for line in dns_lines:
            print(line)
        result["dns_records"] = dns_records
        # keep "ip" for backward compatibility with anything reading the old
        # single-A-record shape - just the first A record, if any
        result["ip"] = dns_records.get("A", [None])[0] if dns_records.get("A") else None

        email_future = executor.submit(_check_email_security, domain, dns_records.get("TXT", []), email_print)

        whois_result = whois_future.result()
        for line in whois_lines:
            print(line)
        result.update(whois_result)

        headers_result = headers_future.result()
        for line in headers_lines:
            print(line)
        result.update(headers_result)

        email_security = email_future.result()
        for line in email_lines:
            print(line)
        result["email_security"] = email_security

        well_known = wellknown_future.result()
        result["robots_disallow"] = well_known["robots_disallow"]
        result["security_txt"] = well_known["security_txt"]
        if result["robots_disallow"]:
            print(f"    [+] robots.txt Disallow entries: {len(result['robots_disallow'])}")
        if result["security_txt"]:
            print("    [+] security.txt found")

        subdomains_result = subdomains_future.result()
        for line in subdomains_lines:
            print(line)
        result["subdomains"] = subdomains_result

    return result
