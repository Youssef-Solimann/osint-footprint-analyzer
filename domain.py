"""Domain reconnaissance: DNS, WHOIS, security headers, subdomain enumeration."""

import requests

import utils


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
        r = requests.get(url, headers=utils.HEADERS, timeout=15)
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
        r = utils.get_with_retry(f"https://{domain}")
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
