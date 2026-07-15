"""
Email checks: format validation, MX lookup, HaveIBeenPwned breach check.

Named email_check.py rather than email.py on purpose - a top-level module
literally named email.py would shadow Python's own stdlib `email` package,
which requests/urllib3 rely on internally for header parsing.
"""

import re

import requests

import utils


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
            r = utils.get_with_retry(
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
