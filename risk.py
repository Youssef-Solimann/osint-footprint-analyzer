"""
Exposure risk scoring.

Data-driven on purpose: tuning the score later means editing RISK_RULES,
not hunting through if/elif branches. Each rule has a point value, a
human-readable description, and a recommendation - so the final report
explains both *why* it landed on a given number and *what to do about it*,
which is most of what the HTML report needs to write itself.
"""

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
