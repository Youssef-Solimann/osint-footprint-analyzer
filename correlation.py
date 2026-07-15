"""
Identifier correlation engine.

Cross-references the identifiers the user supplied (username/domain/email)
against data the other checks already collected, to surface direct
ownership/identity links a human analyst would otherwise have to spot by
hand (e.g. "this domain's WHOIS email is the same email you're
investigating"). Deliberately narrow for v1: every rule here requires a
direct, literal match between two independently-supplied identifiers.
Weaker heuristics (e.g. "photo timestamp is close to the domain's
registration date") are left out on purpose, so every finding is backed by
real evidence rather than a guess. Makes no network requests of its own -
purely reads what check_username()/check_domain()/check_email() already
collected in `report`.
"""


def correlate_findings(report):
    findings = []
    target = report.get("target", {})
    username = target.get("username")
    domain = target.get("domain")
    email_results = report.get("email_results") or {}
    domain_results = report.get("domain_results") or {}

    email = email_results.get("email")

    # --- email's domain matches the domain being scanned ---
    if email and email_results.get("format_valid") and domain and "@" in email:
        email_domain = email.split("@", 1)[1].lower()
        scanned_domain = domain.lower()
        if email_domain == scanned_domain or email_domain.endswith("." + scanned_domain):
            findings.append({
                "type": "email_domain_matches_scanned_domain",
                "confidence": "High",
                "description": (
                    f"The investigated email '{email}' is hosted on '{domain}' - "
                    f"the domain being scanned is the same one backing this email address."
                ),
            })

    # --- username appears as an exact subdomain label ---
    if username and domain:
        subdomain_info = domain_results.get("subdomains", {})
        if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
            username_lower = username.lower()
            domain_lower = domain.lower()
            matched_subs = []
            for sub in subdomain_info.get("subdomains", []):
                # check_subdomains() already lowercases everything it stores,
                # but this function reads `report` as its only contract -
                # lowercase defensively here too rather than relying on that
                # implicit upstream guarantee holding forever.
                sub_lower = sub.lower()
                if sub_lower == domain_lower:
                    continue  # the apex domain itself, not a subdomain label
                label = sub_lower[:-(len(domain_lower) + 1)] if sub_lower.endswith("." + domain_lower) else sub_lower
                leftmost_label = label.split(".")[0]
                if leftmost_label == username_lower:
                    matched_subs.append(sub)
            if matched_subs:
                findings.append({
                    "type": "username_in_subdomains",
                    "confidence": "High",
                    "description": (
                        f"Subdomain(s) {', '.join(matched_subs)} match the username "
                        f"'{username}' exactly - likely a personal or user-specific subdomain."
                    ),
                })

    # --- WHOIS registrant email matches the investigated email directly ---
    registrant_emails = domain_results.get("registrant_emails") or []
    if email and any(email.lower() == e.lower() for e in registrant_emails):
        findings.append({
            "type": "whois_registrant_email_matches_target_email",
            "confidence": "High",
            "description": (
                f"WHOIS registrant contact for '{domain}' lists the email '{email}' "
                f"directly - this domain is very likely registered by the same person "
                f"under investigation."
            ),
        })

    # --- WHOIS registrant name/org contains the username ---
    # Weaker than the exact-match rules above (registrant name/org are free
    # text, so a substring hit isn't as ironclad as an exact email or
    # subdomain match) - rated Medium rather than High for that reason.
    if username:
        username_lower = username.lower()
        for label, value in (
            ("name", domain_results.get("registrant_name")),
            ("organization", domain_results.get("registrant_org")),
        ):
            if value and username_lower in value.lower():
                findings.append({
                    "type": "whois_registrant_matches_username",
                    "confidence": "Medium",
                    "description": (
                        f"WHOIS registrant {label} for '{domain}' ('{value}') contains "
                        f"the username '{username}' - possible link, but registrant "
                        f"fields are free text so this is weaker evidence than an exact "
                        f"email or subdomain match."
                    ),
                })

    return findings
