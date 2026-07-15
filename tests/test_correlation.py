from correlation import correlate_findings


def test_email_domain_matches_scanned_domain():
    report = {
        "target": {"username": None, "domain": "example.com", "email": None},
        "email_results": {"email": "john@example.com", "format_valid": True},
        "domain_results": {},
    }
    findings = correlate_findings(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "email_domain_matches_scanned_domain"
    assert findings[0]["confidence"] == "High"


def test_email_on_different_domain_does_not_correlate():
    report = {
        "target": {"domain": "example.com"},
        "email_results": {"email": "john@other.com", "format_valid": True},
        "domain_results": {},
    }
    assert correlate_findings(report) == []


def test_invalid_email_format_does_not_correlate():
    report = {
        "target": {"domain": "example.com"},
        "email_results": {"email": "not-an-email", "format_valid": False},
        "domain_results": {},
    }
    assert correlate_findings(report) == []


def test_username_matches_exact_subdomain_label():
    report = {
        "target": {"username": "johndoe", "domain": "example.com"},
        "domain_results": {"subdomains": {"success": True, "subdomains": ["johndoe.example.com", "blog.example.com"]}},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "username_in_subdomains" for f in findings)


def test_username_substring_in_subdomain_is_not_an_exact_match():
    report = {
        "target": {"username": "john", "domain": "example.com"},
        "domain_results": {"subdomains": {"success": True, "subdomains": ["johndoe.example.com"]}},
    }
    assert correlate_findings(report) == []


def test_failed_subdomain_lookup_is_not_treated_as_a_match():
    report = {
        "target": {"username": "johndoe", "domain": "example.com"},
        "domain_results": {"subdomains": {"success": False, "subdomains": []}},
    }
    assert correlate_findings(report) == []


def test_whois_registrant_email_exact_match():
    report = {
        "target": {"domain": "example.com"},
        "email_results": {"email": "jane@gmail.com", "format_valid": True},
        "domain_results": {"registrant_emails": ["jane@gmail.com"]},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "whois_registrant_email_matches_target_email" for f in findings)


def test_whois_registrant_name_substring_is_medium_confidence():
    report = {
        "target": {"username": "jsmith", "domain": "example.com"},
        "domain_results": {"registrant_name": "John jsmith Smith"},
    }
    findings = correlate_findings(report)
    assert findings[0]["type"] == "whois_registrant_matches_username"
    assert findings[0]["confidence"] == "Medium"


def test_no_identifiers_produces_no_findings():
    assert correlate_findings({"target": {}}) == []


def test_email_domain_match_is_case_insensitive():
    report = {
        "target": {"domain": "Example.com"},
        "email_results": {"email": "John@EXAMPLE.com", "format_valid": True},
        "domain_results": {},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "email_domain_matches_scanned_domain" for f in findings)


def test_whois_registrant_email_match_is_case_insensitive():
    report = {
        "target": {"domain": "example.com"},
        "email_results": {"email": "Jane@Gmail.com", "format_valid": True},
        "domain_results": {"registrant_emails": ["jane@gmail.com"]},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "whois_registrant_email_matches_target_email" for f in findings)


def test_username_subdomain_match_is_case_insensitive_on_username():
    # check_subdomains() always lowercases before storing, so this is the
    # realistic shape correlate_findings receives - matching should succeed
    # even though the target username was typed with different casing.
    report = {
        "target": {"username": "JohnDoe", "domain": "example.com"},
        "domain_results": {"subdomains": {"success": True, "subdomains": ["johndoe.example.com"]}},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "username_in_subdomains" for f in findings)


def test_username_subdomain_match_is_case_insensitive_even_if_subdomain_string_is_not_lowercased():
    # correlate_findings() is documented as reading `report` as its only
    # contract - it must not silently depend on check_subdomains() having
    # already lowercased the data for it.
    report = {
        "target": {"username": "JohnDoe", "domain": "Example.com"},
        "domain_results": {"subdomains": {"success": True, "subdomains": ["JohnDoe.Example.com"]}},
    }
    findings = correlate_findings(report)
    assert any(f["type"] == "username_in_subdomains" for f in findings)
    # the original casing is preserved in the finding's evidence text
    assert "JohnDoe.Example.com" in findings[0]["description"]


def test_multiple_rules_can_fire_together():
    report = {
        "target": {"username": "janedoe", "domain": "janedoe.dev", "email": "jane@janedoe.dev"},
        "email_results": {"email": "jane@janedoe.dev", "format_valid": True},
        "domain_results": {
            "registrant_emails": ["jane@janedoe.dev"],
            "subdomains": {"success": True, "subdomains": ["janedoe.janedoe.dev"]},
        },
    }
    types = {f["type"] for f in correlate_findings(report)}
    assert types == {
        "email_domain_matches_scanned_domain",
        "username_in_subdomains",
        "whois_registrant_email_matches_target_email",
    }
