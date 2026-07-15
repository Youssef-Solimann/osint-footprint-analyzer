import re

from correlation import correlate_findings
from report import generate_html_report
from risk import calculate_risk

_BALANCED_TAGS = ["section", "div", "table", "ul", "details", "aside", "main", "svg"]


def _assert_tags_balance(html_text):
    for tag in _BALANCED_TAGS:
        opens = len(re.findall(rf"<{tag}\b", html_text))
        closes = len(re.findall(rf"</{tag}>", html_text))
        assert opens == closes, f"<{tag}> mismatch: {opens} opens vs {closes} closes"


def test_empty_report_still_renders():
    html_out = generate_html_report({})
    assert html_out.strip().startswith("<!doctype html>")
    _assert_tags_balance(html_out)


def test_sections_only_render_for_present_data():
    report = {"target": {}, "username_results": {"found": [], "unclear": [], "not_found": [], "error": []}}
    html_out = generate_html_report(report)
    assert 'id="username"' in html_out
    assert 'id="domain"' not in html_out
    assert 'id="email"' not in html_out


def test_external_values_are_escaped():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"registrant_name": "<script>alert(1)</script>"},
    }
    html_out = generate_html_report(report)
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out


def test_gauge_dasharray_reflects_score():
    report = {"risk_score": {"score": 30, "max_score": 100, "severity": "Medium", "triggered_rules": []}}
    html_out = generate_html_report(report)
    assert 'stroke-dasharray="30 70"' in html_out


def test_correlations_absent_skips_the_section_entirely():
    # correlations key missing means the engine never ran (e.g. only one
    # identifier was supplied) - that's different from running and finding
    # nothing, so no "Identifier Correlations" panel should render at all
    html_out = generate_html_report({"target": {"username": "alice"}})
    assert 'id="correlations"' not in html_out


def test_correlations_empty_list_renders_a_no_matches_panel():
    # correlations = [] means the engine DID run and found nothing - that's
    # worth telling the reader explicitly, so the panel should still appear
    html_out = generate_html_report({"target": {}, "correlations": []})
    assert 'id="correlations"' in html_out
    assert "No direct correlations found" in html_out


def test_no_risk_score_shows_not_scored():
    html_out = generate_html_report({"target": {}})
    assert "Not scored" in html_out


def test_full_report_renders_and_balances_tags():
    report = {
        "generated_at": "2026-01-01T00:00:00Z",
        "target": {"username": "janedoe", "domain": "janedoe.dev", "email": "jane@janedoe.dev"},
        "username_results": {
            "found": [{"platform": "GitHub", "url": "https://github.com/janedoe", "status": 200}],
            "unclear": [], "not_found": [], "error": [],
        },
        "domain_results": {
            "dns_records": {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []},
            "registrant_emails": ["jane@janedoe.dev"],
            "security_headers_present": {}, "security_headers_missing": ["Content-Security-Policy"],
            "subdomains": {"success": True, "subdomains": ["janedoe.janedoe.dev"]},
        },
        "email_results": {
            "email": "jane@janedoe.dev", "format_valid": True, "mx_records": [],
            "hibp": {"checked": True, "breaches": []},
        },
        "suggested_dorks": ['"janedoe" site:github.com'],
    }
    report["correlations"] = correlate_findings(report)
    report["risk_score"] = calculate_risk(report)

    html_out = generate_html_report(report)
    _assert_tags_balance(html_out)
    assert 'id="correlations"' in html_out
    assert "janedoe.janedoe.dev" in html_out
    assert str(report["risk_score"]["score"]) in html_out
