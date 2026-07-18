import re

import utils
from correlation import correlate_findings
from report import _collapsible_value, generate_html_report
from risk import calculate_risk

_BALANCED_TAGS = ["section", "div", "table", "ul", "details", "aside", "main", "svg"]


def _assert_tags_balance(html_text):
    for tag in _BALANCED_TAGS:
        opens = len(re.findall(rf"<{tag}\b", html_text))
        closes = len(re.findall(rf"</{tag}>", html_text))
        assert opens == closes, f"<{tag}> mismatch: {opens} opens vs {closes} closes"


class TestCollapsibleValue:
    def test_short_value_stays_inline_no_details(self):
        html_out = _collapsible_value("max-age=31536000")
        assert "<details" not in html_out
        assert "max-age=31536000" in html_out

    def test_long_value_collapses_behind_details(self):
        long_value = "a" * 500
        html_out = _collapsible_value(long_value)
        assert '<details class="value-details">' in html_out
        assert "…" in html_out  # truncated preview marker
        assert long_value in html_out  # full value still present, just inside the details body

    def test_long_value_preview_is_truncated_not_full_length(self):
        long_value = "x" * 500
        html_out = _collapsible_value(long_value)
        summary = html_out.split("<summary")[1].split("</summary>")[0]
        assert len(summary) < 500

    def test_muted_false_omits_span_wrapper_for_short_values(self):
        html_out = _collapsible_value("short", muted=False)
        assert "<span" not in html_out


def test_long_dns_txt_record_collapses_in_report():
    long_txt = "v=spf1 " + " ".join(f"include:_spf{i}.example.com" for i in range(20)) + " ~all"
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"dns_records": {"TXT": [long_txt]}},
    }
    html_out = generate_html_report(report)
    assert '<details class="value-details">' in html_out
    assert long_txt in html_out


def test_short_dns_record_does_not_collapse():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"dns_records": {"A": ["192.0.2.10"]}},
    }
    html_out = generate_html_report(report)
    # "value-details" also appears in the CSS as a class selector regardless
    # of content, so check for the actual <details> tag, not the bare substring
    assert '<details class="value-details">' not in html_out


def test_long_security_header_value_collapses():
    long_csp = "default-src none; " + "; ".join(f"connect-src example{i}.com" for i in range(20))
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"security_headers_present": {"Content-Security-Policy": long_csp}},
    }
    html_out = generate_html_report(report)
    assert '<details class="value-details">' in html_out
    assert long_csp in html_out


def test_long_spf_record_collapses():
    long_spf = "v=spf1 " + " ".join(f"include:_spf{i}.example.com" for i in range(20)) + " ~all"
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"email_security": {"spf": True, "spf_record": long_spf, "dmarc": False, "dmarc_record": None}},
    }
    html_out = generate_html_report(report)
    assert '<details class="value-details">' in html_out
    assert long_spf in html_out


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


def test_domain_name_servers_appear_in_report():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"name_servers": ["ns1.registrar.net", "ns2.registrar.net"]},
    }
    html_out = generate_html_report(report)
    assert "ns1.registrar.net" in html_out
    assert "ns2.registrar.net" in html_out


def test_redirect_chain_renders_when_present():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"redirect_chain": ["http://example.com", "https://example.com", "https://www.example.com"]},
    }
    html_out = generate_html_report(report)
    assert "http://example.com" in html_out
    assert "https://www.example.com" in html_out


def test_no_redirect_chain_renders_nothing_extra():
    report = {"target": {"domain": "example.com"}, "domain_results": {}}
    html_out = generate_html_report(report)
    assert "&rarr;" not in html_out


def test_technologies_render_as_badges():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"technologies": ["Cloudflare", "Nginx"]},
    }
    html_out = generate_html_report(report)
    assert 'class="badge tech"' in html_out
    assert "Cloudflare" in html_out
    assert "Nginx" in html_out
    assert "Technologies Detected" in html_out


def test_no_technologies_hides_the_section_heading():
    report = {"target": {"domain": "example.com"}, "domain_results": {}}
    html_out = generate_html_report(report)
    assert "Technologies Detected" not in html_out


def test_email_security_shows_spf_and_dmarc_status():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"email_security": {
            "spf": True, "spf_record": "v=spf1 -all", "dmarc": False, "dmarc_record": None,
        }},
    }
    html_out = generate_html_report(report)
    assert "Email Security" in html_out
    assert "v=spf1 -all" in html_out
    # SPF passed, DMARC failed - both status chips should appear
    assert '<span class="chip ok">Configured</span>' in html_out
    assert '<span class="chip bad">Not found</span>' in html_out


def test_well_known_files_render_disallow_entries_and_security_txt():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {
            "robots_disallow": ["/admin", "/internal"],
            "security_txt": "Contact: mailto:security@example.com",
        },
    }
    html_out = generate_html_report(report)
    assert "Well-Known Files" in html_out
    assert "/admin" in html_out
    assert "security@example.com" in html_out
    assert 'class="raw-text"' in html_out


def test_latest_certificate_renders_when_subdomains_succeeded():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {
            "subdomains": {
                "success": True, "subdomains": ["www.example.com"],
                "latest_certificate": {"issuer": "Let's Encrypt", "not_before": "2026-01-01", "not_after": "2026-04-01"},
            },
        },
    }
    html_out = generate_html_report(report)
    assert "Let&#x27;s Encrypt" in html_out  # html.escape() encodes the apostrophe
    assert "2026-01-01" in html_out
    assert "2026-04-01" in html_out


def test_security_header_values_appear_not_just_presence():
    report = {
        "target": {"domain": "example.com"},
        "domain_results": {"security_headers_present": {"Strict-Transport-Security": "max-age=63072000"}},
    }
    html_out = generate_html_report(report)
    assert "Strict-Transport-Security" in html_out
    assert "max-age=63072000" in html_out


def test_exif_warnings_show_the_actual_reason_not_a_generic_message():
    report = {
        "target": {"image": "photo.jpg"},
        "exif_results": {
            "file": "photo.jpg", "has_exif": False, "format": None, "dimensions": None,
            "camera_make": None, "camera_model": None, "created": None, "software": None,
            "gps": None, "warnings": ["Could not open image: UnidentifiedImageError: cannot identify image file"],
        },
    }
    html_out = generate_html_report(report)
    assert "Could not open image: UnidentifiedImageError" in html_out


def test_exif_warnings_still_show_alongside_successfully_parsed_data():
    # a partial failure (e.g. GPS parsing blew up) shouldn't hide the fields
    # that DID parse successfully, and shouldn't hide the warning either
    report = {
        "target": {"image": "photo.jpg"},
        "exif_results": {
            "file": "photo.jpg", "has_exif": True, "format": "JPEG", "dimensions": "10x10",
            "camera_make": "TestMake", "camera_model": None, "created": None, "software": None,
            "gps": None, "warnings": ["GPS parsing failed: ValueError"],
        },
    }
    html_out = generate_html_report(report)
    assert "TestMake" in html_out
    assert "GPS parsing failed: ValueError" in html_out


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


# --- executive summary ------------------------------------------------

def test_executive_summary_absent_when_nothing_was_checked():
    html_out = generate_html_report({"target": {}})
    assert 'id="summary"' not in html_out


def test_executive_summary_summarizes_each_checked_category():
    report = {
        "target": {"username": "alice", "domain": "example.com", "email": "alice@example.com", "image": "photo.jpg"},
        "username_results": {"found": [{"platform": "GitHub"}, {"platform": "GitLab"}], "unclear": [{"platform": "X"}], "not_found": [], "error": []},
        "domain_results": {
            "security_headers_present": {"Strict-Transport-Security": "max-age=1"},
            "security_headers_missing": ["Content-Security-Policy"],
            "subdomains": {"success": True, "subdomains": ["a.example.com", "b.example.com"]},
        },
        "email_results": {"email": "alice@example.com", "hibp": {"checked": True, "breaches": [{"name": "X"}]}},
        "exif_results": {"has_exif": True, "gps": {"latitude": 1.0, "longitude": 2.0, "maps_url": "https://maps.example/?q=1,2"}},
        "risk_score": {"score": 42, "max_score": 100, "severity": "Medium", "triggered_rules": []},
    }
    html_out = generate_html_report(report)
    assert 'id="summary"' in html_out
    assert '<div class="kpi-label">Platforms Checked</div><div class="kpi-value">2/3 confirmed</div>' in html_out
    assert '<div class="kpi-label">Security Headers</div><div class="kpi-value">1/2 present</div>' in html_out
    assert '<div class="kpi-label">Subdomains Found</div><div class="kpi-value">2</div>' in html_out
    assert '<div class="kpi-label">Breach Status</div><div class="kpi-value bad">1 found</div>' in html_out
    assert '<div class="kpi-label">GPS In Photo</div><div class="kpi-value bad">Yes</div>' in html_out
    assert 'style="--dot:var(--sev-medium)"' in html_out


def test_executive_summary_email_not_checked_says_so():
    report = {
        "target": {"email": "alice@example.com"},
        "email_results": {"email": "alice@example.com", "hibp": {"checked": False}},
    }
    html_out = generate_html_report(report)
    assert '<div class="kpi-label">Breach Status</div><div class="kpi-value">Not checked</div>' in html_out


def test_executive_summary_no_gps_says_so():
    report = {
        "target": {"image": "photo.jpg"},
        "exif_results": {"has_exif": True, "gps": None},
    }
    html_out = generate_html_report(report)
    assert '<div class="kpi-label">GPS In Photo</div><div class="kpi-value ok">No</div>' in html_out


# --- GPS warning box ---------------------------------------------------

def test_gps_warning_box_shows_coordinates_and_recommendation():
    report = {
        "target": {"image": "photo.jpg"},
        "exif_results": {"has_exif": True, "gps": {
            "latitude": 30.080972, "longitude": 31.344928, "maps_url": "https://maps.example/?q=30,31",
        }},
    }
    html_out = generate_html_report(report)
    assert 'class="gps-warning"' in html_out
    assert "Exact location embedded in image" in html_out
    assert "30.080972" in html_out
    assert "31.344928" in html_out
    assert "strip EXIF metadata" in html_out


def test_no_gps_no_warning_box():
    report = {
        "target": {"image": "photo.jpg"},
        "exif_results": {"has_exif": True, "gps": None},
    }
    html_out = generate_html_report(report)
    assert 'class="gps-warning"' not in html_out


# --- footer --------------------------------------------------------------

def test_footer_shows_tool_name_and_version():
    html_out = generate_html_report({"target": {}})
    assert 'class="report-footer"' in html_out
    assert f"OSINT Footprint Analyzer v{utils.VERSION}" in html_out
    assert "Local analysis" in html_out
