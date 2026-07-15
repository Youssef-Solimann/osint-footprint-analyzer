"""
Full end-to-end integration test.

Every other test file mocks one module in isolation. This one runs the
real main() - real argparse, real file writing, every module wired
together exactly as a live invocation would - with only the network-
touching calls (dns.resolver, whois, requests) mocked out. It's designed
to trigger every risk rule and every correlation rule at least once, so
a single run exercises the full width of the tool: username enumeration,
domain recon, email/HIBP, EXIF/GPS, correlation, risk scoring, and both
JSON and HTML report output.

Where per-module tests answer "does this piece work in isolation", this
answers "do all the pieces still agree with each other's data shapes
once wired together for real" - the class of bug unit tests miss.
"""

import json
import re
import sys
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver
from PIL import Image
from PIL.ExifTags import Base, IFD
from PIL.TiffImagePlugin import IFDRational

import osint_footprint
from risk import RISK_RULES

USERNAME = "janedoe"
DOMAIN = "janedoe.dev"
EMAIL = "jane@janedoe.dev"

# 12 subdomains (> the many_subdomains threshold of 10), including one that
# exactly matches USERNAME as its leftmost label (fires username_in_subdomains)
SUBDOMAINS = [
    "janedoe.janedoe.dev", "blog.janedoe.dev", "mail.janedoe.dev", "api.janedoe.dev",
    "www.janedoe.dev", "shop.janedoe.dev", "dev.janedoe.dev", "staging.janedoe.dev",
    "cdn.janedoe.dev", "assets.janedoe.dev", "support.janedoe.dev", "status.janedoe.dev",
]


class _DnsRec:
    def __init__(self, value):
        self.value = value
        self.exchange = value  # MX records read .exchange

    def __str__(self):
        return self.value


def _fake_dns_resolve(domain, rtype):
    if domain == f"_dmarc.{DOMAIN}" and rtype == "TXT":
        return [_DnsRec('"v=DMARC1; p=reject"')]
    assert domain == DOMAIN  # both --domain and the email's domain are janedoe.dev
    if rtype == "A":
        return [_DnsRec("192.0.2.10")]
    if rtype == "MX":
        return [_DnsRec("mail.janedoe.dev")]
    raise dns.resolver.NoAnswer()


def _whois_stub():
    # registrant org deliberately contains the username substring to fire
    # whois_registrant_matches_username, and registrant_emails matches the
    # target email to fire whois_registrant_email_matches_target_email
    return SimpleNamespace(
        registrar="Namecheap, Inc.",
        creation_date="2019-03-04 00:00:00",
        expiration_date="2027-03-04 00:00:00",
        name_servers=["ns1.registrar.net", "ns2.registrar.net"],
        name="Jane Doe",
        org="JaneDoe Web Services",
        emails=[EMAIL],
    )


ROBOTS_TXT_BODY = "User-agent: *\nDisallow: /admin\nDisallow: /internal\n"
SECURITY_TXT_BODY = "Contact: mailto:security@janedoe.dev\nExpires: 2027-01-01T00:00:00Z\n"


def _make_fake_get_with_retry(fake_response_cls):
    def fake_get_with_retry(url, max_retries=2, extra_headers=None):
        if "haveibeenpwned.com" in url:
            return fake_response_cls(status_code=200, json_data=[{
                "Name": "ExampleBreach", "Title": "Example Breach",
                "BreachDate": "2020-01-01", "DataClasses": ["Emails", "Passwords"],
            }])
        if url == f"https://{DOMAIN}":
            # no security headers present at all -> all 4 header rules fire.
            # Server header doubles as the technology-fingerprint signal.
            return fake_response_cls(status_code=200, headers={"Server": "cloudflare"})
        if url == f"https://{DOMAIN}/robots.txt":
            return fake_response_cls(status_code=200, text=ROBOTS_TXT_BODY)
        if url == f"https://{DOMAIN}/.well-known/security.txt":
            return fake_response_cls(status_code=200, text=SECURITY_TXT_BODY)
        # one of the 15 username platform-check URLs
        return fake_response_cls(status_code=200, text="")
    return fake_get_with_retry


def _make_fake_requests_get(fake_response_cls):
    def fake_requests_get(url, headers=None, timeout=None):
        name_value = "\n".join(SUBDOMAINS)
        return fake_response_cls(status_code=200, json_data=[{"name_value": name_value}])
    return fake_requests_get


def _make_photo_with_gps(path):
    img = Image.new("RGB", (32, 32), color="red")
    exif = Image.Exif()
    exif[Base.Make.value] = "Apple"
    exif[Base.Model.value] = "iPhone 15 Pro"
    gps_ifd = exif.get_ifd(IFD.GPSInfo)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(40, 1), IFDRational(44, 1), IFDRational(54, 1))
    gps_ifd[3] = "W"
    gps_ifd[4] = (IFDRational(73, 1), IFDRational(59, 1), IFDRational(8, 1))
    img.save(path, exif=exif)


def test_full_pipeline_end_to_end(tmp_path, monkeypatch, fake_response):
    image_path = tmp_path / "photo.jpg"
    _make_photo_with_gps(image_path)
    out_path = tmp_path / "results.json"
    html_path = tmp_path / "report.html"

    argv = [
        "osint_footprint.py",
        "--username", USERNAME,
        "--domain", DOMAIN,
        "--email", EMAIL,
        "--image", str(image_path),
        "--hibp-key", "test-key-123",
        "--out", str(out_path),
        "--html", str(html_path),
    ]

    with patch("dns.resolver.resolve", side_effect=_fake_dns_resolve), \
            patch("whois.whois", return_value=_whois_stub()), \
            patch("utils.get_with_retry", side_effect=_make_fake_get_with_retry(fake_response)), \
            patch("requests.get", side_effect=_make_fake_requests_get(fake_response)), \
            patch("time.sleep"), \
            patch.object(sys, "argv", argv):
        osint_footprint.main()

    # --- top-level shape: every module contributed its section ---
    report = json.loads(out_path.read_text())
    for key in (
        "generated_at", "target", "username_results", "domain_results",
        "email_results", "exif_results", "correlations", "suggested_dorks", "risk_score",
    ):
        assert key in report, f"missing top-level key: {key}"

    # --- username enumeration actually ran across all real platforms ---
    username_results = report["username_results"]
    assert len(username_results["found"]) + len(username_results["not_found"]) + len(username_results["unclear"]) == 15

    # --- domain recon: DNS, WHOIS registrant fields, subdomains all present ---
    domain_results = report["domain_results"]
    assert domain_results["dns_records"]["A"] == ["192.0.2.10"]
    assert domain_results["registrant_org"] == "JaneDoe Web Services"
    assert domain_results["registrant_emails"] == [EMAIL]
    assert domain_results["name_servers"] == ["ns1.registrar.net", "ns2.registrar.net"]
    assert domain_results["subdomains"]["success"] is True
    assert len(domain_results["subdomains"]["subdomains"]) == 12

    # --- new OSINT checks: tech fingerprint, SPF/DMARC, robots/security.txt ---
    assert domain_results["technologies"] == ["Cloudflare"]
    assert domain_results["email_security"]["spf"] is False  # no SPF in the (empty) TXT records
    assert domain_results["email_security"]["dmarc"] is True
    assert domain_results["email_security"]["dmarc_record"] == "v=DMARC1; p=reject"
    assert domain_results["robots_disallow"] == ["/admin", "/internal"]
    assert domain_results["security_txt"] == SECURITY_TXT_BODY.strip()

    # --- email/HIBP ---
    assert report["email_results"]["hibp"]["checked"] is True
    assert len(report["email_results"]["hibp"]["breaches"]) == 1

    # --- EXIF/GPS ---
    assert report["exif_results"]["has_exif"] is True
    assert report["exif_results"]["gps"] is not None

    # --- correlation engine: all 4 rule types fired ---
    correlation_types = {c["type"] for c in report["correlations"]}
    assert correlation_types == {
        "email_domain_matches_scanned_domain",
        "username_in_subdomains",
        "whois_registrant_email_matches_target_email",
        "whois_registrant_matches_username",
    }

    # --- risk scoring: every rule in RISK_RULES fired at least once ---
    triggered_rule_names = {t["rule"] for t in report["risk_score"]["triggered_rules"]}
    assert triggered_rule_names == set(RISK_RULES.keys())
    expected_score = (
        RISK_RULES["hibp_breach"]["points"]
        + RISK_RULES["no_hsts"]["points"] + RISK_RULES["no_csp"]["points"]
        + RISK_RULES["no_xfo"]["points"] + RISK_RULES["no_xcto"]["points"]
        + RISK_RULES["many_subdomains"]["points"]
        + RISK_RULES["gps_in_photo"]["points"]
        + report["risk_score"]["triggered_rules"][
            [t["rule"] for t in report["risk_score"]["triggered_rules"]].index("large_username_footprint")
        ]["points"]
    )
    assert report["risk_score"]["score"] == expected_score

    # --- HTML report: every section rendered, key findings visible ---
    html_out = html_path.read_text()
    assert html_out.strip().startswith("<!doctype html>")
    for section_id in ("summary", "risk", "correlations", "username", "domain", "email", "exif", "dorks"):
        assert f'id="{section_id}"' in html_out
    assert "Example Breach" in html_out
    assert "janedoe.janedoe.dev" in html_out
    assert "ns1.registrar.net" in html_out
    assert "JaneDoe Web Services" in html_out
    assert "Cloudflare" in html_out
    assert "v=DMARC1; p=reject" in html_out
    assert "/admin" in html_out
    assert "security@janedoe.dev" in html_out

    # --- executive summary reflects every category that ran ---
    assert "confirmed" in html_out and "unclear" in html_out  # username line
    assert "security headers present" in html_out
    assert "known breach(es)" in html_out
    assert "GPS coordinates found" in html_out

    # --- GPS warning box and footer ---
    assert 'class="gps-warning"' in html_out
    assert "strip EXIF metadata" in html_out
    assert 'class="report-footer"' in html_out
    assert "OSINT Footprint Analyzer v" in html_out

    for tag in ("section", "div", "table", "ul", "details", "aside", "main", "svg"):
        opens = len(re.findall(rf"<{tag}\b", html_out))
        closes = len(re.findall(rf"</{tag}>", html_out))
        assert opens == closes, f"<{tag}> mismatch: {opens} opens vs {closes} closes"
