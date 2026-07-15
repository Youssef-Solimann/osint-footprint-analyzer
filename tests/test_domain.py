import sys
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver
import requests

import domain as mod
from domain import _normalize_whois_value


class TestNormalizeWhoisValue:
    def test_passes_through_scalar(self):
        assert _normalize_whois_value("Namecheap") == "Namecheap"

    def test_takes_first_of_list(self):
        assert _normalize_whois_value(["first", "second"]) == "first"

    def test_empty_list_is_none(self):
        assert _normalize_whois_value([]) is None

    def test_none_stays_none(self):
        assert _normalize_whois_value(None) is None


class _Rec:
    """Minimal stand-in for a dnspython answer record - only str() is used."""

    def __init__(self, value):
        self.value = value
        self.exchange = value  # MX records are read via .exchange in check_email

    def __str__(self):
        return self.value


# --- check_dns_records -------------------------------------------------

def test_dns_records_normal(monkeypatch):
    def fake_resolve(domain, rtype):
        if rtype == "A":
            return [_Rec("1.2.3.4")]
        raise dns.resolver.NoAnswer()

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        result = mod.check_dns_records("example.com")
    assert result["A"] == ["1.2.3.4"]
    assert result["MX"] == []


def test_dns_nxdomain_stops_early_and_flags_result(monkeypatch):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = mod.check_dns_records("doesnotexist.invalid")
    assert result["nxdomain"] is True
    assert result["A"] == []


def test_dns_no_nameservers_reported_as_empty_not_crashing(monkeypatch):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoNameservers()):
        result = mod.check_dns_records("example.com")
    assert result["A"] == []
    assert "nxdomain" not in result


def test_dns_unexpected_exception_per_record_type_does_not_crash(monkeypatch):
    # a record type raising something other than the three expected
    # dnspython exceptions (e.g. a raw socket timeout) must not blow up
    # the whole lookup - every other record type should still be attempted
    with patch("dns.resolver.resolve", side_effect=TimeoutError("network unreachable")):
        result = mod.check_dns_records("example.com")
    assert result["A"] == []
    assert result["MX"] == []
    assert "nxdomain" not in result


def test_dns_records_skipped_when_dnspython_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    result = mod.check_dns_records("example.com")
    assert result["skipped"] is True
    assert result["reason"] == "dnspython not installed"
    assert result["A"] == []


# --- check_subdomains ----------------------------------------------------

def test_subdomains_success(fake_response):
    body = [{"name_value": "foo.example.com\nbar.example.com"}]
    with patch("requests.get", return_value=fake_response(status_code=200, json_data=body)):
        result = mod.check_subdomains("example.com")
    assert result["success"] is True
    assert result["subdomains"] == ["bar.example.com", "foo.example.com"]


def test_subdomains_strips_wildcard_prefix(fake_response):
    body = [{"name_value": "*.example.com"}]
    with patch("requests.get", return_value=fake_response(status_code=200, json_data=body)):
        result = mod.check_subdomains("example.com")
    assert result["subdomains"] == ["example.com"]


def test_subdomains_rate_limited(fake_response):
    with patch("requests.get", return_value=fake_response(status_code=429)):
        result = mod.check_subdomains("example.com")
    assert result["success"] is False
    assert "429" in result["reason"]


def test_subdomains_service_unavailable(fake_response):
    with patch("requests.get", return_value=fake_response(status_code=503)):
        result = mod.check_subdomains("example.com")
    assert result["success"] is False
    assert "503" in result["reason"]


def test_subdomains_non_json_response_does_not_crash(fake_response):
    with patch("requests.get", return_value=fake_response(status_code=200)):
        result = mod.check_subdomains("example.com")
    assert result["success"] is False
    assert "non-JSON" in result["reason"]


def test_subdomains_request_exception():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("slow")):
        result = mod.check_subdomains("example.com")
    assert result["success"] is False
    assert result["status"] is None


def test_subdomains_deduplicates_repeated_names(fake_response):
    # multiple certs commonly re-list the same name - crt.sh output should
    # collapse to unique entries, not one per certificate
    body = [{"name_value": "foo.example.com"}, {"name_value": "foo.example.com\nbar.example.com"}]
    with patch("requests.get", return_value=fake_response(status_code=200, json_data=body)):
        result = mod.check_subdomains("example.com")
    assert result["subdomains"] == ["bar.example.com", "foo.example.com"]


def test_subdomains_filters_out_entries_for_a_different_domain(fake_response):
    # a cert can cover unrelated SANs alongside the target - only names that
    # actually belong to the queried domain should survive
    body = [{"name_value": "foo.example.com\nsomethingelse.completely-different.org"}]
    with patch("requests.get", return_value=fake_response(status_code=200, json_data=body)):
        result = mod.check_subdomains("example.com")
    assert result["subdomains"] == ["foo.example.com"]


# --- check_domain: WHOIS registrant extraction ---------------------------

def _whois_stub(**overrides):
    defaults = dict(
        registrar="Namecheap, Inc.",
        creation_date="2019-03-04 00:00:00",
        expiration_date="2027-03-04 00:00:00",
        name_servers=["ns1.registrar.net", "ns2.registrar.net"],
        name="Jane Doe",
        org=None,
        emails=["jane@janedoe.dev"],
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


_NO_SUBDOMAINS = {"success": False, "status": None, "source": "crt.sh", "reason": "stubbed", "subdomains": []}


def test_check_domain_extracts_registrant_fields(fake_response):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", return_value=_whois_stub()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, headers={})), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("janedoe.dev")

    assert result["registrar"] == "Namecheap, Inc."
    assert result["registrant_name"] == "Jane Doe"
    assert result["registrant_emails"] == ["jane@janedoe.dev"]


def test_check_domain_normalizes_list_shaped_whois_fields(fake_response):
    stub = _whois_stub(registrar=["Registrar A", "Registrar A (dup)"], emails="single@example.com")
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", return_value=stub), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, headers={})), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")

    assert result["registrar"] == "Registrar A"
    assert result["registrant_emails"] == ["single@example.com"]


def test_check_domain_missing_registrant_fields_are_none_or_empty(fake_response):
    stub = _whois_stub(name=None, org=None, emails=None)
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", return_value=stub), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, headers={})), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")

    assert result["registrant_name"] is None
    assert result["registrant_org"] is None
    assert result["registrant_emails"] == []


def test_check_domain_handles_missing_whois_library(monkeypatch, fake_response):
    monkeypatch.setitem(sys.modules, "whois", None)
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, headers={})), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")
    assert result["whois"] == "SKIPPED - install python-whois"


def test_check_domain_security_headers_split_present_and_missing(fake_response):
    resp = fake_response(status_code=200, headers={"Strict-Transport-Security": "max-age=1"})
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", return_value=_whois_stub()), \
            patch("utils.get_with_retry", return_value=resp), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")

    assert result["security_headers_present"] == {"Strict-Transport-Security": "max-age=1"}
    assert "Content-Security-Policy" in result["security_headers_missing"]


def test_check_domain_whois_generic_exception_is_captured_not_raised(fake_response):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", side_effect=RuntimeError("registrar server refused connection")), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, headers={})), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")

    assert "registrar server refused connection" in result["whois_error"]
    assert "registrar" not in result


def test_check_domain_unreachable_site_leaves_header_keys_unset(fake_response):
    # if the site itself can't be reached, check_domain must not crash - and
    # since we never got headers, present/missing should be left unset
    # rather than reported as "all headers missing" (that would be a false
    # security finding, not an honest "couldn't check")
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("whois.whois", return_value=_whois_stub()), \
            patch("utils.get_with_retry", side_effect=requests.exceptions.ConnectionError("refused")), \
            patch("domain.check_subdomains", return_value=_NO_SUBDOMAINS):
        result = mod.check_domain("example.com")

    assert "security_headers_present" not in result
    assert "security_headers_missing" not in result
