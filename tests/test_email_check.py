import sys
from unittest.mock import patch

import dns.resolver

import email_check as mod


class _MXRec:
    def __init__(self, exchange):
        self.exchange = exchange

    def __str__(self):
        return self.exchange


def test_invalid_format_short_circuits():
    result = mod.check_email("not-an-email")
    assert result["format_valid"] is False
    assert "hibp" not in result
    assert "mx_records" not in result


def test_valid_format_with_mx_records():
    with patch("dns.resolver.resolve", return_value=[_MXRec("mail.example.com")]):
        result = mod.check_email("user@example.com")
    assert result["format_valid"] is True
    assert result["mx_records"] == ["mail.example.com"]


def test_nxdomain_email_domain():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = mod.check_email("user@doesnotexist.invalid")
    assert result["mx_records"] == []
    assert "does not exist" in result["mx_error"]


def test_domain_exists_but_no_mx():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
        result = mod.check_email("user@example.com")
    assert result["mx_records"] == []
    assert "mx_error" not in result


def test_mx_check_skipped_when_dnspython_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    result = mod.check_email("user@example.com")
    assert result["mx_check"] == "SKIPPED - install dnspython"
    assert "mx_records" not in result


def test_hibp_not_checked_without_key():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
        result = mod.check_email("user@example.com", hibp_api_key=None)
    assert result["hibp"]["checked"] is False
    assert result["hibp"]["reason"] == "No HIBP API key provided"


def test_hibp_breach_found(fake_response):
    breach_body = [{"Name": "X", "Title": "Example Breach", "BreachDate": "2020-01-01", "DataClasses": ["Emails"]}]
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=200, json_data=breach_body)):
        result = mod.check_email("user@example.com", hibp_api_key="fake-key")
    assert result["hibp"]["checked"] is True
    assert len(result["hibp"]["breaches"]) == 1
    assert result["hibp"]["breaches"][0]["title"] == "Example Breach"


def test_hibp_no_breach_404(fake_response):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=404)):
        result = mod.check_email("user@example.com", hibp_api_key="fake-key")
    assert result["hibp"]["checked"] is True
    assert result["hibp"]["breaches"] == []


def test_hibp_invalid_key_401(fake_response):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=401)):
        result = mod.check_email("user@example.com", hibp_api_key="bad-key")
    assert result["hibp"]["checked"] is False
    assert "401" in result["hibp"]["reason"]


def test_hibp_sends_api_key_header(fake_response):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()), \
            patch("utils.get_with_retry", return_value=fake_response(status_code=404)) as get_mock:
        mod.check_email("user@example.com", hibp_api_key="secret-key")
    _, kwargs = get_mock.call_args
    assert kwargs["extra_headers"] == {"hibp-api-key": "secret-key"}
