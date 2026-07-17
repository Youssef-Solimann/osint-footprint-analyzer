from unittest.mock import patch

import requests

import username as mod


def _one_platform(monkeypatch, **overrides):
    platform = {"url": "https://fake.com/{u}", "reliable": True, "not_found_text": None}
    platform.update(overrides)
    monkeypatch.setattr(mod, "PLATFORMS", {"Fake": platform})


def test_404_is_not_found_regardless_of_reliability(monkeypatch, fake_response):
    _one_platform(monkeypatch, reliable=False)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=404)):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_reliable_200_is_found(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200)):
        result = mod.check_username("alice")
    assert len(result["found"]) == 1


def test_not_found_text_overrides_200(monkeypatch, fake_response):
    _one_platform(monkeypatch, not_found_text="nobody here")
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text="oops nobody here at all")):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_missing_og_title_overrides_200(monkeypatch, fake_response):
    _one_platform(monkeypatch, requires_og_title=True)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text="<html><head></head></html>")):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_present_og_title_confirms_found(monkeypatch, fake_response):
    _one_platform(monkeypatch, requires_og_title=True)
    body = '<meta property="og:title" content="Alice">'
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text=body)):
        result = mod.check_username("alice")
    assert len(result["found"]) == 1


def test_unreliable_200_is_unclear_not_found(monkeypatch, fake_response):
    _one_platform(monkeypatch, reliable=False)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200)):
        result = mod.check_username("alice")
    assert len(result["unclear"]) == 1
    assert result["found"] == []
    assert result["not_found"] == []


def test_403_is_unclear_with_reason(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=403)):
        result = mod.check_username("alice")
    assert "403" in result["unclear"][0]["reason"]


def test_redirect_is_surfaced_on_the_entry(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    resp = fake_response(status_code=200, history=[object()], url="https://fake.com/Alice")
    with patch("utils.get_with_retry", return_value=resp):
        result = mod.check_username("alice")
    assert result["found"][0]["redirected_to"] == "https://fake.com/Alice"


def test_request_exception_is_captured_as_error(monkeypatch):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", side_effect=requests.exceptions.ConnectionError("boom")):
        result = mod.check_username("alice")
    assert len(result["error"]) == 1
    assert result["found"] == result["not_found"] == result["unclear"] == []


def test_checks_run_concurrently_not_sequentially(monkeypatch, fake_response):
    # each platform is a distinct host, so the checks fire off in parallel
    # threads rather than one at a time with a politeness delay in between -
    # prove it by making every request block briefly and asserting the
    # wall-clock time stays well under what N sequential requests would take
    import time

    platforms = {
        f"Fake{i}": {"url": "https://fake.com/{u}", "reliable": True, "not_found_text": None}
        for i in range(8)
    }
    monkeypatch.setattr(mod, "PLATFORMS", platforms)

    def slow_get(url, *args, **kwargs):
        time.sleep(0.2)
        return fake_response(status_code=200)

    with patch("utils.get_with_retry", side_effect=slow_get):
        start = time.monotonic()
        result = mod.check_username("alice")
        elapsed = time.monotonic() - start

    assert len(result["found"]) == 8
    # sequential would take ~1.6s (8 * 0.2s); concurrent should be closer to 0.2s
    assert elapsed < 1.0
