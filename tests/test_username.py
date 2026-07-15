from unittest.mock import patch

import requests

import username as mod


def _one_platform(monkeypatch, **overrides):
    platform = {"url": "https://fake.com/{u}", "reliable": True, "not_found_text": None}
    platform.update(overrides)
    monkeypatch.setattr(mod, "PLATFORMS", {"Fake": platform})


def test_404_is_not_found_regardless_of_reliability(monkeypatch, fake_response):
    _one_platform(monkeypatch, reliable=False)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=404)), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_reliable_200_is_found(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200)), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["found"]) == 1


def test_not_found_text_overrides_200(monkeypatch, fake_response):
    _one_platform(monkeypatch, not_found_text="nobody here")
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text="oops nobody here at all")), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_missing_og_title_overrides_200(monkeypatch, fake_response):
    _one_platform(monkeypatch, requires_og_title=True)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text="<html><head></head></html>")), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["not_found"]) == 1
    assert result["found"] == []


def test_present_og_title_confirms_found(monkeypatch, fake_response):
    _one_platform(monkeypatch, requires_og_title=True)
    body = '<meta property="og:title" content="Alice">'
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200, text=body)), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["found"]) == 1


def test_unreliable_200_is_unclear_not_found(monkeypatch, fake_response):
    _one_platform(monkeypatch, reliable=False)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200)), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert len(result["unclear"]) == 1
    assert result["found"] == []
    assert result["not_found"] == []


def test_403_is_unclear_with_reason(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=403)), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert "403" in result["unclear"][0]["reason"]


def test_redirect_is_surfaced_on_the_entry(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    resp = fake_response(status_code=200, history=[object()], url="https://fake.com/Alice")
    with patch("utils.get_with_retry", return_value=resp), \
            patch("time.sleep"):
        result = mod.check_username("alice")
    assert result["found"][0]["redirected_to"] == "https://fake.com/Alice"


def test_request_exception_is_captured_as_error_with_no_pacing_sleep(monkeypatch):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", side_effect=requests.exceptions.ConnectionError("boom")), \
            patch("time.sleep") as sleep_mock:
        result = mod.check_username("alice")
    assert len(result["error"]) == 1
    assert result["found"] == result["not_found"] == result["unclear"] == []
    # regression check: a failed request shouldn't also pay the 0.3s pacing delay
    sleep_mock.assert_not_called()


def test_pacing_sleep_happens_after_a_completed_request(monkeypatch, fake_response):
    _one_platform(monkeypatch)
    with patch("utils.get_with_retry", return_value=fake_response(status_code=200)), \
            patch("time.sleep") as sleep_mock:
        mod.check_username("alice")
    sleep_mock.assert_called_once_with(0.3)
