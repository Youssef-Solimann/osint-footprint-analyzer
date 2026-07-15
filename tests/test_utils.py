from unittest.mock import patch

import utils


def test_returns_immediately_on_200(fake_response):
    with patch("requests.get", return_value=fake_response(status_code=200)) as get_mock:
        r = utils.get_with_retry("https://example.com")
    assert r.status_code == 200
    assert get_mock.call_count == 1


def test_non_429_status_is_never_retried(fake_response):
    with patch("requests.get", return_value=fake_response(status_code=500)) as get_mock:
        r = utils.get_with_retry("https://example.com")
    assert r.status_code == 500
    assert get_mock.call_count == 1


def test_retries_on_429_then_succeeds(fake_response):
    responses = [fake_response(status_code=429, headers={}), fake_response(status_code=200)]
    with patch("requests.get", side_effect=responses) as get_mock, \
            patch("time.sleep") as sleep_mock:
        r = utils.get_with_retry("https://example.com")
    assert r.status_code == 200
    assert get_mock.call_count == 2
    sleep_mock.assert_called_once()


def test_gives_up_after_max_retries(fake_response):
    responses = [fake_response(status_code=429, headers={})] * 3
    with patch("requests.get", side_effect=responses) as get_mock, \
            patch("time.sleep"):
        r = utils.get_with_retry("https://example.com", max_retries=2)
    assert r.status_code == 429
    assert get_mock.call_count == 3  # initial attempt + 2 retries


def test_prefers_retry_after_header(fake_response):
    responses = [fake_response(status_code=429, headers={"Retry-After": "3"}), fake_response(status_code=200)]
    with patch("requests.get", side_effect=responses), \
            patch("time.sleep") as sleep_mock:
        utils.get_with_retry("https://example.com")
    sleep_mock.assert_called_once_with(3.0)


def test_non_numeric_retry_after_falls_back_to_exponential_backoff(fake_response):
    responses = [
        fake_response(status_code=429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        fake_response(status_code=200),
    ]
    with patch("requests.get", side_effect=responses), \
            patch("time.sleep") as sleep_mock:
        utils.get_with_retry("https://example.com")
    sleep_mock.assert_called_once_with(1)  # 2**0, first backoff step


def test_backoff_is_capped_at_max_wait(fake_response):
    responses = [fake_response(status_code=429, headers={})] * 6 + [fake_response(status_code=200)]
    with patch("requests.get", side_effect=responses), \
            patch("time.sleep") as sleep_mock:
        utils.get_with_retry("https://example.com", max_retries=6)
    waits = [call.args[0] for call in sleep_mock.call_args_list]
    assert max(waits) <= utils.MAX_BACKOFF_WAIT


class TestGenerateDorks:
    def test_username_only(self):
        dorks = utils.generate_dorks(username="alice")
        assert any("alice" in d for d in dorks)
        assert not any("example.com" in d for d in dorks)

    def test_domain_only(self):
        dorks = utils.generate_dorks(domain="example.com")
        assert any("site:example.com" in d for d in dorks)

    def test_email_only(self):
        dorks = utils.generate_dorks(email="alice@example.com")
        assert any("alice@example.com" in d for d in dorks)

    def test_nothing_supplied_returns_empty(self):
        assert utils.generate_dorks() == []
