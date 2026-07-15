import os
import sys

# Every recon module (username.py, domain.py, email_check.py, etc.) is a
# flat top-level module, not an installed package - make sure the repo root
# is importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


class FakeResponse:
    """Stands in for requests.Response across all mocked-network tests.

    Only implements the surface area the recon modules actually touch
    (status_code, text, headers, history, url, json()) - not a general
    requests mock.
    """

    def __init__(self, status_code=200, text="", headers=None, history=None, url="", json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.history = history or []
        self.url = url
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body configured on this FakeResponse")
        return self._json_data


@pytest.fixture
def fake_response():
    return FakeResponse
