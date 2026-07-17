"""
CLI orchestration in osint_footprint.py.

Every recon/scoring module is mocked here - this file isn't about whether
domain.py or risk.py compute the right thing (their own test files already
cover that), it's about whether main() wires their outputs into the printed
report correctly. Complements tests/test_integration.py, which wires
everything together for real but only inspects the JSON/HTML outputs, never
stdout.
"""

import sys
from unittest.mock import patch

import osint_footprint


def test_triggered_rule_prints_recommendation_alongside_description(monkeypatch, capsys):
    fake_risk_result = {
        "score": 10,
        "max_score": 100,
        "severity": "Low",
        "triggered_rules": [{
            "rule": "no_hsts",
            "points": 10,
            "description": "Domain does not enforce HTTPS (missing Strict-Transport-Security)",
            "recommendation": "Enable Strict-Transport-Security to force HTTPS on all connections.",
        }],
    }
    monkeypatch.setattr(osint_footprint.domain_mod, "check_domain", lambda domain: {})
    monkeypatch.setattr(osint_footprint.risk, "calculate_risk", lambda report: fake_risk_result)

    argv = ["osint_footprint.py", "--domain", "example.com"]
    with patch.object(sys, "argv", argv):
        osint_footprint.main()

    out = capsys.readouterr().out
    assert "+10  Domain does not enforce HTTPS (missing Strict-Transport-Security)" in out
    assert "-> Enable Strict-Transport-Security to force HTTPS on all connections." in out


def test_no_triggered_rules_prints_no_risk_factors_and_no_arrow(monkeypatch, capsys):
    monkeypatch.setattr(osint_footprint.domain_mod, "check_domain", lambda domain: {})
    monkeypatch.setattr(osint_footprint.risk, "calculate_risk", lambda report: {
        "score": 0, "max_score": 100, "severity": "Low", "triggered_rules": [],
    })

    argv = ["osint_footprint.py", "--domain", "example.com"]
    with patch.object(sys, "argv", argv):
        osint_footprint.main()

    out = capsys.readouterr().out
    assert "No risk factors triggered." in out
    assert "->" not in out