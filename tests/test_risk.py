import pytest

from risk import RISK_RULES, calculate_risk, get_severity


class TestGetSeverity:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "Low"), (20, "Low"),
            (21, "Medium"), (40, "Medium"),
            (41, "High"), (70, "High"),
            (71, "Critical"), (100, "Critical"),
        ],
    )
    def test_bands(self, score, expected):
        assert get_severity(score) == expected


def test_no_data_scores_zero():
    result = calculate_risk({})
    assert result["score"] == 0
    assert result["severity"] == "Low"
    assert result["triggered_rules"] == []


def test_hibp_breach_fires():
    report = {"email_results": {"hibp": {"checked": True, "breaches": [{"name": "X"}]}}}
    result = calculate_risk(report)
    assert result["score"] == RISK_RULES["hibp_breach"]["points"]
    assert result["triggered_rules"][0]["rule"] == "hibp_breach"


def test_hibp_checked_but_clean_does_not_fire():
    report = {"email_results": {"hibp": {"checked": True, "breaches": []}}}
    assert calculate_risk(report)["score"] == 0


def test_hibp_not_checked_does_not_fire():
    report = {"email_results": {"hibp": {"checked": False, "breaches": []}}}
    assert calculate_risk(report)["score"] == 0


def test_domain_results_present_but_no_header_keys_at_all():
    # this is exactly the shape check_domain leaves behind when the site
    # was unreachable (RequestException) - present/missing keys are absent
    # entirely, not empty. Must not crash and must not fire any header rule.
    report = {"domain_results": {"registrar": "Example Registrar"}}
    result = calculate_risk(report)
    assert result["score"] == 0


def test_missing_security_header_fires_its_own_rule():
    report = {"domain_results": {"security_headers_missing": ["X-Frame-Options"]}}
    result = calculate_risk(report)
    assert result["score"] == RISK_RULES["no_xfo"]["points"]
    assert result["triggered_rules"][0]["rule"] == "no_xfo"


def test_all_security_headers_missing_sum_independently():
    report = {
        "domain_results": {
            "security_headers_missing": [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
            ]
        }
    }
    result = calculate_risk(report)
    expected = sum(RISK_RULES[r]["points"] for r in ("no_hsts", "no_csp", "no_xfo", "no_xcto"))
    assert result["score"] == expected
    assert len(result["triggered_rules"]) == 4


def test_many_subdomains_does_not_fire_at_threshold():
    threshold = RISK_RULES["many_subdomains"]["threshold"]
    report = {"domain_results": {"subdomains": {"success": True, "subdomains": [f"s{i}.x.com" for i in range(threshold)]}}}
    assert calculate_risk(report)["score"] == 0


def test_many_subdomains_fires_above_threshold():
    threshold = RISK_RULES["many_subdomains"]["threshold"]
    report = {"domain_results": {"subdomains": {"success": True, "subdomains": [f"s{i}.x.com" for i in range(threshold + 1)]}}}
    assert calculate_risk(report)["score"] == RISK_RULES["many_subdomains"]["points"]


def test_failed_subdomain_lookup_never_scores():
    report = {"domain_results": {"subdomains": {"success": False, "subdomains": []}}}
    assert calculate_risk(report)["score"] == 0


def test_username_footprint_scales_below_cap():
    rule = RISK_RULES["large_username_footprint"]
    report = {"username_results": {"found": [{"platform": "a"}, {"platform": "b"}]}}
    assert calculate_risk(report)["score"] == min(2 * rule["points"], rule["max_points"])


def test_username_footprint_caps_at_max_points():
    rule = RISK_RULES["large_username_footprint"]
    report = {"username_results": {"found": [{"platform": f"p{i}"} for i in range(20)]}}
    assert calculate_risk(report)["score"] == rule["max_points"]


def test_combined_rules_sum_and_severity_matches_get_severity():
    report = {
        "email_results": {"hibp": {"checked": True, "breaches": [{"name": "a"}] * 5}},
        "domain_results": {
            "security_headers_missing": [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
            ],
            "subdomains": {"success": True, "subdomains": [f"s{i}.x.com" for i in range(20)]},
        },
        "username_results": {"found": [{"platform": f"p{i}"} for i in range(20)]},
    }
    result = calculate_risk(report)
    expected = (
        RISK_RULES["hibp_breach"]["points"]
        + RISK_RULES["no_hsts"]["points"] + RISK_RULES["no_csp"]["points"]
        + RISK_RULES["no_xfo"]["points"] + RISK_RULES["no_xcto"]["points"]
        + RISK_RULES["many_subdomains"]["points"]
        + RISK_RULES["large_username_footprint"]["max_points"]
    )
    assert result["score"] == expected
    assert result["severity"] == get_severity(expected)


def test_score_never_exceeds_100_even_if_rules_summed_higher(monkeypatch):
    # construct a report that would score well past 100 if nothing capped it,
    # to prove the min(total, 100) cap in calculate_risk actually holds
    report = {
        "email_results": {"hibp": {"checked": True, "breaches": [{"name": "a"}] * 20}},
        "domain_results": {
            "security_headers_missing": [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
            ],
            "subdomains": {"success": True, "subdomains": [f"s{i}.x.com" for i in range(50)]},
        },
        "username_results": {"found": [{"platform": f"p{i}"} for i in range(50)]},
    }
    inflated_rules = dict(RISK_RULES)
    inflated_rules["hibp_breach"] = {**RISK_RULES["hibp_breach"], "points": 90}
    monkeypatch.setattr("risk.RISK_RULES", inflated_rules)

    result = calculate_risk(report)
    assert result["score"] == 100
    assert result["severity"] == "Critical"
