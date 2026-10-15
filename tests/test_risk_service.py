import pytest

from app.services.risk_service import prioritize_finding


@pytest.mark.parametrize(
    ("severity", "status", "kev", "expected"),
    [
        ("CRITICAL", "affected", False, "CRITICAL"),
        ("HIGH", "affected", False, "HIGH"),
        ("CRITICAL", "potential", False, "HIGH"),
        ("HIGH", "potential", False, "MEDIUM"),
        ("LOW", "potential", True, "HIGH"),
        ("CRITICAL", "affected", True, "CRITICAL"),
        ("CRITICAL", "potential", True, "HIGH"),
        ("HIGH", "not_applicable", True, "NOT PRIORITIZED"),
    ],
)
def test_contextual_priority_rules_are_explainable(
    severity,
    status,
    kev,
    expected,
):
    result = prioritize_finding(severity, None, status, kev)

    assert result["priority"] == expected
    assert result["reason"]


def test_cvss_score_can_supply_missing_severity():
    result = prioritize_finding(None, 9.8, "affected", False)

    assert result["priority"] == "CRITICAL"
    assert "CRITICAL vulnerability severity" in result["reason"]


def test_missing_severity_and_score_require_review_not_low_priority():
    result = prioritize_finding(None, None, "potential", False)

    assert result["priority"] == "REVIEW"
    assert "not evidence of low risk" in result["reason"]


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 10.1, True])
def test_invalid_cvss_score_is_not_used(score):
    result = prioritize_finding(None, score, "affected", False)

    assert result["priority"] == "REVIEW"
