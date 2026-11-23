from app.scoring.engine import ScoreInput, calculate, severity_for_score


def factors(result):
    return {f["factor"]: f["points"] for f in result.breakdown}


def test_severity_bands():
    assert [severity_for_score(s) for s in (0, 19, 20, 39, 40, 59, 60, 79, 80, 100)] == [
        "informational", "informational", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_base_only_with_full_confidence_keeps_score():
    r = calculate(ScoreInput("R", base_score=45, confidence=1.0), {}, {})
    assert r.score == 45 and r.severity == "medium"


def test_confidence_reduces_score():
    r = calculate(ScoreInput("R", base_score=50, confidence=0.5), {}, {})
    assert r.score == 40  # 50 * (0.6 + 0.2)


def test_frequency_factor_is_logarithmic_and_capped():
    double = calculate(ScoreInput("R", 40, 1.0, count=10, threshold=5), {}, {})
    huge = calculate(ScoreInput("R", 40, 1.0, count=10_000, threshold=5), {}, {})
    assert factors(double)["Event frequency"] == 5
    assert factors(huge)["Event frequency"] == 15


def test_accounts_reputation_asset_and_related_factors():
    rep = {"203.0.113.5": {"verdict": "malicious", "source": "local", "confidence": 0.9},
           "203.0.113.6": {"verdict": "suspicious", "source": "local", "confidence": 0.5}}
    r = calculate(ScoreInput("SEN-AUTH-001", 40, 1.0, accounts=["a", "b", "c"], ips=["203.0.113.6", "203.0.113.5"],
                             systems=["dc-01"], related_alert_ids=[7, 8, 9]), rep, {"dc-01": "high"})
    f = factors(r)
    assert f["Affected accounts"] == 8 and f["Source reputation"] == 15  # strongest IP once, not 15 + 7
    assert f["Asset importance"] == 10 and f["Related activity"] == 10
    assert r.score == 83


def test_reputation_not_double_counted_for_intel_rule():
    rep = {"203.0.113.5": {"verdict": "malicious", "source": "local", "confidence": 0.9}}
    r = calculate(ScoreInput("SEN-INTEL-001", 45, 1.0, ips=["203.0.113.5"], severity_hint="high"), rep, {})
    assert "Source reputation" not in factors(r)
    assert factors(r)["Rule base score"] == 60


def test_extra_points_capped_and_total_capped_at_100():
    r = calculate(ScoreInput("R", 95, 1.0, extra_points=[{"factor": "a", "points": 12, "explanation": ""},
                                                       {"factor": "b", "points": 12, "explanation": ""}],
                             related_alert_ids=[1, 2]), {}, {})
    f = factors(r)
    assert f["a"] + f["b"] == 15
    assert r.score == 100


def test_every_point_is_explained():
    r = calculate(ScoreInput("R", 45, 0.8, count=12, threshold=5, accounts=["a", "b"]), {}, {})
    assert sum(item["points"] for item in r.breakdown) == r.score
    assert all(item["explanation"] for item in r.breakdown)
