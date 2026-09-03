# NOTE (repaired): this module previously imported a removed `score()` API,
# which broke pytest collection for the entire suite. Updated to the
# current validated `calculate()` semantics (severity weights, unknown
# adds no penalty). Production code untouched.
from security.scoring import calculate


def test_score_is_transparent_and_bounded():
    from security.schema import Finding, Evidence
    f = [Finding("x", "x", "security", "high", "fail", "x", [], "fix", 1.0)]
    r = calculate(f, {"protocol": Evidence("protocol", "ESP", "directly_observed", 1.0, "t")},
                  {"pass_score": 70})
    assert r["score"] == 20 and r["penalty_points"] == 20 and r["transparent"]
    assert r["evidence_completeness"] == 0.125


def test_unknown_evidence_adds_no_penalty():
    from security.schema import Finding, Evidence
    f = [Finding("x", "x", "security", "medium", "unknown", "x", [], "fix", 0.0)]
    r = calculate(f, {"x": Evidence("x", None, "unknown", 0.0, "t")}, {})
    assert r["score"] == 0 and r["penalty_points"] == 0
