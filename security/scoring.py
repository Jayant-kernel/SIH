def calculate(findings, selected, policy):
    weights = policy.get("severity_points", {"low": 3, "medium": 10, "high": 20, "critical": 35})
    penalty = sum(weights.get(f.severity, 0) for f in findings if f.status == "fail")
    score = max(0, min(100, penalty))
    important = policy.get("completeness_fields", ["encryption_algorithm", "integrity_algorithm", "mode", "dh_strength_bits", "pfs", "replay", "rekey_status", "protocol"])
    known = sum(1 for field in important if field in selected and selected[field].evidence_type != "unknown")
    completeness = round(known / len(important), 3) if important else 0.0
    level = "low" if score <= 19 else "low-moderate" if score <= 39 else "moderate" if score <= 59 else "high" if score <= 79 else "critical"
    return {"score": score, "level": level, "evidence_completeness": completeness, "penalty_points": penalty, "formula": "sum(rule penalties for proven failures); unknown adds no penalty", "transparent": True}
