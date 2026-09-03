"""Stable Phase 6 result schema helpers."""

ANALYSIS_VERSION = "phase6-v1"
REPORT_VERSION = "phase6-v1"


def unknown(value="Unknown"):
    return {"value": value, "evidence_type": "unknown", "confidence": 0.0, "source": "not available"}
