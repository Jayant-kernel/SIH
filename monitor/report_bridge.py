#!/usr/bin/env python3
"""Adapt a live monitor contract into the result shape consumed by
reports.generate_report.executive/technical.

Read-only: it reformats values already produced by the passive monitor
(evidence, findings, risk, ML output). It never recomputes risk, retrains
ML, invents findings, or treats an unknown as secure or insecure.
"""
from datetime import datetime, timezone

PROVENANCE_TO_EVIDENCE = {
    "Observed": "directly_observed",
    "Derived": "deterministically_derived",
    "ML Inferred": "ml_inferred",
    "Unknown": "unknown",
}

PASSIVE_LIMITATION = (
    "Passive ciphertext cannot prove encryption algorithm, key size, "
    "integrity transform, mode, PFS, DH group, or replay protection."
)


def _iso(ts):
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return ts if ts is not None else None


def _evidence_type(provenance):
    return PROVENANCE_TO_EVIDENCE.get(str(provenance), "unknown")


def _fields(profile):
    out = {}
    for key, value in (profile.get("fields") or {}).items():
        out[key] = {
            "value": value.get("value"),
            "evidence_type": _evidence_type(value.get("provenance")),
            "confidence": None,
            "source": value.get("source"),
            "reason": value.get("reason"),
        }
    return out


def _limitations(profile, contract):
    limits = []
    if profile.get("low_evidence_warning"):
        limits.append(profile["low_evidence_warning"])
    unknown = profile.get("unknown_fields") or []
    if unknown:
        limits.append(
            "Unverified checks (insufficient passive evidence): %s."
            % ", ".join(str(x) for x in unknown))
    limits.append(PASSIVE_LIMITATION)
    state = contract.get("live_state")
    if state == "stale":
        limits.append("Live sensor data is stale: %s."
                      % (contract.get("live_state_reason") or "no fresh heartbeat"))
    elif state == "unavailable":
        limits.append("Live sensor data is unavailable.")
    return limits


def live_report_input(contract, state_file=None):
    """Map a live_contract() snapshot onto the Phase 6 result shape."""
    contract = contract or {}
    profiles = contract.get("profiles") or []
    profile = profiles[0] if profiles else {}
    fields = _fields(profile)

    tp = profile.get("traffic") or {}
    prediction = {
        "label": tp.get("label", "Unknown"),
        "confidence": tp.get("confidence"),
        "probabilities": tp.get("probabilities", {}),
        "reason": tp.get("reason", "no_prediction_yet"),
        "explanation": tp.get("explanation", ""),
        "window_packets": tp.get("window_packets"),
        "window_seconds": tp.get("window_seconds"),
        "provenance": "ML Inferred" if tp.get("label") not in (None, "", "Unknown") else "Unknown",
    }
    traffic_analysis = {
        "traffic_prediction": prediction,
        "model_version": tp.get("model_version", "unknown"),
        "reason": prediction["reason"],
        "explanation": prediction["explanation"],
    }

    risk = profile.get("risk")
    if not isinstance(risk, dict) or risk.get("score") is None:
        vr = profile.get("verified_configuration_risk") or {}
        risk = {
            "score": vr.get("score"),
            "level": vr.get("level"),
            "penalty_points": vr.get("penalty_points"),
            "evidence_completeness": profile.get("evidence_completeness"),
        }

    residual = profile.get("residual_threats") or []
    sensor = contract.get("sensor") or {}
    source = str(state_file) if state_file else "monitor/state/live_profiles.json"
    return {
        "analysis_version": "live-monitor-v1",
        "generated_at": _iso(contract.get("generated_at")),
        "input": {"type": "live_monitor", "source": source, "extraction_error": None},
        "components": {
            "model_version": tp.get("model_version", "unknown"),
            "security_version": "phase5-v1",
            "report_version": "live-monitor-v1",
            "monitor": contract.get("monitor", "monitor-v1"),
        },
        "protocol_analysis": {
            "fields": fields,
            "values": {k: v["value"] for k, v in fields.items() if v["value"] is not None},
        },
        "traffic_analysis": traffic_analysis,
        "security_assessment": {
            "security_findings": profile.get("findings") or [],
            "vpn_characteristics": {"fields": fields},
            "risk": risk,
            "limitations": _limitations(profile, contract),
        },
        "risk": risk,
        "threat_matrix": residual,
        "residual_threats": residual,
        "evidence_summary": {
            "sources": ["live monitor state"],
            "field_count": len(fields),
            "unknown_fields": profile.get("unknown_fields") or [],
        },
        "limitations": _limitations(profile, contract),
        "provenance": {
            "data_source": "live passive monitor state",
            "state_file": source,
            "sensor_status": sensor.get("status"),
            "sensor_link": sensor.get("link"),
            "sensor_last_packet": _iso(sensor.get("last_packet_ts")),
            "monitor_generated_at": _iso(contract.get("generated_at")),
            "heartbeat_ts": _iso(contract.get("heartbeat_ts")),
            "heartbeat_age_seconds": contract.get("heartbeat_age"),
            "live_state": contract.get("live_state", "unknown"),
            "live_state_reason": contract.get("live_state_reason", ""),
        },
        "live_state": contract.get("live_state", "unknown"),
        "live_state_reason": contract.get("live_state_reason", ""),
    }
