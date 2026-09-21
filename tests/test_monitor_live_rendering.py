"""Semantic live-dashboard rendering tests."""

from monitor.dashboard import render_live


def _profile(traffic, completeness=0.222, score=0, level="low", last_ts=1788505254.075401):
    return {
        "profile_id": "10.77.0.10<->10.77.0.20",
        "gateways": ["10.77.0.10", "10.77.0.20"],
        "status": "Active",
        "first_seen": last_ts,
        "last_seen": last_ts + 10,
        "last_evidence_update": last_ts,
        "packets": 200,
        "fields": {
            "protocol": {"value": "ESP", "provenance": "Observed", "source": "ESP packet", "first_seen": last_ts, "last_seen": last_ts},
            "outer_ip_version": {"value": "IPv4", "provenance": "Observed", "source": "IP header", "first_seen": last_ts, "last_seen": last_ts},
            "ike_version": {"value": "Unknown", "provenance": "Unknown", "source": "IKE packet", "first_seen": None, "last_seen": None, "reason": "No IKE negotiation captured yet."},
            "natt": {"value": "Unknown", "provenance": "Unknown", "source": "UDP 4500", "first_seen": None, "last_seen": None, "reason": "Not observable"},
            "spis": {"value": ["c203a33e", "cf34a920"], "provenance": "Observed", "source": "ESP/AH header", "first_seen": last_ts, "last_seen": last_ts + 10},
            "rekey_status": {"value": "no_rekey", "provenance": "Derived", "source": "SPI timeline", "first_seen": last_ts, "last_seen": last_ts + 10, "reason": "<=2 directional SPIs (normal SA pair)"},
            "child_encryption": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "encryption_key_length": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "integrity_algorithm": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "child_dh_group": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "pfs": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "mode": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "replay": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "lifetime": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "Not observable from current passive evidence"},
            "ike_proposal": {"value": "Unknown", "provenance": "Unknown", "source": "not observable", "first_seen": None, "last_seen": None, "reason": "No unencrypted IKE_SA_INIT captured yet."},
        },
        "traffic": traffic,
        "verified_configuration_risk": {"score": score, "level": level, "penalty_points": score},
        "evidence_completeness": completeness,
        "low_evidence_warning": "Insufficient evidence for a complete VPN security assessment.",
        "residual_threats": [{"threat": "passive traffic analysis", "condition": "outer metadata visible", "risk": "moderate"}],
        "unknown_fields": ["IPSEC-IKE-001"],
        "spis": [
            {"spi": "c203a33e", "packets": 100, "bytes": 17000, "last": last_ts},
            {"spi": "cf34a920", "packets": 100, "bytes": 17000, "last": last_ts},
        ],
        "findings": [],
        "changes": [
            {"ts": last_ts, "type": "profile_created", "detail": "new gateway pair 10.77.0.10<->10.77.0.20"},
            {"ts": last_ts + 1, "type": "new_spi", "detail": "new ESP SPI c203a33e on 10.77.0.10<->10.77.0.20"},
        ],
    }


def _contract(profile, live_active=True):
    return {
        "live_active": live_active,
        "sensor": {"status": "LIVE", "link": "UNKNOWN", "stats": {"packets": 208, "esp": 200, "ike": 8, "ah": 0}, "profiles": 1, "last_packet_ts": 1788505385.703783},
        "profiles": [profile],
        "recent_events": [
            {"ts": 1788505254.075401, "kind": "esp", "spi": "c203a33e", "size": 170, "src": "10.77.0.10", "dst": "10.77.0.20"},
            {"ts": 1788505254.075685, "kind": "esp", "spi": "cf34a920", "size": 170, "src": "10.77.0.20", "dst": "10.77.0.10"},
        ],
    }


def test_no_prediction_yet_rendering():
    html = render_live(_contract(_profile({"label": "Unknown", "confidence": 0.0, "probabilities": {}, "reason": "no_prediction_yet", "explanation": "No rolling ML window has been evaluated yet."})))
    assert "Traffic classification: Not evaluated yet" in html
    assert "No rolling ML window has been evaluated yet." in html
    assert "Confidence:</b> <span id='ml-conf'>—</span>" in html


def test_accepted_prediction_does_not_show_no_prediction_message():
    html = render_live(_contract(_profile({"label": "icmp", "confidence": 0.715, "probabilities": {"icmp": 0.715, "web": 0.285}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."})))
    assert "Predicted traffic: ICMP" in html
    assert "Confidence:</b> <span id='ml-conf'>71.5%" in html
    assert "Status:</b> <span id='ml-status'>Accepted" in html
    assert "No rolling ML window has been evaluated yet." not in html
    assert "Model produced a prediction above the confidence threshold." in html


def test_below_threshold_is_abstention_not_no_prediction():
    html = render_live(_contract(_profile({"label": "unknown", "confidence": 0.585, "probabilities": {"web": 0.585, "icmp": 0.415}, "reason": "below_threshold", "explanation": "confidence 0.585 below threshold 0.60"})))
    assert "Predicted traffic: Unknown" in html
    assert "Status:</b> <span id='ml-status'>Abstained" in html
    assert "Top candidate: Web" in html
    assert "Threshold: 60%" in html
    assert "No rolling ML window has been evaluated yet." not in html


def test_probability_formatting_and_semantics():
    html = render_live(_contract(_profile({"label": "icmp", "confidence": 0.715, "probabilities": {"icmp": 0.715, "web": 0.285, "voip-like": 0.0}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."})))
    assert "71.5%" in html
    assert "28.5%" in html
    assert "0.0%" in html
    assert "ML inference only. Not directly observed from ESP ciphertext." in html


def test_none_and_zero_completeness_are_rendered_distinctly():
    html_none = render_live(_contract(_profile({"label": "icmp", "confidence": 0.71, "probabilities": {"icmp": 0.71, "web": 0.29}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."}, completeness=None)))
    assert "Not available" in html_none
    assert "None" not in html_none

    html_zero = render_live(_contract(_profile({"label": "icmp", "confidence": 0.71, "probabilities": {"icmp": 0.71, "web": 0.29}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."}, completeness=0.0)))
    assert "0%" in html_zero


def test_live_demo_hides_confusing_blocks_and_keeps_story():
    html = render_live(_contract(_profile({"label": "icmp", "confidence": 0.715, "probabilities": {"icmp": 0.715, "web": 0.285}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."})))
    # Risk summary now lives on the Executive report, not the live page.
    assert "SECURITY ASSESSMENT" not in html
    assert "Assessment incomplete" not in html
    assert "risk-gauge" not in html
    # Demo view: threat matrix, unknown wall, timeline, sensor facts gone.
    assert "LIVE THREAT EVIDENCE" not in html
    assert "Threat Matrix" not in html
    assert "Unknown Information" not in html
    assert "Event timeline" not in html
    assert "Sensor facts" not in html
    assert "Reason code:" not in html
    # SPI hashes hidden, Unknown rows collapsed to one honest line.
    assert "c203a33e" not in html
    assert "ike_version" not in html
    assert "honestly reported as Unknown" in html
    # Plain-language provenance kept.
    assert "AI's guess" in html
    assert "ML Inferred" not in html
    # Story pieces kept.
    assert "Predicted traffic: ICMP" in html
    assert "Telemetry stream" in html
    assert "Live feed" in html


def test_event_timestamps_human_readable_and_utf8_clean():
    html = render_live(_contract(_profile({"label": "icmp", "confidence": 0.7125, "probabilities": {"icmp": 0.7125, "web": 0.2875}, "reason": "ok", "explanation": "Model produced a prediction above the confidence threshold."})))
    assert "1788505254.075401" not in html
    assert "2026-" in html
    assert "â€”" not in html
    assert "->" in html
