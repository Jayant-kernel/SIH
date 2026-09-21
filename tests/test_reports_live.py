"""Live executive/technical report tests.

Verifies the dashboard report routes read the CURRENT monitor state,
use the authoritative risk/completeness values, surface residual
threats and provenance, keep unknowns unknown, and honestly report
stale or unavailable state.
"""
import json
import threading
import time
import urllib.request
from http.server import HTTPServer
from pathlib import Path

from monitor import security_bridge
from monitor.dashboard import live_contract, render_live
from monitor.report_bridge import live_report_input

ROOT = Path(__file__).resolve().parents[1]


def _state():
    profile = {
        "profile_id": "10.77.0.10<->10.77.0.20",
        "gateway_a": "10.77.0.10", "gateway_b": "10.77.0.20",
        "first_seen": 1788512639.2, "last_seen": 1788512740.5,
        "last_evidence_update": 1788512639.2,
        "packets": 200, "observations": 4,
        "protocols": ["ESP"], "ip_versions": [4], "natt": None,
        "ike": {"version": None, "exchanges": [], "offered": [],
                "selected": None, "ke_groups": [], "sessions": {},
                "fingerprint_versions": []},
        "esp_sas": {"c1060cec": {"first": 1.0, "last": 2.0, "packets": 100,
                                 "bytes": 17000, "retired": True}},
        "ah_sas": {}, "rekey_status": "no_rekey",
        "rekey_evidence": ["<=2 directional SPIs (normal SA pair)"],
        "traffic": {
            "window_packets": 20, "window_seconds": 9.2, "label": "icmp",
            "confidence": 0.72,
            "probabilities": {"icmp": 0.72, "web": 0.28},
            "model_version": "phase4-v1", "reason": "ok",
            "explanation": "Model produced a prediction above the confidence threshold. ",
        },
    }
    policy = json.loads(
        (ROOT / "security" / "policy" / "default_policy.json").read_text(encoding="utf-8"))
    profile["security"] = security_bridge.assess_profile(profile, policy)
    return {
        "monitor": "monitor-v1",
        "sensor": {"started_at": 1788512517.0, "status": "LIVE", "link": "UNKNOWN",
                   "last_packet_ts": 1788516498.2,
                   "stats": {"packets": 319, "esp": 200, "ah": 0, "ike": 119,
                             "other": 0, "malformed": 119}},
        "generated_at": 1788516499.5,
        "profiles": [profile],
    }


def _write_state_dir(tmp_path, state, heartbeat_status="LIVE", heartbeat_age=0):
    (tmp_path / "live_profiles.json").write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / "heartbeat.json").write_text(
        json.dumps({"status": heartbeat_status, "ts": time.time() - heartbeat_age}),
        encoding="utf-8")
    return tmp_path / "live_profiles.json"


def _serve(state_path):
    import app.app as appmod
    appmod.LIVE_STATE = Path(state_path)
    srv = HTTPServer(("127.0.0.1", 0), appmod.Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05})
    thread.daemon = True
    thread.start()
    return srv, thread, port


def _get(port, path):
    return urllib.request.urlopen(
        "http://127.0.0.1:%d%s" % (port, path), timeout=10).read().decode()


def test_executive_route_uses_live_state(tmp_path):
    state = _state()
    path = _write_state_dir(tmp_path, state)
    srv, thread, port = _serve(path)
    try:
        body = _get(port, "/executive")
    finally:
        srv.shutdown(); thread.join(timeout=5)
    src = state["profiles"][0]["security"]
    assert "IPsec VPN Executive Assessment" in body
    assert "Verified configuration risk" in body       # risk gauge block moved here
    assert "<b>%d</b>" % src["risk"]["score"] in body  # seal renders the score
    assert "Evidence completeness: <b>" in body
    assert "%</b>" in body                             # completeness as percent
    assert "What an outsider can still see" in body    # single-statement threats
    assert "Threat matrix" not in body                 # tables removed for demo
    assert "Data provenance" not in body               # provenance removed for demo
    assert "reason code" not in body                   # jargon removed
    assert "AI's guess" in body                        # plain-language traffic verdict
    assert "LIVE SENSOR" in body                       # fresh banner
    assert "href='/live'" in body                      # back navigation present
    assert "aria-current='page'" in body               # active nav state


def test_executive_report_summarises_threats_in_plain_words():
    from reports.generate_report import executive
    state = _state()
    result = live_report_input(live_contract(state), "monitor/state/live_profiles.json")
    body = executive(result)
    assert "What an outsider can still see" in body    # single-statement threats
    assert "stay encrypted" in body
    assert "Observed on the wire" in body              # technical detail sub-line
    assert "Runner-up" in body                         # runner-up detail sub-line
    assert "Penalty score" in body                     # risk mini tiles
    assert "<h2>Threat matrix</h2>" not in body
    assert ">directly_observed<" not in body           # no raw slugs in content


def test_technical_route_uses_live_state(tmp_path):
    state = _state()
    path = _write_state_dir(tmp_path, state)
    srv, thread, port = _serve(path)
    try:
        body = _get(port, "/technical")
    finally:
        srv.shutdown(); thread.join(timeout=5)
    assert "IPsec VPN Technical Assessment" in body
    assert "live-monitor-v1" in body
    assert "ESP" in body                               # observed protocol field
    assert "icmp" in body and "72.0%" in body          # ML output as plain verdict
    assert "What an outsider can still see" in body    # single-statement threats
    assert "How it works" in body                      # live flowchart strip
    assert "AI guesses" in body
    assert "Threat matrix" not in body                 # tables removed for demo
    assert "Data provenance" not in body               # provenance removed for demo
    assert "reason code" not in body                   # jargon removed
    assert "c1060cec" not in body                      # SPI hashes hidden


def test_risk_and_completeness_match_source_state():
    state = _state()
    contract = live_contract(state)
    result = live_report_input(contract, "monitor/state/live_profiles.json")
    src = state["profiles"][0]["security"]
    assert result["risk"]["score"] == src["verified_configuration_risk"]["score"]
    assert result["risk"]["level"] == src["verified_configuration_risk"]["level"]
    assert result["risk"]["evidence_completeness"] == src["evidence_completeness"]


def test_threat_matrix_matches_live_residual_threats():
    state = _state()
    contract = live_contract(state)
    result = live_report_input(contract, "monitor/state/live_profiles.json")
    residuals = state["profiles"][0]["security"]["residual_threats"]
    assert result["threat_matrix"] == residuals
    assert result["residual_threats"] == residuals


def test_unknown_values_stay_unknown(tmp_path):
    state = _state()
    path = _write_state_dir(tmp_path, state)
    srv, thread, port = _serve(path)
    try:
        body = _get(port, "/executive")
    finally:
        srv.shutdown(); thread.join(timeout=5)
    assert "Insufficient evidence" not in body         # codes collapsed away
    unknown = state["profiles"][0]["security"]["unknown_fields"]
    assert unknown and unknown[0] not in body          # no raw check IDs on page
    assert "never guessed" in body                     # honest one-liner instead


def test_stale_state_is_reported_honestly(tmp_path):
    state = _state()
    path = _write_state_dir(tmp_path, state, heartbeat_status="LIVE", heartbeat_age=600)
    srv, thread, port = _serve(path)
    try:
        contract = json.loads(_get(port, "/live.json"))
        body = _get(port, "/executive")
    finally:
        srv.shutdown(); thread.join(timeout=5)
    assert contract["live_state"] == "stale"
    assert "STALE SNAPSHOT" in body
    assert "heartbeat is" in body


def test_unavailable_state_is_reported_honestly(tmp_path):
    missing = tmp_path / "live_profiles.json"
    srv, thread, port = _serve(missing)
    try:
        contract = json.loads(_get(port, "/live.json"))
        body = _get(port, "/technical")
    finally:
        srv.shutdown(); thread.join(timeout=5)
    assert contract["live_state"] == "unavailable"
    assert "unavailable" in body.lower()


def test_live_page_exposes_report_links_and_refresh_target():
    state = _state()
    html = render_live(live_contract(state))
    assert "href='/executive'" in html and "href='/technical'" in html
    assert "fetch('/live.json'" in html  # polling refreshes from /live.json
