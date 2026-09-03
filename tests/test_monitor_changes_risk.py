"""Change detection + continuous risk semantics tests."""
import json
from pathlib import Path

from monitor import security_bridge
from monitor.changes import ChurnWatch, traffic_shift
from monitor.session import Correlator

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.load(open(ROOT / "security" / "policy" / "default_policy.json"))
A, B = "10.77.0.10", "10.77.0.20"


def esp_profile(n=30):
    c = Correlator()
    for i in range(n):
        c.ingest({"kind": "esp", "ts": float(i), "src": A, "dst": B,
                  "spi": "aa", "size": 120, "ip_version": 4, "natt": True})
        c.ingest({"kind": "esp", "ts": float(i) + 0.01, "src": B, "dst": A,
                  "spi": "bb", "size": 120, "ip_version": 4, "natt": True})
    return next(iter(c.profiles.values()))


def test_unknown_never_becomes_failure():
    p = esp_profile()
    rep = security_bridge.assess_profile(p, POLICY)
    fails = [f for f in rep["findings"] if f["status"] == "fail"]
    assert fails == []
    assert rep["verified_configuration_risk"]["score"] == 0
    assert rep["evidence_completeness"] < 0.5
    assert "Insufficient evidence" in rep["low_evidence_warning"]
    assert any(t["threat"] == "passive traffic analysis"
               for t in rep["residual_threats"])


def test_verified_vs_residual_split():
    p = esp_profile()
    rep = security_bridge.assess_profile(p, POLICY)
    assert "verified_configuration_risk" in rep
    assert rep["residual_threats"][0]["risk"] == "moderate"
    assert "IPSEC-ENC-001" in rep["unknown_fields"]


def test_new_spi_change_has_provenance():
    c = Correlator()
    _, ch = c.ingest({"kind": "esp", "ts": 1.0, "src": A, "dst": B,
                      "spi": "aa", "size": 100, "ip_version": 4, "natt": False})
    assert ch[0]["type"] in ("profile_created", "new_spi")
    assert ch[0]["provenance"] == "directly_observed"


def test_traffic_shift_and_churn():
    assert traffic_shift(9.0, "icmp", {"label": "video-like", "confidence": 0.9})["type"] == "traffic_shift"
    assert traffic_shift(9.0, "icmp", {"label": "Unknown", "confidence": 0.2}) is None
    assert traffic_shift(9.0, "icmp", {"label": "icmp", "confidence": 0.9}) is None
    w = ChurnWatch(threshold=3, window=60.0)
    assert w.note(1.0) is None and w.note(2.0) is None
    hit = w.note(3.0)
    assert hit and hit["type"] == "spi_churn" and hit["provenance"] == "deterministically_derived"


def test_ike_enrichment_keeps_evidence_history():
    c = Correlator()
    p, _ = c.ingest({"kind": "esp", "ts": 5.0, "src": A, "dst": B,
                     "spi": "aa", "size": 100, "ip_version": 4, "natt": False})
    n0 = len(p["evidence_history"])
    c.ingest({"kind": "ike", "ts": 6.0, "src": A, "dst": B, "size": 300,
              "ip_version": 4, "natt": False, "sport": 500, "dport": 500,
              "ike": {"ok": True, "version": 2, "exchange_name": "IKE_SA_INIT",
                      "response": False, "proposals": [], "ke_groups": [15],
                      "init_spi": "q"}})
    assert len(p["evidence_history"]) > n0
    assert p["first_seen"] == 5.0
