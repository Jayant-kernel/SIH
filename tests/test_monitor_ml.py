"""ML bridge tests: failure reasons first, real pipeline where deps exist."""
import json

import pytest

from monitor import ml_bridge

HAS_DEPS = True
try:
    import sklearn  # noqa
    import scapy  # noqa
except ImportError:
    HAS_DEPS = False


def test_insufficient_packets_explained():
    out = ml_bridge.analyze_window([(1.0, b"x")] * 3, 1, "nope", "nope", {"features": []}, ".")
    assert out["label"] == "Unknown" and out["reason"] == "insufficient_packets"
    assert "10" in out["explanation"] and out["probabilities"] == {}


def test_model_unavailable_explained(tmp_path):
    feats = {"capture": {"total_packets": 50}}
    doc, reason, detail = ml_bridge.predict_traffic(
        feats, ".", str(tmp_path / "missing.py"))
    assert doc is None and reason == "model_unavailable"


def test_below_threshold_keeps_unknown_with_reason(monkeypatch, tmp_path):
    low = {"traffic_prediction": {"label": "unknown", "confidence": 0.3,
                                  "probabilities": {"icmp": 0.3, "web": 0.2,
                                                    "voip-like": 0.25, "video-like": 0.25}},
           "model_version": "phase4-v1"}

    class R:
        returncode = 0
        stdout = json.dumps(low)
        stderr = ""
    monkeypatch.setattr(ml_bridge.subprocess, "run", lambda *a, **k: R())
    doc, reason, _ = ml_bridge.predict_traffic({"capture": {}}, ".", __file__)
    assert reason == "below_threshold" and doc["traffic_prediction"]["label"] == "unknown"


def test_schema_mismatch_detected(monkeypatch, tmp_path):
    thin = {"capture": {"total_packets": 50}}

    class R:
        returncode = 0
        stdout = ""
        stderr = ""
    import subprocess as sp

    def fake_run(cmd, **kw):
        if "pcap_features" in str(cmd):
            target = cmd[cmd.index("--out") + 1]
            with open(target, "w") as fh:
                json.dump(thin, fh)
            return R()
        raise AssertionError("unexpected call")
    monkeypatch.setattr(ml_bridge, "PcapWriter", lambda *a, **k: _NullWriter())
    monkeypatch.setattr(sp, "run", fake_run)
    feats, reason, detail = ml_bridge.window_to_features(
        [(float(i), b"\x00" * 60) for i in range(12)], 1, "pcap_features_stub",
        {"features": ["capture.total_packets", "capture.nope"]})
    assert feats is None and reason == "schema_mismatch"


class _NullWriter:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def write(self, *a):
        pass


@pytest.mark.skipif(not HAS_DEPS, reason="needs sklearn+scapy")
def test_real_window_through_existing_pipeline(tmp_path):
    from scapy.all import Ether, IP, UDP, Raw, wrpcap
    pkts = []
    base = 1700000000.0
    for i in range(120):
        sport = 5001 if i % 2 == 0 else 5002
        p = (Ether() / IP(src="10.77.0.10", dst="10.77.0.20") /
             UDP(sport=sport, dport=5001) / Raw(b"v" * 900))
        p.time = base + i * 0.08
        pkts.append(p)
    pcap = str(tmp_path / "w.pcap")
    wrpcap(pcap, pkts)
    import struct
    from monitor.pcapio import PcapReader
    raw = [(ts, b) for ts, b in PcapReader(pcap).packets()]
    assert len(raw) == 120
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    schema = json.load(open(root / "ml_v2" / "feature_schema.json"))
    out = ml_bridge.analyze_window(
        raw, 1, str(root / "analyzer" / "pcap_features.py"),
        str(root / "ml_v2" / "predict_traffic.py"), schema, str(root))
    assert out["reason"] in ("ok", "below_threshold")
    assert set(out["probabilities"]) == {"icmp", "web", "voip-like", "video-like"}
    assert abs(sum(out["probabilities"].values()) - 1.0) < 1e-6
