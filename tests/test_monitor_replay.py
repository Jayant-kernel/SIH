"""Replay parity + dashboard contract tests.

Same synthetic capture through the static reader and through the
follow/tail reader must yield identical profiles (one pipeline).
The /live contract must carry provenance, first/last seen, reasons.
"""
import json
import struct
import threading

from monitor.monitor import Monitor
from monitor.pcapio import PcapReader, PcapWriter
from monitor.dashboard import live_contract
from tests.test_monitor_ike import build_ike, T

A, B = "10.77.0.10", "10.77.0.20"


def ip(a):
    return bytes(int(x) for x in a.split("."))


def frame(src, dst, proto, payload):
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ih = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0,
                     64, proto, 0, ip(src), ip(dst))
    return eth + ih + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def synth_pcap(path):
    t = 1000.0
    recs = []
    req = build_ike(b"\x11" * 8, b"\x00" * 8, 34, [(1, T)], ke_group=15)
    recs.append((t, frame(A, B, 17, udp(500, 500, req))))
    resp = build_ike(b"\x11" * 8, b"\x22" * 8, 34, [(1, T)], ke_group=15,
                     response=True)
    recs.append((t + 0.1, frame(B, A, 17, udp(500, 500, resp))))
    for i in range(30):
        recs.append((t + 1 + i * 0.05,
                     frame(A, B, 50, struct.pack("!I", 0xAAAA) + b"\xe0" * 100)))
        recs.append((t + 1 + i * 0.05 + 0.01,
                     frame(B, A, 50, struct.pack("!I", 0xBBBB) + b"\xe0" * 100)))
    with PcapWriter(str(path)) as w:
        for ts, raw in recs:
            w.write(ts, raw)
    return recs


def run_monitor(path, tmp_state, follow=False, do_ml=False):
    import tempfile
    state = str(tmp_state)
    mon = Monitor(state_dir=state, analyzer_path="x", cli_path="x",
                  schema={"features": []}, policy={}, do_ml=do_ml)
    if follow:
        stop = threading.Event()
        reader = PcapReader(str(path), follow=True, stop_event=stop)
    else:
        reader = PcapReader(str(path))
    snap = mon.process_stream(reader, max_packets=62 if follow else None)
    mon.store.save_snapshot({**snap, "monitor": "monitor-v1",
                             "sensor": {"started_at": 0, "link": "EN10MB",
                                        "status": "DONE", "stats": mon.stats}})
    return mon.store.snapshot_path


def canon(snapshot_path):
    snap = json.load(open(snapshot_path))
    profs = snap["profiles"]
    profs = list(profs.values()) if isinstance(profs, dict) else profs
    assert len(profs) == 1
    p = profs[0]
    return {"proto": p["protocols"], "ike": p["ike"]["version"],
            "offered": p["ike"]["offered"], "selected": p["ike"]["selected"],
            "ke": p["ike"]["ke_groups"], "spis": sorted(p["esp_sas"]),
            "rekey": p["rekey_status"], "n": p["packets"]}


def test_replay_parity_static_vs_follow(tmp_path):
    pcap = tmp_path / "s.pcap"
    synth_pcap(pcap)
    s1 = run_monitor(pcap, tmp_path / "s1")
    s2 = run_monitor(pcap, tmp_path / "s2", follow=True)
    c1, c2 = canon(s1), canon(s2)
    assert c1 == c2
    assert c1["proto"] == ["ESP"] and c1["ike"] == 2
    assert c1["spis"] == ["0000aaaa", "0000bbbb"] and c1["rekey"] in ("unknown", "no_rekey")


def test_dashboard_contract(tmp_path):
    pcap = tmp_path / "s.pcap"
    synth_pcap(pcap)
    s1 = run_monitor(pcap, tmp_path / "s1")
    snap = json.load(open(s1))
    contract = live_contract(snap)
    assert contract["sensor"]["stats"]["packets"] == 62
    assert len(contract["profiles"]) == 1
    p = contract["profiles"][0]
    assert p["fields"]["protocol"]["provenance"] == "Observed"
    assert p["fields"]["ike_version"]["value"] == "IKEv2"
    for uf in ("child_encryption", "pfs", "replay"):
        assert p["fields"][uf]["value"] == "Unknown"
        assert p["fields"][uf]["reason"]
    assert p["traffic"]["reason"] in ("no_prediction_yet", "insufficient_packets")
    assert p["traffic"]["explanation"]
    assert p["fields"]["spis"]["first_seen"] is not None
