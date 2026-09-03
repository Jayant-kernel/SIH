"""Packet classification + flow tracking + rekey semantics tests (stdlib only)."""
import struct

from monitor import packets as P
from monitor.flows import FlowTracker, spi_lifecycle


def v4(proto, sport=0, dport=0, body=b"", src="10.77.0.10", dst="10.77.0.20"):
    def ip(a):
        return bytes(int(x) for x in a.split("."))
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ihl = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(body), 0, 0,
                      64, proto, 0, ip(src), ip(dst))
    if proto == 17:
        udp = struct.pack("!HHHH", sport, dport, 8 + len(body), 0)
        return eth + ihl + udp + body
    return eth + ihl + body


def v6(nh, body=b"", sport=0, dport=0):
    def ip6(a):
        h = a.split(":")
        return b"".join(struct.pack("!H", int(x or "0", 16)) for x in h)
    eth = b"\x00" * 12 + struct.pack("!H", 0x86DD)
    base = struct.pack("!IHBB16s16s", len(body) + (8 if nh == 17 else 0), 0,
                       nh, 64, ip6("fd77:77::10"), ip6("fd77:77::20"))
    if nh == 17:
        base += struct.pack("!HHHH", sport, dport, 8 + len(body), 0)
    return eth + base + body


def test_esp_v4_spi():
    ev = P.parse_frame(v4(50, body=struct.pack("!I", 0xDEADBEEF) + b"\x00" * 60), 1, 1.0)
    assert ev["kind"] == "esp" and ev["spi"] == "deadbeef" and ev["ip_version"] == 4


def test_ah_v4_spi():
    ev = P.parse_frame(v4(51, body=b"\x33\x04\x00\x00" + struct.pack("!I", 0x1234) + b"\x00" * 20), 1, 1.0)
    assert ev["kind"] == "ah" and ev["spi"] == "00001234"


def test_ike_500_and_natt():
    ev = P.parse_frame(v4(17, 500, 500, body=b"\xaa" * 28), 1, 1.0)
    assert ev["kind"] == "ike" and ev["natt"] is False
    ev2 = P.parse_frame(v4(17, 4500, 4500, body=b"\x00" * 4 + b"\xaa" * 28), 1, 1.0)
    assert ev2["kind"] == "ike" and ev2["natt"] is True
    ev3 = P.parse_frame(v4(17, 4500, 4500, body=struct.pack("!I", 0xBEEF) + b"\x00" * 40), 1, 1.0)
    assert ev3["kind"] == "esp" and ev3["spi"] == "0000beef" and ev3["natt"] is True


def test_esp_v6_and_malformed():
    ev = P.parse_frame(v6(50, body=struct.pack("!I", 0x11) + b"\x00" * 40), 1, 2.0)
    assert ev["kind"] == "esp" and ev["ip_version"] == 6
    assert P.parse_frame(b"\x00" * 5, 1, 0.0) is None
    assert P.parse_frame(v4(50, body=b"\x01\x02"), 1, 0.0) is None


def test_two_directional_spis_are_not_rekey():
    tr = FlowTracker()
    for i in range(10):
        tr.update({"kind": "esp", "ts": float(i), "src": "10.77.0.10",
                   "dst": "10.77.0.20", "spi": "aaaa", "size": 100})
        tr.update({"kind": "esp", "ts": float(i) + 0.01, "src": "10.77.0.20",
                   "dst": "10.77.0.10", "spi": "bbbb", "size": 100})
    rels = tr.relationships()
    assert len(rels) == 1
    status, _ev = spi_lifecycle(next(iter(rels.values()))["spis"])
    assert status == "no_rekey"


def test_temporal_transition_is_rekey_and_overlap_is_possible():
    old = {"a": {"first": 0.0, "last": 5.0}, "b": {"first": 0.0, "last": 5.0}}
    assert spi_lifecycle(dict(old, c={"first": 20.0, "last": 25.0}))[0] == "rekey_observed"
    assert spi_lifecycle(dict(old, c={"first": 2.0, "last": 8.0}))[0] == "possible_rekey"
    st, ev = spi_lifecycle(dict(old, c={"first": 2.0, "last": 8.0}), ike_rekey_times=[5.0])
    assert st == "rekey_observed" and any("CREATE_CHILD_SA" in e for e in ev)
