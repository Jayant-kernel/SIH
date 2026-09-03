"""Session correlation + knowledge accumulation tests."""
from monitor.session import Correlator
from tests.test_monitor_ike import build_ike, T


def esp(ts, src, dst, spi):
    return {"kind": "esp", "ts": ts, "src": src, "dst": dst, "spi": spi,
            "size": 120, "ip_version": 4, "natt": False}


def ike_ev(ts, src, dst, raw):
    from monitor import ike as I
    return {"kind": "ike", "ts": ts, "src": src, "dst": dst, "size": len(raw),
            "ip_version": 4, "natt": False, "sport": 500, "dport": 500,
            "ike": I.parse_ike(raw, 500, 500)}


A, B = "10.77.0.10", "10.77.0.20"


def test_esp_only_profile_has_unknown_ike():
    c = Correlator()
    for i in range(4):
        c.ingest(esp(float(i), A, B, "aa"))
        c.ingest(esp(float(i) + 0.01, B, A, "bb"))
    assert len(c.profiles) == 1
    p = next(iter(c.profiles.values()))
    assert p["protocols"] == ["ESP"] and p["ike"]["version"] is None
    assert p["rekey_status"] in ("unknown", "no_rekey")


def test_ike_enriches_same_profile_and_preserves_history():
    c = Correlator()
    p0, _ = c.ingest(esp(10.0, A, B, "aa"))
    first = p0["first_seen"]
    req = build_ike(b"\xaa" * 8, b"\x00" * 8, 34, [(1, T)], ke_group=15)
    p1, ch1 = c.ingest(ike_ev(11.0, A, B, req))
    assert p1["profile_id"] == p0["profile_id"] and p1["first_seen"] == first
    assert p1["ike"]["version"] == 2 and len(p1["ike"]["offered"]) == 1
    assert p1["ike"]["selected"] is None  # request only: no proven selection
    assert p1["ike"]["ke_groups"] == ["MODP3072"]
    resp = build_ike(b"\xaa" * 8, b"\xbb" * 8, 34, [(1, T)], ke_group=15,
                     response=True)
    p2, _ = c.ingest(ike_ev(11.2, B, A, resp))
    assert p2["ike"]["selected"] is not None
    assert "MODP2048" in p2["ike"]["selected"]
    assert len(p2["ike"]["fingerprint_versions"]) >= 2  # history grows
    assert p2["evidence_history"][0]["ts"] == first  # earliest kept


def test_conservative_split_on_new_pair():
    c = Correlator()
    c.ingest(esp(1.0, A, B, "aa"))
    c.ingest(esp(2.0, "10.77.0.30", B, "cc"))
    assert len(c.profiles) == 2


def test_natt_and_version_change_events():
    c = Correlator()
    _, ch = c.ingest({"kind": "ike", "ts": 1.0, "src": A, "dst": B, "size": 200,
                      "ip_version": 4, "natt": True, "sport": 4500, "dport": 4500,
                      "ike": {"ok": True, "version": 2, "exchange_name": "IKE_SA_INIT",
                              "response": False, "proposals": [], "ke_groups": [],
                              "init_spi": "x"}})
    assert any(x["type"] == "natt_changed" for x in ch)
    _, ch2 = c.ingest({"kind": "ike", "ts": 2.0, "src": A, "dst": B, "size": 200,
                       "ip_version": 4, "natt": True, "sport": 500, "dport": 500,
                       "ike": {"ok": True, "version": 1, "exchange_name": "Informational",
                               "response": False, "proposals": [], "ke_groups": [],
                               "init_spi": "y"}})
    assert any(x["type"] == "ike_version_changed" for x in ch2)
