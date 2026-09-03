"""IKE parser tests: v1/v2 recognition, exchanges, transforms, offered-vs-selected."""
import struct

from monitor import ike as I


def build_sa(proposals):
    """proposals: [(proto, [(ttype, tid, [(attr_type, attr_val_or_len), ...])])]."""
    out = b""
    for pi, (proto, trans) in enumerate(proposals):
        last = pi == len(proposals) - 1
        tbytes = b""
        for ti, (tt, tid, attrs) in enumerate(trans):
            ab = b""
            for at, av in attrs:
                if at & 0x8000:
                    ab += struct.pack("!HH", at, av)
                else:
                    ab += struct.pack("!HH", at, len(av)) + av
            tbytes += struct.pack("!BBHBBH", 3 if ti < len(trans) - 1 else 0,
                                  0, 8 + len(ab), tt, 0, tid) + ab
        out += struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(tbytes), pi + 1,
                           proto, 0, len(trans)) + tbytes
    return out


def build_ike(spi_i, spi_r, exchange, proposals=(), ke_group=None,
              response=False, version=0x20, msgid=0, nonce=b"\x11" * 16):
    body = b""
    first = 0
    if proposals:
        sa = build_sa(proposals)
        nxt = 34 if ke_group is not None else (40 if nonce else 0)
        body += struct.pack("!BBH", nxt, 0, 4 + len(sa)) + sa
        first = 33
    if ke_group is not None:
        ke = struct.pack("!H", ke_group) + b"\x22" * 32
        nxt = 40 if nonce else 0
        if not proposals:
            first = 34
        body += struct.pack("!BBH", nxt, 0, 4 + len(ke)) + ke
    if nonce:
        if not proposals and ke_group is None:
            first = 40
        body += struct.pack("!BBH", 0, 0, 4 + len(nonce)) + nonce
    flags = 0x08 if not response else 0x28
    hdr = (spi_i + spi_r + struct.pack("!BBBB", first, version, exchange, flags)
           + struct.pack("!II", msgid, 28 + len(body)))
    return hdr + body


T = [(1, 12, []), (2, 5, []), (3, 12, []), (4, 14, [])]


def test_ikev2_sa_init_request_offered():
    raw = build_ike(b"\xaa" * 8, b"\x00" * 8, 34, [ (1, T) ], ke_group=15)
    r = I.parse_ike(raw, 500, 500)
    assert r["ok"] and r["version"] == 2 and r["exchange_name"] == "IKE_SA_INIT"
    assert r["initiator"] is True and r["response"] is False
    assert len(r["proposals"]) == 1
    names = {t["type"]: t["name"] for t in r["proposals"][0]["transforms"]}
    assert names[ "ENCR"] == "AES-CTR" and names["PRF"] == "HMAC-SHA2-256"
    assert names["DH"] == "MODP2048" and r["ke_groups"] == [15]


def test_response_single_proposal_is_selected_source():
    raw = build_ike(b"\xaa" * 8, b"\xbb" * 8, 34, [(1, T)], ke_group=14,
                    response=True, msgid=0)
    r = I.parse_ike(raw, 500, 500)
    assert r["ok"] and r["response"] is True and len(r["proposals"]) == 1


def test_multi_proposal_request_and_unknown_ids():
    trans = [(1, 99, []), (2, 5, [(0x800E, 256)]), (4, 15, [])]
    raw = build_ike(b"\xaa" * 8, b"\x00" * 8, 34,
                    [(1, trans), (1, [(1, 12, [])])], ke_group=None, nonce=b"")
    r = I.parse_ike(raw, 500, 500)
    assert r["ok"] and len(r["proposals"]) == 2
    assert r["proposals"][0]["transforms"][0]["name"] == "ID(99)"
    assert r["proposals"][0]["transforms"][1]["attrs"]["keylen"] == 256


def test_ikev1_recognized():
    raw = build_ike(b"\xaa" * 8, b"\x00" * 8, 2, [], version=0x10, nonce=b"")
    r = I.parse_ike(raw, 500, 500)
    assert r["ok"] and r["version"] == 1 and r["exchange_name"] == "Identity Protection"


def test_malformed_yields_not_ok():
    assert I.parse_ike(b"\x00" * 10, 500, 500)["ok"] is False
    assert I.parse_ike(b"\x00" * 28, 500, 500)["ok"] is False
    short = build_ike(b"\xaa" * 8, b"\x00" * 8, 34, [(1, T)], ke_group=15)[:40]
    assert I.parse_ike(short, 500, 500)["truncated"] is True


def test_other_exchanges_named():
    assert I.parse_ike(build_ike(b"\xaa" * 8, b"\xbb" * 8, 36, [], nonce=b""),
                       4500, 4500)["exchange_name"] == "CREATE_CHILD_SA"
    assert I.parse_ike(build_ike(b"\xaa" * 8, b"\xbb" * 8, 37, [], nonce=b""),
                       4500, 4500)["exchange_name"] == "INFORMATIONAL"
