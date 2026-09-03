#!/usr/bin/env python3
"""Passive L2-L4 classification (stdlib struct only).

Emits packet events with header metadata ONLY. Payload bytes are never
retained or decrypted; only lengths are recorded.
"""
import struct

ESP = 50
AH = 51
UDP = 17

KINDS = ("esp", "ah", "ike", "other")


def _u16(b, o):
    return struct.unpack("!H", b[o:o + 2])[0]


def _ip_str(version, raw):
    if version == 4:
        return ".".join(str(x) for x in raw)
    return ":".join("%x" % _u16(raw, i) for i in range(0, 16, 2))


def parse_frame(raw, linktype=1, ts=0.0):
    """Return event dict or None if unparseable. Never raises on bad input."""
    try:
        return _parse_frame(raw, linktype, ts)
    except (IndexError, struct.error, ValueError):
        return None


def _parse_frame(raw, linktype, ts):
    if linktype == 1:  # Ethernet
        if len(raw) < 14:
            return None
        etype = _u16(raw, 12)
        off = 14
    elif linktype == 113:  # Linux cooked v1: proto at 14:16
        if len(raw) < 16:
            return None
        etype = _u16(raw, 14)
        off = 16
    elif linktype in (101, 228, 229, 12):
        etype = None
        off = 0
    else:
        return None
    if etype is None:
        if len(raw) < 1:
            return None
        version = raw[0] >> 4
    elif etype == 0x0800:
        version = 4
    elif etype == 0x86DD:
        version = 6
    else:
        return None
    if version == 4:
        if len(raw) < off + 20:
            return None
        ihl = (raw[off] & 0x0F) * 4
        proto = raw[off + 9]
        src = _ip_str(4, raw[off + 12:off + 16])
        dst = _ip_str(4, raw[off + 16:off + 20])
        body = off + ihl
    else:
        if len(raw) < off + 40:
            return None
        nh = raw[off + 6]
        src = _ip_str(6, raw[off + 8:off + 24])
        dst = _ip_str(6, raw[off + 24:off + 40])
        body = off + 40
        # Walk a short extension-header chain (hop-by-hop 0, routing 43, fragment 44, dest 60).
        for _ in range(4):
            if nh in (0, 43, 60):
                if len(raw) < body + 2:
                    return None
                nh = raw[body]
                body += (raw[body + 1] + 1) * 8
            elif nh == 44:
                if len(raw) < body + 8:
                    return None
                nh = raw[body]
                body += 8
            else:
                break
        proto = nh
    size = len(raw)
    base = {"ts": ts, "ip_version": version, "src": src, "dst": dst,
            "size": size, "linktype": linktype}
    if proto == ESP:
        if len(raw) < body + 4:
            return None
        base.update(kind="esp", spi=raw[body:body + 4].hex(),
                    sport=None, dport=None, natt=False)
        return base
    if proto == AH:
        if len(raw) < body + 8:
            return None
        base.update(kind="ah", spi=raw[body + 4:body + 8].hex(),
                    sport=None, dport=None, natt=False)
        return base
    if proto == UDP:
        if len(raw) < body + 8:
            return None
        sport = _u16(raw, body)
        dport = _u16(raw, body + 2)
        payload = raw[body + 8:]
        base.update(sport=sport, dport=dport)
        if sport in (500, 4500) or dport in (500, 4500):
            if dport == 500 or sport == 500:
                base.update(kind="ike", spi=None, natt=False)
                return base
            # UDP 4500: non-ESP marker (4 zero bytes) => IKE; else NAT-T ESP.
            if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                base.update(kind="ike", spi=None, natt=True)
                return base
            if len(payload) >= 4:
                base.update(kind="esp", spi=payload[:4].hex(), natt=True)
                return base
            return None
        base.update(kind="other", spi=None, natt=False)
        return base
    base.update(kind="other", spi=None, sport=None, dport=None, natt=False)
    return base
