#!/usr/bin/env python3
"""Passive IKE parser (stdlib struct only).

Extracts ONLY what is legitimately visible on the wire: header fields,
exchange type, direction flags, and transforms inside UNENCRYPTED
payloads (IKE_SA_INIT SA/KE). Offered proposals and the responder's
selected IKE proposal are kept strictly separate; Child-SA parameters
are never inferred here (CREATE_CHILD_SA bodies are encrypted).
Unknown numeric IDs are reported numerically, never guessed.
"""
import struct

# IKEv2 exchange types (RFC 7296)
EXCH_V2 = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
           37: "INFORMATIONAL"}
# IKEv1 exchange types (RFC 2408)
EXCH_V1 = {1: "Base", 2: "Identity Protection", 3: "Authentication Only",
           4: "Aggressive", 5: "Informational"}

# IKEv2 payload types
PL_V2 = {0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT",
         38: "CERTREQ", 39: "AUTH", 40: "Ni", 41: "Nr", 42: "D", 43: "VID",
         44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP"}

TRANSFORM_TYPES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}

ENCR_IDS = {1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA",
            6: "CAST", 7: "BLOWFISH", 8: "3IDEA", 9: "DES-IV32",
            10: "NULL", 11: "AES-CBC", 12: "AES-CTR", 13: "AES-CCM-8",
            14: "AES-CCM-12", 15: "AES-CCM-16", 16: "AES-GCM-8",
            17: "AES-GCM-12", 18: "AES-GCM-16", 19: "AES-GCM-16",
            20: "AES-GCM-16", 21: "ChaCha20-Poly1305"}
PRF_IDS = {1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-TIGER", 4: "AES128-XCBC",
           5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512",
           8: "AES128-CMAC"}
INTEG_IDS = {0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96",
             12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192",
             14: "HMAC-SHA2-512-256"}
DH_IDS = {1: "MODP768", 2: "MODP1024", 5: "MODP1536", 14: "MODP2048",
          15: "MODP3072", 16: "MODP4096", 17: "MODP6144", 18: "MODP8192",
          19: "ECP256", 20: "ECP384", 21: "ECP521", 22: "MODP1024s160",
          23: "MODP2048s224", 24: "MODP2048s256", 25: "ECP192", 26: "ECP224",
          27: "BrainpoolP224", 28: "BrainpoolP256", 29: "BrainpoolP384",
          30: "BrainpoolP512", 31: "Curve25519", 32: "Curve448"}
ID_TABLES = {1: ENCR_IDS, 2: PRF_IDS, 3: INTEG_IDS, 4: DH_IDS}

FLAG_INITIATOR = 0x08
FLAG_VERSION = 0x10
FLAG_RESPONSE = 0x20

KEYLEN_ATTR = 14


def _tname(ttype, tid):
    table = ID_TABLES.get(ttype, {})
    return table.get(tid, "ID(%d)" % tid)


def _walk_payloads(body, first):
    """Yield (ptype, payload_bytes). Stops safely on truncation."""
    off = 0
    ptype = first
    truncated = False
    while ptype != 0:
        if off + 4 > len(body):
            truncated = True
            break
        _next, _flags, plen = struct.unpack("!BBH", body[off:off + 4])
        if plen < 4 or off + plen > len(body):
            truncated = True
            break
        yield ptype, body[off + 4:off + plen]
        off += plen
        ptype = _next
    return truncated


def _parse_sa(data):
    """Parse v2 SA payload data into proposal list. Best-effort, bounds-checked."""
    proposals = []
    off = 0
    while off + 8 <= len(data):
        _next, _res, plen = struct.unpack("!BBH", data[off:off + 4])
        if plen < 8 or off + plen > len(data):
            break
        pno, proto, spi_sz, ntrans = struct.unpack("!BBBB", data[off + 4:off + 8])
        spi = data[off + 8:off + 8 + spi_sz].hex() if spi_sz else ""
        toff = off + 8 + spi_sz
        transforms = []
        for _ in range(ntrans):
            if toff + 8 > off + plen:
                break
            _tn, _tr, tlen = struct.unpack("!BBH", data[toff:toff + 4])
            if tlen < 8 or toff + tlen > off + plen:
                break
            ttype, _r, tid = struct.unpack("!BBH", data[toff + 4:toff + 8])
            attrs = {}
            aoff = toff + 8
            while aoff + 4 <= toff + tlen:
                atype, aval = struct.unpack("!HH", data[aoff:aoff + 4])
                if atype & 0x8000:
                    if (atype & 0x7FFF) == KEYLEN_ATTR:
                        attrs["keylen"] = aval
                    aoff += 4
                else:
                    aoff += 4 + aval
            transforms.append({"type": TRANSFORM_TYPES.get(ttype, "TYPE(%d)" % ttype),
                               "type_id": ttype, "id": tid,
                               "name": _tname(ttype, tid), "attrs": attrs})
            toff += tlen
        proposals.append({"proposal_no": pno, "protocol_id": proto,
                          "protocol": {1: "IKE", 2: "AH", 3: "ESP"}.get(proto, "PROTO(%d)" % proto),
                          "spi": spi, "transforms": transforms})
        off += plen
        if _next == 0:
            break
    return proposals


def parse_ike(payload, sport=None, dport=None):
    """Parse an IKE UDP payload. Returns dict with ok=True/False.

    Never raises on malformed input; undecodable input yields ok=False
    (caller records it as malformed, not as evidence).
    """
    out = {"ok": False, "version": None, "exchange": None, "exchange_name": "UNKNOWN",
           "initiator": None, "response": None, "message_id": None,
           "init_spi": "", "resp_spi": "", "proposals": [], "ke_groups": [],
           "truncated": False, "error": ""}
    try:
        if len(payload) < 28:
            out["error"] = "short header"
            return out
        init_spi = payload[0:8].hex()
        resp_spi = payload[8:16].hex()
        first, ver, exch, flags = struct.unpack("!BBBB", payload[16:20])
        major = ver >> 4
        if major not in (1, 2):
            out["error"] = "bad version 0x%02x" % ver
            return out
        msg_id, _length = struct.unpack("!II", payload[20:28])
        body = payload[28:]
        out.update(ok=True, version=major,
                   exchange=exch,
                   exchange_name=(EXCH_V2 if major == 2 else EXCH_V1).get(exch, "EXCH(%d)" % exch),
                   initiator=bool(flags & FLAG_INITIATOR),
                   response=bool(flags & FLAG_RESPONSE),
                   message_id=msg_id, init_spi=init_spi, resp_spi=resp_spi)
        truncated = False
        off = 0
        ptype = first
        while ptype != 0:
            if off + 4 > len(body):
                truncated = True
                break
            _next, _fl, plen = struct.unpack("!BBH", body[off:off + 4])
            if plen < 4 or off + plen > len(body):
                truncated = True
                break
            pdata = body[off + 4:off + plen]
            if major == 2 and ptype == 33:
                out["proposals"] = _parse_sa(pdata)
            elif major == 2 and ptype == 34 and len(pdata) >= 2:
                # KE payload: group num (2 octets) then key data (not stored).
                out["ke_groups"].append(struct.unpack("!H", pdata[0:2])[0])
            off += plen
            ptype = _next
        out["truncated"] = truncated
        return out
    except (struct.error, IndexError, ValueError) as exc:
        out["error"] = "parse: %s" % exc
        return out
