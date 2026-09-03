import json
import re
from pathlib import Path
from .schema import Evidence, RANK


def load(path):
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        if p.suffix.lower() == ".json":
            return json.loads(p.read_text(encoding="utf-8-sig"))
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _ev(out, field, value, typ, source, detail="", confidence=1.0):
    out.append(Evidence(field, value, typ, confidence, source, detail))


def parse_text(text, source, typ="directly_observed"):
    out = []
    s = text if isinstance(text, str) else json.dumps(text or {})
    if re.search(r"\bproto\s+esp\b|\bESP\s*\(|\bESP:", s, re.I):
        _ev(out, "protocol", "ESP", typ, source)
        m = re.search(r"\bspi\s*=\s*(0x[0-9a-f]+|[0-9]+)", s, re.I)
        if m:
            _ev(out, "spi", m.group(1), typ, source)
    if re.search(r"\bproto\s+ah\b|\bAH\s*\(|\bAH:", s, re.I):
        _ev(out, "protocol", "AH", typ, source)
    m = re.search(r"IKEv([12])", s, re.I)
    if m:
        _ev(out, "ike_version", int(m.group(1)), typ, source)
    if re.search(r"\bIPv6\b|\bIP6\b", s, re.I):
        _ev(out, "outer_ip_version", "IPv6", typ, source)
    elif re.search(r"\bIP\b", s, re.I):
        _ev(out, "outer_ip_version", "IPv4", typ, source)
    m = re.search(r"\b(TUNNEL|TRANSPORT)\b", s, re.I)
    if m:
        _ev(out, "mode", m.group(1).lower(), typ, source)
    m = re.search(r"(?:ESP|AH):([^\s,]+)", s, re.I)
    if m:
        proposal = m.group(1).upper().replace("_", "-")
        _ev(out, "proposal", proposal, typ, source)
        if "GCM" in proposal:
            _ev(out, "encryption_algorithm", "AES-GCM", typ, source)
            _ev(out, "aead", True, typ, source)
        elif "CBC" in proposal:
            _ev(out, "encryption_algorithm", "AES-CBC", typ, source)
            _ev(out, "aead", False, typ, source)
        km = re.search(r"(?:CBC|GCM)[_-](128|192|256)", proposal)
        if km:
            _ev(out, "encryption_key_length", int(km.group(1)), typ, source)
        sm = re.search(r"(?:SHA2|SHA)[_-]?(256|384|512)", proposal)
        if sm:
            _ev(out, "integrity_algorithm", "HMAC-SHA" + sm.group(1), typ, source)
        dm = re.search(r"(MODP|ECP)[_-]?(\d+)", proposal)
        if dm:
            _ev(out, "child_dh_group", dm.group(1).upper() + dm.group(2), typ, source)
        if dm:
            _ev(out, "pfs", True, "deterministically_derived", source, "Child-SA proposal contains DH")
        # Omitted Child-SA DH fields are not proof that PFS is disabled.
    if re.search(r"enc\s+cbc\(aes\)", s, re.I):
        _ev(out, "encryption_algorithm", "AES-CBC", typ, source)
        _ev(out, "aead", False, typ, source)
    if re.search(r"aead\s+gcm\(aes\)|gcm\(aes\)", s, re.I):
        _ev(out, "encryption_algorithm", "AES-GCM", typ, source)
        _ev(out, "aead", True, typ, source)
    m = re.search(r"(?:MODP|ECP)[_-]?(\d+)|\bDH(?: group)?\s*(?:=|:)?\s*(\d+)", s, re.I)
    if m:
        group = next(x for x in m.groups() if x)
        _ev(out, "dh_group", ("MODP" + group) if "MODP" in s.upper() else group, typ, source)
        bits = {"1024": 1024, "2048": 2048, "3072": 3072, "4096": 4096, "256": 256}.get(group)
        if bits:
            _ev(out, "dh_strength_bits", bits, typ, source)
    if re.search(r"rekeying in\s+(?:0|0s)\b|rekey\s+(?:disabled|off)", s, re.I):
        _ev(out, "rekey_configured", False, typ, source)
    elif re.search(r"rekeying in\s+\d+|CREATE_CHILD_SA", s, re.I):
        _ev(out, "rekey_configured", True, typ, source)
    if re.search(r"CREATE_CHILD_SA|child.?SA rekey|rekey observed", s, re.I):
        _ev(out, "rekey_status", "rekey_observed", "directly_observed", source)
    windows = [int(x) for x in re.findall(r"replay-window\s+(\d+)", s, re.I)]
    if windows and all(x == 0 for x in windows):
        _ev(out, "replay", "disabled", "deterministically_derived", source, "explicit replay window 0")
    elif windows and all(x > 0 for x in windows):
        _ev(out, "replay", "enabled", "deterministically_derived", source, "explicit positive replay window")
    elif windows:
        _ev(out, "replay", None, "unknown", source, "conflicting replay windows")
    for key in ("local_ts", "remote_ts"):
        m = re.search(r"\b" + key.replace("_", "\s+") + r"\s+(.+)", s, re.I)
        if m:
            _ev(out, key, m.group(1).strip(), typ, source)
    return out


def parse_features(data, source="features.json"):
    out = []
    if not isinstance(data, dict):
        return out
    cap = data.get("capture", {})
    if cap.get("esp_packets", 0):
        _ev(out, "protocol", "ESP", "directly_observed", source, "ESP packet count")
    if cap.get("ah_packets", 0):
        _ev(out, "protocol", "AH", "directly_observed", source, "AH packet count")
    if cap.get("ipv4_count", 0):
        _ev(out, "outer_ip_version", "IPv4", "directly_observed", source)
    if cap.get("ipv6_count", 0):
        _ev(out, "outer_ip_version", "IPv6", "directly_observed", source)
    ea = data.get("esp_ah", {})
    if "esp_spi_count" in ea:
        _ev(out, "esp_spi_count", ea["esp_spi_count"], "directly_observed", source)
    if "ah_spi_count" in ea:
        _ev(out, "ah_spi_count", ea["ah_spi_count"], "directly_observed", source)
    rk = data.get("rekey", {})
    status = rk.get("rekey_status")
    if status == "no_rekey":
        _ev(out, "rekey_status", "no_rekey", "deterministically_derived", source, "lifecycle evidence")
    elif status in {"rekey_observed", "possible_rekey"}:
        # Passive heuristics (SPI counts, IKE packet text) cannot prove a rekey;
        # runtime before/after SPI comparison is required to confirm one.
        _ev(out, "rekey_status", "possible_rekey", "deterministically_derived", source, "passive rekey heuristic; runtime lifecycle corroboration required")
    return out


def choose(events):
    chosen = {}
    conflicts = []
    def source_rank(source):
        source = source.lower()
        if "xfrm" in source or "swanctl" in source: return 4
        if "metadata" in source: return 3
        if "feature" in source or "tcpdump" in source or "pcap" in source: return 2
        if "phase 4" in source: return 1
        return 0
    for item in events:
        old = chosen.get(item.field)
        item_rank = (RANK[item.evidence_type], source_rank(item.source))
        old_rank = (RANK[old.evidence_type], source_rank(old.source)) if old else (-1, -1)
        if old is None or item_rank > old_rank:
            if old is not None and old.value != item.value:
                conflicts.append({"field": item.field, "chosen": item.json(), "rejected": old.json()})
            chosen[item.field] = item
        elif old.value != item.value:
            if item_rank == old_rank:
                chosen[item.field] = Evidence(item.field, None, "unknown", 0.0, "conflict", "Conflicting equal-authority evidence")
            conflicts.append({"field": item.field, "chosen": old.json(), "rejected": item.json()})
    return chosen, conflicts
