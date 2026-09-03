#!/usr/bin/env python3
"""Live dashboard contract + rendering. The contract is the tested data
interface between the monitor snapshot and the /live page."""

LABELS = {"directly_observed": "Observed",
          "deterministically_derived": "Derived",
          "ml_inferred": "ML Inferred",
          "unknown": "Unknown"}

# Fields that passive monitoring can never legitimately determine, with
# the reason shown so Unknown looks intentional, not broken.
UNKNOWN_REASONS = {
    "child_encryption": "Child-SA transforms travel inside encrypted IKE exchanges; not externally observable.",
    "encryption_key_length": "AES key length cannot be recovered from ESP ciphertext appearance.",
    "integrity_algorithm": "Child-SA integrity transform is negotiated inside protected IKE exchanges.",
    "child_dh_group": "Child-SA DH group is not externally visible from passive capture.",
    "pfs": "PFS requires negotiated/runtime evidence of a Child-SA DH exchange.",
    "mode": "Tunnel vs transport cannot be proven from passive capture alone.",
    "replay": "Replay protection is an endpoint/runtime property; not visible in ciphertext.",
    "ike_version": "No IKE negotiation captured yet (monitoring may have started mid-session).",
    "ike_proposal": "No unencrypted IKE_SA_INIT captured yet.",
    "lifetime": "SA lifetimes live on the endpoints, not on the wire.",
}


def _hist(p, field):
    """(first_seen, last_seen) for a field from evidence history."""
    ts = [e["ts"] for e in p.get("evidence_history", []) if e.get("field") == field]
    if not ts:
        return None, None
    return min(ts), max(ts)


def _field(p, field, value, provenance, source):
    first, last = _hist(p, field)
    return {"value": value, "provenance": LABELS.get(provenance, provenance),
            "source": source, "first_seen": first, "last_seen": last}


def live_contract(state):
    """Validate + shape a monitor snapshot into the /live data contract."""
    state = state or {}
    sensor = state.get("sensor", {})
    out = {"monitor": state.get("monitor", "monitor-v1"),
           "generated_at": state.get("generated_at"),
           "sensor": {"started_at": sensor.get("started_at"),
                       "last_packet_ts": sensor.get("last_packet_ts"),
                      "link": sensor.get("link"),
                      "status": sensor.get("status", "UNKNOWN"),
                      "stats": sensor.get("stats", {}),
                      "profiles": len((state.get("profiles") or {}))},
           "profiles": []}
    profiles = state.get("profiles", {})
    if isinstance(profiles, dict):
        items = list(profiles.values())
    else:
        items = list(profiles)
    for p in items:
        fields = {}
        fields["protocol"] = _field(
            p, "protocol", (p.get("protocols") or ["Unknown"])[0],
            "directly_observed" if p.get("protocols") else "unknown", "ESP/AH packet")
        ivs = p.get("ip_versions", [])
        fields["outer_ip_version"] = _field(
            p, "outer_ip_version", ("IPv%d" % ivs[0]) if ivs else "Unknown",
            "directly_observed" if ivs else "unknown", "IP header")
        ike = p.get("ike", {}) or {}
        fields["ike_version"] = _field(
            p, "ike_version", ("IKEv%d" % ike["version"]) if ike.get("version") else "Unknown",
            "directly_observed" if ike.get("version") else "unknown", "IKE packet")
        fields["natt"] = _field(p, "natt", p.get("natt"), "directly_observed"
                               if p.get("natt") is not None else "unknown", "UDP 4500")
        spis = sorted(set(list((p.get("esp_sas") or {}).keys())
                            + list((p.get("ah_sas") or {}).keys())))
        fields["spis"] = _field(p, "spi", spis or "Unknown",
                                "directly_observed" if spis else "unknown", "ESP/AH header")
        fields["rekey_status"] = _field(p, "rekey_status",
                                        p.get("rekey_status", "unknown"),
                                        "deterministically_derived"
                                        if p.get("rekey_status", "unknown") != "unknown"
                                        else "unknown", "SPI timeline")
        for uf, reason in UNKNOWN_REASONS.items():
            if uf in ("ike_version", "ike_proposal"):
                continue
            fields[uf] = {"value": "Unknown", "provenance": "Unknown",
                          "source": "not observable", "first_seen": None,
                          "last_seen": None, "reason": reason}
        if not ike.get("version"):
            fields["ike_version"]["reason"] = UNKNOWN_REASONS["ike_version"]
        if not ike.get("offered"):
            fields["ike_proposal"] = {
                "value": "Unknown", "provenance": "Unknown",
                "source": "not observable", "first_seen": None, "last_seen": None,
                "reason": UNKNOWN_REASONS["ike_proposal"]}
        else:
            fields["ike_proposal"] = _field(p, "ike_offered_proposal",
                                            ike.get("offered"), "directly_observed",
                                            "IKE_SA_INIT request")
        tp = p.get("traffic", {}) or {}
        ml = {"label": tp.get("label", "Unknown"),
              "confidence": tp.get("confidence", 0.0),
              "probabilities": tp.get("probabilities", {}),
              "provenance": "ML Inferred" if tp.get("label") not in (None, "Unknown", "") else "Unknown",
              "reason": tp.get("reason", "no_prediction_yet"),
              "explanation": tp.get("explanation", "")}
        sec = p.get("security", {}) or {}
        vr = sec.get("verified_configuration_risk", {})
        out["profiles"].append({
            "profile_id": p.get("profile_id"),
            "gateways": [p.get("gateway_a"), p.get("gateway_b")],
            "status": "Active",
            "first_seen": p.get("first_seen"), "last_seen": p.get("last_seen"),
            "last_evidence_update": p.get("last_evidence_update"),
            "packets": p.get("packets", 0),
            "fields": fields,
            "ike_fingerprint": (ike.get("fingerprint_versions") or [None])[-1],
            "traffic": ml,
            "verified_configuration_risk": {
                "score": vr.get("score"), "level": vr.get("level"),
                "penalty_points": vr.get("penalty_points")},
            "evidence_completeness": sec.get("evidence_completeness"),
            "low_evidence_warning": sec.get("low_evidence_warning", ""),
            "residual_threats": sec.get("residual_threats", []),
            "unknown_fields": sec.get("unknown_fields", []),
            "changes": (p.get("change_history") or [])[-20:],
        })
    return out


def render_live(contract):
    h = ["<meta http-equiv='refresh' content='2'><h2>Live IPsec Monitor</h2>"]
    s = contract.get("sensor", {})
    st = s.get("stats", {})
    h.append("<h3>Sensor</h3><table><tr><th>Status</th><th>Link</th><th>Packets</th>"
             "<th>ESP</th><th>IKE</th><th>Profiles</th></tr><tr><td>%s</td><td>%s</td>"
             "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr></table>" % (
                 s.get("status"), s.get("link"), st.get("packets"),
                 st.get("esp"), st.get("ike"), s.get("profiles")))
    for p in contract.get("profiles", []):
        h.append("<h3>VPN Tunnel: %s</h3>" % (p["profile_id"],))
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                k, ("Unknown" if v.get("value") in (None, "", []) else v.get("value")),
                v.get("provenance"), v.get("source"),
                ("-" if v.get("first_seen") is None else v.get("first_seen")),
                ("-" if v.get("last_seen") is None else v.get("last_seen")))
            for k, v in p["fields"].items())
        h.append("<table><tr><th>Field</th><th>Value</th><th>Provenance</th>"
                 "<th>Source</th><th>First seen</th><th>Last seen</th></tr>%s</table>" % rows)
        t = p["traffic"]
        h.append("<h4>Traffic (ML Inferred)</h4><p>%s (confidence %.2f, reason: %s — %s)</p>" % (
            t.get("label"), t.get("confidence", 0.0), t.get("reason"), t.get("explanation")))
        probs = "".join("<tr><td>%s</td><td>%.4f</td></tr>" % kv
                        for kv in (t.get("probabilities") or {}).items())
        if probs:
            h.append("<table><tr><th>Class</th><th>Probability</th></tr>%s</table>" % probs)
        vr = p.get("verified_configuration_risk", {})
        h.append("<h4>Verified Configuration Risk: %s (%s)</h4>" % (
            vr.get("score"), vr.get("level")))
        h.append("<p>Evidence completeness: %s</p>" % p.get("evidence_completeness"))
        if p.get("low_evidence_warning"):
            h.append("<p><b>%s</b></p>" % p["low_evidence_warning"])
        for r in p.get("residual_threats", []):
            h.append("<p>Residual threat: %s — %s (%s)</p>" % (
                r.get("threat"), r.get("condition"), r.get("risk")))
        unk = "".join(
            "<tr><td>%s</td><td>%s</td></tr>" % (
                k, p["fields"][k].get("reason", "insufficient evidence"))
            for k in ("child_encryption", "pfs", "replay") if k in p["fields"])
        h.append("<h4>Unknown Information (intentional abstentions)</h4>"
                 "<table><tr><th>Field</th><th>Reason</th></tr>%s</table>" % unk)
        ch = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            c.get("ts"), c.get("type"), c.get("detail")) for c in p.get("changes", []))
        if ch:
            h.append("<h4>Change History</h4><table><tr><th>Time</th><th>Type</th>"
                     "<th>Detail</th></tr>%s</table>" % ch)
    if not contract.get("profiles"):
        h.append("<p>No VPN profiles yet. Waiting for IKE/ESP/AH traffic…</p>")
    return "".join(h)
