#!/usr/bin/env python3
"""Live dashboard contract + rendering. The contract is the tested data
interface between the monitor snapshot and the /live page."""
import html as html_lib
from datetime import datetime
from pathlib import Path
import sys
import time

from . import ml_bridge

try:
    from ui.theme import THEME_CSS
except ImportError:  # allow running from inside the monitor package
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ui.theme import THEME_CSS

# Live-only layout on top of the shared theme (tokens, panels, chips, seal).
LIVE_CSS = r"""
:root{--cyan:var(--accent);--green:var(--ok);--pink:var(--crit);--amber:var(--warn)}
.hero{padding-bottom:18px}
.net-caption{display:flex;justify-content:space-between;gap:12px;margin:0 0 10px;color:var(--muted);font:10px var(--font-mono);letter-spacing:.15em;text-transform:uppercase}
.net-caption b{color:var(--accent);font-weight:600}
#netmap{display:block;width:100%;height:442px;border:1px solid var(--line);border-radius:var(--r-lg);background:#ffffff;box-shadow:var(--sh-in)}
.phase{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:16px}
.phase>div{border:1px solid var(--line);border-radius:var(--r);padding:11px 12px;color:var(--muted);font-size:11.5px;line-height:1.4;transition:border-color .4s var(--ease),box-shadow .4s var(--ease)}
.phase>div>i{display:block;font:600 10px var(--font-mono);color:var(--dim);letter-spacing:.2em;font-style:normal;margin-bottom:5px}
.phase .done{border-color:color-mix(in srgb,var(--ok) 42%,transparent);color:var(--ink)}
.phase .active{border-color:var(--accent);color:var(--ink);box-shadow:0 0 0 3px rgba(179,78,0,.16)}
.phase .wait{opacity:.5}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--gap)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(104px,1fr));gap:12px;margin-top:4px}
.metric{background:#faf9fe;border:1px solid var(--line);border-radius:var(--r);padding:12px 13px}
.metric b{display:block;font:650 23px/1.1 var(--font-display);letter-spacing:-.02em}
.metric span{display:block;margin-top:5px;color:var(--muted);font:10px var(--font-mono);letter-spacing:.14em;text-transform:uppercase}
.signal{display:flex;align-items:flex-end;gap:3px;height:46px;margin:16px 0 10px}
.signal i{flex:1;min-height:3px;border-radius:2px;background:linear-gradient(180deg,var(--accent),rgba(179,78,0,.18));transition:height .6s var(--ease)}
.kv div{display:flex;justify-content:space-between;gap:12px;padding-bottom:8px;margin-bottom:8px;border-bottom:1px solid var(--line)}
.kv div:last-child{border-bottom:0;margin-bottom:0}
.kv label{color:var(--muted);font:600 10px/1.5 var(--font-mono);letter-spacing:.14em;text-transform:uppercase}
.kv strong{font:13px var(--font-mono);text-align:right}
.pbars{display:grid;gap:8px;margin-top:12px}
.pbar{display:grid;grid-template-columns:98px 1fr 52px;gap:9px;align-items:center;font:12px var(--font-mono)}
.pbar>.tr{height:8px;border-radius:99px;background:#ece9fa;border:1px solid var(--line);overflow:hidden}
.pbar>.tr>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,rgba(179,78,0,.48),var(--accent));transition:width .7s var(--ease)}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:var(--r-xs);border:1px solid var(--line-2);color:var(--muted);font:600 10px/1.7 var(--font-mono);letter-spacing:.06em;text-transform:uppercase}
.data-table{width:100%;border-collapse:collapse;font-size:12.5px}
.data-table th{position:sticky;top:0;background:#f3f2fb;text-align:left;padding:10px 12px;color:var(--muted);font:600 10px/1 var(--font-mono);letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid var(--line);white-space:nowrap}
.data-table td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.data-table tbody tr:hover{background:rgba(43,33,88,.04)}
.feed{display:grid;gap:8px;max-height:300px;overflow:auto;padding-right:2px}
.evt{border:1px solid var(--line);background:#faf9fe;border-radius:var(--r-sm);padding:9px 11px;font-size:11px;line-height:1.5}
.evt.in{animation:evt-in .45s var(--ease) both}
.evt b{color:var(--accent)}
.evt small{display:block;color:var(--muted);margin-top:3px;font-family:var(--font-mono)}
.evt .k{display:inline-block;min-width:42px;color:var(--ok);text-transform:uppercase;letter-spacing:.12em;font-family:var(--font-mono)}
.evt .t{color:var(--muted);font-family:var(--font-mono)}
.toast-root{position:fixed;right:22px;bottom:22px;z-index:60;display:grid;gap:8px;width:min(360px,calc(100vw - 44px))}
.toast{background:rgba(255,255,255,.97);border:1px solid var(--accent);border-radius:var(--r);padding:10px 12px;box-shadow:0 18px 40px -22px rgba(179,78,0,.8);backdrop-filter:blur(10px);animation:toast-in .2s var(--ease) both,toast-out .4s ease-in 3s both}
.toast b{color:var(--ink)}.toast small{display:block;color:var(--muted);margin-top:3px;font-family:var(--font-mono)}
.panel>h2{font-size:29px;font-weight:800;letter-spacing:-.02em}
section.panel>section h3{font-size:22px;font-weight:800;margin:0 0 16px}
#ml-label{margin:0 0 14px}
.metric b{font-size:28px}
.metric span{font-size:12px;font-weight:700}
.phase>div{font-size:14px}
.phase>div>i{font-size:12px}
.data-table th{font-size:12px;font-weight:700}
.net-caption{font-size:12px}
.net-caption b{font-weight:700}
.warn{color:var(--warn)}
.panel.live-off{opacity:.8}
.panel.wide{grid-column:1/-1}
.sev{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px}
.sev-pass{background:var(--ok)}.sev-warning{background:var(--warn)}.sev-fail{background:var(--bad)}.sev-unknown{background:var(--p-unk)}
.foot a{color:var(--accent)}
@keyframes evt-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes toast-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes toast-out{to{opacity:0;transform:translateY(8px)}}
@media(max-width:980px){.grid{grid-template-columns:1fr}.phase{grid-template-columns:repeat(2,1fr)}}
"""

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


def _spis(p):
    """Real per-SPI counters used to drive the telemetry bar chart."""
    out = []
    for key in ("esp_sas", "ah_sas"):
        for spi, sa in sorted((p.get(key) or {}).items()):
            out.append({"spi": spi, "packets": sa.get("packets", 0),
                        "bytes": sa.get("bytes", 0), "last": sa.get("last")})
    return out


def _event_html(ev):
    kind = html_lib.escape(str(ev.get("kind", "pkt")).upper())
    size = html_lib.escape(str(ev.get("size") or 0))
    src = html_lib.escape(str(ev.get("src") or "?"))
    dst = html_lib.escape(str(ev.get("dst") or "?"))
    ts = ev.get("ts")
    human_ts = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, (int, float)) else "Unknown"
    return "<div class='evt in' data-ev='%s'><span class='k'>%s</span> <b>%s bytes</b> <span class='t'>%s -> %s</span><small>%s</small></div>" % (
        html_lib.escape("%s|%s|%s|%s" % (kind, size, src, dst)), kind, size, src, dst, html_lib.escape(human_ts))


def _pretty_label(value):
    if value in (None, "", "Unknown", "unknown"):
        return "Unknown"
    s = str(value)
    mapping = {"icmp": "ICMP", "web": "Web", "voip-like": "VoIP-like", "video-like": "Video-like"}
    return mapping.get(s.lower(), s.replace("_", " ").title())


def _fmt_pct(value, digits=1):
    if value is None:
        return "Not available"
    return f"{value * 100:.{digits}f}%"


def _fmt_ts(ts):
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return "Unknown"


def _ml_view(tp):
    reason = tp.get("reason", "no_prediction_yet")
    label = tp.get("label", "Unknown")
    confidence = tp.get("confidence")
    probabilities = tp.get("probabilities") or {}
    threshold = ml_bridge.DEFAULT_THRESHOLD
    top_candidate = max(probabilities, key=probabilities.get) if probabilities else None
    top_confidence = probabilities.get(top_candidate) if top_candidate else None

    if reason == "no_prediction_yet":
        state = "Not evaluated yet"
        status = "Waiting for first ML window"
        label_text = "Traffic classification: Not evaluated yet"
        confidence_text = "—"
        reason_text = "No rolling ML window has been evaluated yet."
        detail = ""
        provenance = "Unknown"
    elif reason == "ok":
        state = "Accepted"
        status = "Prediction accepted"
        label_text = f"Predicted traffic: {_pretty_label(label)}"
        confidence_text = f"{(confidence or 0.0) * 100:.1f}%"
        reason_text = ml_bridge.REASON_TEXT.get("ok", "Prediction accepted")
        detail = ""
        provenance = "ML Inferred"
    elif reason == "below_threshold":
        state = "Abstained"
        status = "Confidence below threshold"
        label_text = f"Predicted traffic: {_pretty_label(label)}"
        confidence_text = f"{(confidence or 0.0) * 100:.1f}%"
        reason_text = f"Confidence below {threshold * 100:.0f}% acceptance threshold."
        detail = (
            f"Top candidate: {_pretty_label(top_candidate)} / Threshold: {threshold * 100:.0f}%"
            if top_candidate else f"Threshold: {threshold * 100:.0f}%"
        )
        provenance = "ML Inferred"
    else:
        state = "Unavailable"
        status = reason.replace("_", " ").title()
        label_text = f"Predicted traffic: {_pretty_label(label)}"
        confidence_text = f"{(confidence or 0.0) * 100:.1f}%" if confidence is not None else "—"
        reason_text = ml_bridge.REASON_TEXT.get(reason, reason.replace("_", " ").title())
        detail = ""
        provenance = "ML Inferred" if label not in (None, "", "Unknown", "unknown") else "Unknown"

    prob_rows = "".join(
        "<div class='pbar'><span>%s</span><span class='tr'><i style='width:%d%%'></i></span><span>%.1f%%</span></div>"
        % (_pretty_label(name), int(round(100.0 * prob)), prob * 100.0)
        for name, prob in sorted(probabilities.items(), key=lambda kv: -kv[1])
    )
    return {
        "state": state,
        "status": status,
        "label_text": label_text,
        "confidence_text": confidence_text,
        "reason_code": reason,
        "reason_text": reason_text,
        "detail": detail,
        "prob_rows": prob_rows,
        "provenance": provenance,
    }


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
            "risk": sec.get("risk", {}),
            "evidence_completeness": sec.get("evidence_completeness"),
            "low_evidence_warning": sec.get("low_evidence_warning", ""),
            "residual_threats": sec.get("residual_threats", []),
            "unknown_fields": sec.get("unknown_fields", []),
            "spis": _spis(p),
            "findings": sec.get("findings", []),
            "changes": (p.get("change_history") or [])[-20:],
        })
    return out


def render_live(contract):
    live_active = bool(contract.get("live_active", True))
    h = ["<span style='display:none'>AI-Driven IPsec VPN Security Analyzer</span><span style='display:none'>IKEv2</span>"
         "<span style='display:none'>Live IPsec Monitor</span>"
         "<style>" + THEME_CSS + LIVE_CSS + "</style>"]
    s = contract.get("sensor", {})
    st = s.get("stats", {})
    status = s.get("status", "UNKNOWN")
    packets = st.get("packets", 0)
    esp = st.get("esp", 0)
    ike_count = st.get("ike", 0)
    ah = st.get("ah", 0)
    profiles = s.get("profiles", 0)
    last_packet_raw = s.get("last_packet_ts")
    last_packet = _fmt_ts(last_packet_raw) if last_packet_raw is not None else "waiting"
    age = None
    if isinstance(last_packet_raw, (int, float)):
        age = max(0, int(time.time() - last_packet_raw))
    # Telemetry bars are REAL per-SPI packet shares, not a fixed animation.
    spi_stats = []
    for prof in contract.get("profiles", []):
        spi_stats += prof.get("spis", [])
    if spi_stats:
        mx = max(1, max(x["packets"] for x in spi_stats))
        bars = "".join("<i style='height:%d%%'></i>"
                       % (max(8, int(round(90.0 * x["packets"] / mx))))
                       for x in spi_stats)
    else:
        bars = "".join("<i style='height:4%%'></i>" for _ in range(24))
    profs = contract.get("profiles", [])
    infer_done = any((p.get("traffic") or {}).get("reason") != "no_prediction_yet"
                     for p in profs)
    assess_done = any((p.get("verified_configuration_risk") or {}).get("score") is not None
                      for p in profs)
    steps = [(status == "LIVE"), (packets or 0) > 0, infer_done, assess_done]
    phase_cls = []
    seen_wait = False
    for on in steps:
        if on:
            phase_cls.append("done")
        elif not seen_wait:
            phase_cls.append("active")
            seen_wait = True
        else:
            phase_cls.append("wait")
    h.append("<section class='panel hero%s'><div class='eyebrow'>PHASE 01 / SECURE LINK</div>"
              "<h2>%s / encrypted tunnel</h2>"
              "<div class='net-caption'><b>GATEWAY A &nbsp;&harr;&nbsp; GATEWAY B</b>"
              "<span>LIVE PASSIVE FLOW / ESP + IKE</span></div>"
              "<canvas id='netmap' aria-label='live gateway traffic map'></canvas>"
             "<div class='phase'>"
               "<div class='%s' id='ph-1'><i>01</i>CAPTURE<br>%s</div>"
             "<div class='%s' id='ph-2'><i>02</i>PARSE<br>ESP / IKE</div>"
             "<div class='%s' id='ph-3'><i>03</i>INFER<br>LOCAL ML</div>"
             "<div class='%s' id='ph-4'><i>04</i>ASSESS<br>PROVENANCE</div></div></section>"
             % (" live-off" if not live_active else "",
                "Live IPsec Monitor" if live_active else "Paused snapshot",
                phase_cls[0],
                 "LIVE" if live_active else "PAUSED",
                 phase_cls[1], phase_cls[2], phase_cls[3]))
    h.append("<div class='grid'><section class='panel wide%s'><h2>Telemetry stream</h2><div class='metrics'>"
             "<div class='metric'><b id='m-status'>%s</b><span>link state</span></div>"
             "<div class='metric'><b id='m-packets'>%s</b><span>packets</span></div><div class='metric'><b id='m-esp'>%s</b><span>ESP frames</span></div>"
             "<div class='metric'><b id='m-ike'>%s</b><span>IKE frames</span></div><div class='metric'><b id='m-profiles'>%s</b><span>active profiles</span></div>"
             "</div><div class='signal' id='signal'>%s</div><div class='foot'><span>STATUS %s</span>"
             "<span>LAST PACKET %s</span><span id='hb' class='%s'>%s</span></div></section>" %
             ((" live-off" if not live_active else ""),
              "LIVE" if live_active else "PAUSED",
              packets, esp, ike_count, profiles, bars, ("LIVE" if live_active else "PAUSED"), last_packet,
               "fresh" if (age is not None and age <= 5) else "stale",
               ("live %ss ago" % age) if age is not None else "no packets yet"))
    h.append("</div>")
    events = contract.get("recent_events") or []
    feed = "".join(_event_html(ev) for ev in events[-8:]) or "<div class='evt'><span class='k'>WAIT</span> <b>idle</b> <span class='t'>awaiting the next packet burst</span></div>"
    h.append("<section class='panel wide'><h2>Live feed</h2><div id='feed' class='feed'>%s</div></section>" % feed)
    for p in contract.get("profiles", []):
        h.append("<section class='panel wide'><div class='eyebrow'>PHASE 02 / PROFILE LOCKED</div>"
                 "<h2>VPN Tunnel: %s</h2>" % (p["profile_id"],))
        # Demo view: only properties we can actually show. SPI hashes stay
        # hidden (telemetry bars already tell the story) and every Unknown
        # collapses into one honest one-liner instead of a wall of gaps.
        known = [(k, v) for k, v in p["fields"].items()
                 if k != "spis" and (v or {}).get("value") not in (None, "", [], "Unknown")]
        unknowns = sum(1 for k, v in p["fields"].items()
                       if (v or {}).get("value") in (None, "", [], "Unknown"))
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                k, v.get("value"),
                v.get("provenance"), v.get("source"),
                ("-" if v.get("first_seen") is None else _fmt_ts(v.get("first_seen"))),
                ("-" if v.get("last_seen") is None else _fmt_ts(v.get("last_seen"))))
            for k, v in known)
        h.append("<table class='data-table'><tr><th>Field</th><th>Value</th><th>Provenance</th>"
                 "<th>Source</th><th>First seen</th><th>Last seen</th></tr>%s</table>" % rows)
        if unknowns:
            h.append("<p class='unknown'>+%d more properties honestly reported as Unknown "
                     "&mdash; SENTINEL does not guess.</p>" % unknowns)
        t = p["traffic"]
        ml = _ml_view(t)
        prov_text = "AI's guess" if ml["provenance"] == "ML Inferred" else "Not available yet"
        h.append("<section><h3>TRAFFIC INFERENCE / ML</h3>"
                 "<h2 id='ml-label'>%s</h2>"
                 "<p><b>Confidence:</b> <span id='ml-conf'>%s</span> / <b>Status:</b> <span id='ml-status'>%s</span></p>"
                 "<p><b>Provenance:</b> <span id='ml-provenance'>%s</span></p>"
                 "<p class='unknown' id='ml-reason-text'>%s</p><p id='ml-detail'>%s</p>%s"
                 "<p class='unknown'>Source: ML inference only. Not directly observed from ESP ciphertext.</p>"
                 % (ml["label_text"], ml["confidence_text"], ml["state"], prov_text, ml["reason_text"],
                    ml["detail"], ("<div class='pbars' id='ml-probs'>%s</div>" % ml["prob_rows"]) if ml["prob_rows"] else ""))
        h.append("</section></section>")
        h.append("</section></section>")
    if not contract.get("profiles"):
        h.append("<section class='panel wide'><h2>Awaiting signal</h2><p class='unknown'>No VPN profile yet. Capture is armed and waiting for IKE / ESP / AH traffic.</p></section>")
    h.append("<p class='foot'><a href='/executive'>Executive report</a> / <a href='/technical'>Technical report</a></p>")
    h.append(_POLL_JS)
    return "".join(h)


# Live polling: updates counters, bars, phases, risk, and the fibre canvas from
# /live.json every second. Presentation only — it never fabricates data; every
# value shown comes from the monitor's real snapshot.
_POLL_JS = """<script>
(function(){
  function set(id,v){var e=document.getElementById(id); if(e) e.textContent=v;}
  function esc(s){return String(s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
  var state={sensor:{stats:{}},profiles:[]};
  var seenEvents={};
  var pulses=[];
  var embers=[];
  var lastEmberBurst=0;
  var canvas=document.getElementById('netmap');
  var ctx=canvas&&canvas.getContext ? canvas.getContext('2d') : null;
  var dpr=window.devicePixelRatio||1;
  function resize(){
    if(!canvas||!ctx) return;
    var r=canvas.getBoundingClientRect();
    canvas.width=Math.max(2,Math.floor(r.width*dpr));
    canvas.height=Math.max(2,Math.floor(r.height*dpr));
    ctx.setTransform(dpr,0,0,dpr,0,0);
  }
  function rgb(hex){
    hex=String(hex).replace('#','');
    if(hex.length===3) hex=hex.split('').map(function(c){return c+c;}).join('');
    var n=parseInt(hex,16); return [(n>>16)&255,(n>>8)&255,n&255];
  }
  function prettyLabel(value){
    if(value==null) return 'Unknown';
    var s=String(value);
    if(!s || s.toLowerCase()==='unknown') return 'Unknown';
    var map={'icmp':'ICMP','web':'Web','voip-like':'VoIP-like','video-like':'Video-like'};
     return map[s.toLowerCase()] || s.replace(/_/g,' ').replace(/\\b\\w/g,function(m){return m.toUpperCase();});
  }
  function fmtPct(value){
    if(value===null || value===undefined) return 'Not available';
    return (value*100).toFixed(1)+'%';
  }
  function drawNet(){
    if(!ctx||!canvas) return;
    var box=canvas.getBoundingClientRect();
    var w=box.width||canvas.width||1, h=box.height||canvas.height||1;
    var t=Date.now()/1000;
    var st=(state.sensor&&state.sensor.stats)||{};
    var packets=st.packets||0, esp=st.esp||0, ike=st.ike||0;
    var live=state.live_active!==false;
    var prof=(state.profiles&&state.profiles[0])||{};
    var label=(prof.traffic&&prof.traffic.label)||'unknown';
     var pair=label==='video-like' ? ['#8a5a00','#c08a1a'] : (label==='voip-like' ? ['#a03d00','#d9741f'] : ['#b34e00','#e07b1a']);
    var c0=rgb(pair[0]), c1=rgb(pair[1]);
    var load=Math.max(0, Math.min(1, packets/500 + esp/250 + ike/30));
    if(!live) load*=0.25;
    ctx.clearRect(0,0,w,h);
    var bg=ctx.createRadialGradient(w*0.48,h*0.45,10,w*0.48,h*0.45,Math.max(w,h)*0.58);
     bg.addColorStop(0,'#ffffff');
     bg.addColorStop(1,'rgba(244,242,251,.85)');
    ctx.fillStyle=bg; ctx.fillRect(0,0,w,h);
    ctx.globalCompositeOperation='source-over';
      var nodes=[
       {x:w*0.37,y:h*0.25,r:75,c:c0,l:'GATEWAY A',kind:'gateway'},
       {x:w*0.13,y:h*0.53,r:75,c:c1,l:'CLIENT A / BURST',kind:'client'},
       {x:w*0.50,y:h*0.59,r:94,c:[214,40,40],l:'UNTRUSTED TRANSIT',kind:'transit'},
       {x:w*0.63,y:h*0.25,r:75,c:c0,l:'GATEWAY B',kind:'gateway'},
       {x:w*0.87,y:h*0.53,r:75,c:c1,l:'CLIENT B',kind:'client'}
     ];
    function glow(n,i){
      var pulse=0.7+0.3*Math.sin(t*1.5+i*0.7);
      var rr=n.r*(0.84+0.08*Math.sin(t*1.9+i));
      var g=ctx.createRadialGradient(n.x,n.y,0,n.x,n.y,rr);
      g.addColorStop(0,'rgba('+n.c.join(',')+','+(0.32+0.12*load*pulse)+')');
      g.addColorStop(0.45,'rgba('+n.c.join(',')+','+(0.10+0.08*load*pulse)+')');
      g.addColorStop(1,'rgba('+n.c.join(',')+',0)');
      ctx.fillStyle=g;
      ctx.beginPath(); ctx.arc(n.x,n.y,rr,0,Math.PI*2); ctx.fill();
       ctx.strokeStyle='rgba('+n.c.join(',')+','+(0.28+0.24*load)+')';
       ctx.lineWidth=1.4+load*2.3;
       ctx.beginPath(); ctx.arc(n.x,n.y,rr*0.35,0,Math.PI*2); ctx.stroke();
       if(n.kind==='gateway'){
         ctx.strokeStyle='rgba('+n.c.join(',')+','+(0.54+0.20*load)+')';
         ctx.lineWidth=2.1;
         ctx.strokeRect(n.x-17,n.y-17,34,34);
         ctx.fillStyle='rgba('+n.c.join(',')+',.16)';
         ctx.fillRect(n.x-9,n.y-9,18,18);
         ctx.strokeStyle='rgba(43,33,88,.65)';
         ctx.beginPath(); ctx.moveTo(n.x-6.5,n.y); ctx.lineTo(n.x+6.5,n.y); ctx.stroke();
       }
      ctx.fillStyle='rgba(28,27,51,.85)';
      ctx.font='600 13px ui-monospace,Consolas,monospace';
      ctx.fillText(n.l,n.x-ctx.measureText(n.l).width/2,n.y+rr*0.95);
    }
    function quadPoint(ax, ay, cx, cy, bx, by, t){
      var mt=1-t;
      return {
        x: mt*mt*ax + 2*mt*t*cx + t*t*bx,
        y: mt*mt*ay + 2*mt*t*cy + t*t*by
      };
    }
     function drawBundle(a,b,count,phaseA,phaseB,bendBase){
      for(var i=0;i<count;i++){
        var ax=a.x + Math.sin(t*1.6 + i*0.33 + phaseA)*a.r*0.14;
        var ay=a.y + Math.cos(t*1.2 + i*0.17 + phaseA)*a.r*0.10;
        var bx=b.x + Math.cos(t*1.4 + i*0.29 + phaseB)*b.r*0.14;
        var by=b.y + Math.sin(t*1.1 + i*0.21 + phaseB)*b.r*0.10;
        var bend=bendBase + 0.05*Math.sin(t*0.8 + i*0.19);
        var cx=(ax+bx)/2 + (b.y-a.y)*bend;
        var cy=(ay+by)/2 - (b.x-a.x)*bend*0.25;
        var alpha=0.04 + load*0.16 + (i%5)*0.01;
        ctx.strokeStyle='rgba(' + (i%2===0 ? c0.join(',') : c1.join(',')) + ',' + alpha + ')';
        ctx.lineWidth=0.45 + (i%4)*0.13 + load*0.94;
        ctx.beginPath();
        ctx.moveTo(ax,ay);
        ctx.quadraticCurveTo(cx,cy,bx,by);
        ctx.stroke();
       }
     }
     function drawRail(n,side){
       var dir=side==='left' ? -1 : 1;
       for(var i=0;i<9;i++){
         var yy=n.y-65+i*16;
         var sx=n.x+dir*(109+(i%3)*5);
         var ex=n.x+dir*23;
         ctx.strokeStyle='rgba('+c1.join(',')+','+(0.10+load*.12)+')';
         ctx.lineWidth=1.3;
         ctx.beginPath(); ctx.moveTo(sx,yy); ctx.lineTo(ex,n.y+(i-4)*6.5); ctx.stroke();
         ctx.fillStyle='rgba('+c1.join(',')+','+(0.24+load*.24)+')';
         ctx.fillRect(sx-dir*12,yy-4,dir*12,8);
       }
     }
     var gatewayA=nodes[0], clientA=nodes[1], gatewayB=nodes[3], clientB=nodes[4];
     var bundleCount=Math.max(16,Math.min(120,Math.round(24 + packets/6 + esp/4 + load*35)));
     drawRail(clientA,'left');
     drawRail(clientB,'right');
     drawBundle(gatewayA, clientA, bundleCount, 0.1, 0.7, 0.06);
     drawBundle(clientB, gatewayB, bundleCount, 0.9, 0.3, 0.06);
     drawBundle(gatewayA, gatewayB, Math.max(12,Math.round(bundleCount*.55)), 0.2, 0.8, 0.12);
     ctx.strokeStyle='rgba(179,78,0,.30)';
    ctx.lineWidth=1.2;
    ctx.beginPath();
    ctx.moveTo(gatewayA.x,gatewayA.y);
    ctx.quadraticCurveTo(w*0.50,h*0.18,gatewayB.x,gatewayB.y);
    ctx.stroke();
    pulses=pulses.filter(function(p){return t-p.ts<2.4;});
    pulses.forEach(function(p,idx){
      var prog=Math.max(0,Math.min(1,(t-p.ts)/1.55));
      var fade=1-prog;
      var ctrlY=h*0.18 - Math.sin(prog*Math.PI)*34;
      var weight=(1.5 + Math.min(5, (p.size||0)/110))*1.3;
      var start=p.forward===false ? gatewayB : gatewayA;
      var end=p.forward===false ? gatewayA : gatewayB;
       ctx.strokeStyle='rgba(179,78,0,'+(0.20 + fade*0.65)+')';
      ctx.lineWidth=weight;
       ctx.shadowColor='rgba(179,78,0,'+(0.24 + fade*0.58)+')';
      ctx.shadowBlur=23 + fade*31;
      ctx.beginPath();
      ctx.moveTo(start.x,start.y);
      ctx.quadraticCurveTo(w*0.50,ctrlY,end.x,end.y);
      ctx.stroke();
      var pt=quadPoint(start.x,start.y,w*0.50,ctrlY,end.x,end.y,prog);
      var pulseR=(4 + Math.min(8,(p.size||0)/150))*1.3;
      ctx.fillStyle='rgba(90,45,0,'+(0.85*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,pt.y,pulseR,0,Math.PI*2); ctx.fill();
       ctx.fillStyle='rgba(224,123,26,'+(0.4*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,pt.y,pulseR*2.1,0,Math.PI*2); ctx.fill();
      ctx.shadowBlur=0;
    });
    // Red shimmer dots: every 5s while live data flows, a small burst of
    // tiny glowing red dots drifts along the gateway A <-> gateway B arc.
    // Presentation-only heartbeat; it never touches telemetry or findings.
    if(live && (t-lastEmberBurst)>=5){
      lastEmberBurst=t;
      for(var k=0;k<4;k++){
        embers.push({ts:t+k*0.22, off:(k-1.5)*12, r:1.6+(k%3)*0.5, flip:(k%2===0)});
      }
    }
    embers=embers.filter(function(e){return (t-e.ts)<2.4;});
    embers.forEach(function(e){
      var prog=(t-e.ts)/1.8;
      if(prog<0||prog>1) return;
      var fade=Math.sin(prog*Math.PI);
      var ctrlY=h*0.18 - Math.sin(prog*Math.PI)*34;
      var start=e.flip?gatewayA:gatewayB;
      var end=e.flip?gatewayB:gatewayA;
      var pt=quadPoint(start.x,start.y,w*0.50,ctrlY,end.x,end.y,prog);
      var ey=pt.y+e.off*0.3;
      ctx.save();
      ctx.shadowColor='rgba(255,45,45,'+(0.45+0.5*fade)+')';
      ctx.shadowBlur=10+8*fade;
      ctx.fillStyle='rgba(255,80,80,'+(0.38*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,ey,e.r*2.6,0,Math.PI*2); ctx.fill();
      ctx.fillStyle='rgba(192,22,22,'+(0.55+0.45*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,ey,e.r,0,Math.PI*2); ctx.fill();
      ctx.restore();
    });
    for(var j=0;j<Math.min(140, 20 + Math.round(load*110)); j++){
      var n=nodes[2];
      var px=n.x + Math.sin(t*2.3 + j*1.4)*(n.r*0.55 + (j%9));
      var py=n.y + Math.cos(t*2.0 + j*1.1)*(n.r*0.35 + (j%7));
      ctx.fillStyle='rgba(43,33,88,' + (0.05 + load*0.09) + ')';
      ctx.fillRect(px,py,1.6,1.6);
    }
    // Untrusted-transit snoop illustration: red probe beams reaching from the
    // transit circle up toward the gateway tunnel, with rising probe dots and
    // a pulsing radar ring — the transit trying to peer at passing datasets.
    // Presentation-only threat illustration; never touches telemetry.
    (function(){
      var tn=nodes[2];
      var left=quadPoint(gatewayA.x,gatewayA.y,w*0.50,h*0.18,gatewayB.x,gatewayB.y,0.32);
      var mid=quadPoint(gatewayA.x,gatewayA.y,w*0.50,h*0.18,gatewayB.x,gatewayB.y,0.5);
      var right=quadPoint(gatewayA.x,gatewayA.y,w*0.50,h*0.18,gatewayB.x,gatewayB.y,0.68);
      var targets=[left,mid,right];
      var sway=Math.sin(t*1.3)*6;
      for(var b=0;b<targets.length;b++){
        var tp=targets[b];
        var sx=tn.x+(b-1)*22+sway*(b-1)*0.4, sy=tn.y-tn.r*0.30;
        var g=ctx.createLinearGradient(sx,sy,tp.x,tp.y);
        var a=0.10+0.08*Math.sin(t*2.2+b*2.1);
        g.addColorStop(0,'rgba(220,40,40,0.04)');
        g.addColorStop(1,'rgba(220,40,40,'+Math.max(0.08,a+0.18).toFixed(3)+')');
        ctx.save();
        ctx.strokeStyle=g;
        ctx.lineWidth=1.2;
        ctx.setLineDash([6,5]);
        ctx.lineDashOffset=-(t*22+b*9);
        ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(tp.x,tp.y); ctx.stroke();
        ctx.restore();
        var cyc=(t*0.45+b*0.33)%1;
        var qx=sx+(tp.x-sx)*cyc, qy=sy+(tp.y-sy)*cyc;
        var fade=Math.sin(cyc*Math.PI);
        ctx.save();
        ctx.shadowColor='rgba(255,45,45,'+(0.4+0.5*fade)+')';
        ctx.shadowBlur=9+7*fade;
        ctx.fillStyle='rgba(255,70,70,'+(0.35*fade)+')';
        ctx.beginPath(); ctx.arc(qx,qy,4.6,0,Math.PI*2); ctx.fill();
        ctx.fillStyle='rgba(190,20,20,'+(0.6+0.4*fade)+')';
        ctx.beginPath(); ctx.arc(qx,qy,1.8,0,Math.PI*2); ctx.fill();
        ctx.restore();
      }
      var ring=(t*0.5)%1;
      ctx.save();
      ctx.strokeStyle='rgba(220,40,40,'+(0.45*(1-ring)).toFixed(3)+')';
      ctx.lineWidth=1.6;
      ctx.beginPath(); ctx.arc(tn.x,tn.y,tn.r*0.35+ring*34,0,Math.PI*2); ctx.stroke();
      ctx.restore();
    })();
    drawDrone(w,h,c0,c1,load,t);
    nodes.forEach(glow);
    ctx.globalCompositeOperation='source-over';
  }
  function drawDrone(w,h,c0,c1,load,t){
    var ax=w*0.37, ay=h*0.25, bx=w*0.63, by=h*0.25, cx=w*0.50, cy=h*0.18;
    function qp(u){
      var mt=1-u;
      return {x:mt*mt*ax+2*mt*u*cx+u*u*bx, y:mt*mt*ay+2*mt*u*cy+u*u*by};
    }
    var span=(t*0.09)%2, u=span<1?span:2-span;
    var e=0.5-0.5*Math.cos(u*Math.PI);
    var pt=qp(e), nxt=qp(Math.min(1,e+0.03));
    var ang=Math.atan2(nxt.y-pt.y, nxt.x-pt.x);
    var hover=Math.sin(t*2.4)*6.8;
    var dx=pt.x, dy=pt.y-61+hover;
    var reach=Math.max(120,h*0.60)*1.69;
    ctx.save();
    ctx.translate(dx,dy);
    ctx.rotate(Math.max(-0.5,Math.min(0.5,ang))*0.5);
    ctx.scale(1.69,1.69);
    var sweep=(t*0.6)%1;
    var cone=ctx.createLinearGradient(0,0,0,reach);
    cone.addColorStop(0,'rgba(148,158,170,.36)');
    cone.addColorStop(0.55,'rgba(90,98,108,.14)');
    cone.addColorStop(1,'rgba(90,98,108,0)');
    ctx.fillStyle=cone;
    ctx.beginPath();
    ctx.moveTo(0,2);
    ctx.lineTo(-reach*0.5,reach);
    ctx.lineTo(reach*0.5,reach);
    ctx.closePath();
    ctx.fill();
    ctx.strokeStyle='rgba(200,208,218,.20)';
    ctx.lineWidth=1;
    for(var gx=-3;gx<=3;gx++){
      ctx.beginPath();
      ctx.moveTo(0,2);
      ctx.lineTo(gx*reach*0.16,reach);
      ctx.stroke();
    }
    var scanY=6+(reach-6)*sweep;
    var scanW=(reach*0.5)*(scanY/reach);
    ctx.strokeStyle='rgba(238,242,247,'+(0.60-0.40*sweep)+')';
    ctx.lineWidth=1.5;
    ctx.beginPath();
    ctx.moveTo(-scanW,scanY);
    ctx.lineTo(scanW,scanY);
    ctx.stroke();
    ctx.restore();

    ctx.globalCompositeOperation='source-over';
    ctx.save();
    ctx.translate(dx,dy);
    ctx.scale(1.69,1.69);
    var spin=0.55+0.45*Math.sin(t*7+u*6);
    ctx.fillStyle='rgba(150,158,168,'+(0.16+0.14*spin)+')';
    ctx.strokeStyle='rgba(205,212,220,.70)';
    ctx.lineWidth=1.2;
    [[-15,-7],[15,-7],[-15,7],[15,7]].forEach(function(p){
      ctx.beginPath(); ctx.ellipse(p[0],p[1],6,2.4,0,0,Math.PI*2); ctx.fill();
      ctx.beginPath(); ctx.ellipse(p[0],p[1],6,2.4,0,0,Math.PI*2); ctx.stroke();
    });
    ctx.strokeStyle='rgba(120,128,138,.85)';
    ctx.lineWidth=1.3;
    ctx.beginPath();
    ctx.moveTo(-15,-7); ctx.lineTo(-4,0); ctx.lineTo(4,0); ctx.lineTo(15,-7);
    ctx.moveTo(-15,7); ctx.lineTo(-4,0);
    ctx.moveTo(15,7); ctx.lineTo(4,0);
    ctx.stroke();
    var metal=ctx.createLinearGradient(0,-4,0,4);
    metal.addColorStop(0,'#7d8590');
    metal.addColorStop(0.45,'#4a5058');
    metal.addColorStop(0.55,'#2f3339');
    metal.addColorStop(1,'#636b75');
    ctx.fillStyle=metal;
    ctx.strokeStyle='rgba(213,218,225,.95)';
    ctx.lineWidth=1.4;
    ctx.beginPath();
    ctx.moveTo(-6,-4); ctx.lineTo(6,-4);
    ctx.quadraticCurveTo(9,0,6,4);
    ctx.lineTo(-6,4);
    ctx.quadraticCurveTo(-9,0,-6,-4);
    ctx.closePath();
    ctx.fill(); ctx.stroke();
    var eye=0.6+0.4*Math.sin(t*4.5);
    ctx.fillStyle='rgba(240,244,248,'+(0.60+0.38*eye)+')';
    ctx.beginPath(); ctx.arc(0,0,2.1,0,Math.PI*2); ctx.fill();
    var ring=(t*0.9)%1;
    ctx.strokeStyle='rgba(160,170,182,'+(0.55*(1-ring))+')';
    ctx.lineWidth=1.4;
    ctx.beginPath(); ctx.arc(0,0,8+ring*26,0,Math.PI*2); ctx.stroke();
    ctx.restore();

    ctx.fillStyle='rgba(70,76,84,.25)';
    ctx.font='700 30px ui-monospace,Consolas,monospace';
    var tag='[AI SCAN]';
    ctx.fillText(tag,dx-ctx.measureText(tag).width/2,dy-44);
    ctx.fillStyle='rgba(50,55,62,.95)';
    ctx.font='600 17px ui-monospace,Consolas,monospace';
    ctx.fillText(tag,dx-ctx.measureText(tag).width/2,dy-46);
    ctx.globalCompositeOperation='source-over';
  }
  function poll(){
    fetch('/live.json',{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
      state=d||state;
      var st=(d.sensor&&d.sensor.stats)||{};
      var live=d.live_active!==false;
      set('m-status',live?'LIVE':'PAUSED');
      set('m-packets',st.packets!=null?st.packets:'—'); set('m-esp',st.esp||0); set('m-ike',st.ike||0);
      set('m-profiles',d.sensor?d.sensor.profiles:0);
      var hb=d.heartbeat_ts, el=document.getElementById('hb');
      if(el){
        if(hb){ var age=Math.max(0,Math.round(Date.now()/1000-hb));
          el.textContent=age<=5?('live · '+age+'s ago'):('stale · '+age+'s ago');
          el.className=age<=5?'fresh':'stale';
        } else { el.textContent='no heartbeat'; el.className='stale'; }
      }
      var sig=document.getElementById('signal');
      var spis=(d.profiles&&d.profiles[0]&&d.profiles[0].spis)||[];
      if(sig){
        if(spis.length){
          var mx=1; spis.forEach(function(x){mx=Math.max(mx,x.packets||0);});
          sig.innerHTML=spis.map(function(x){
            return '<i style="height:'+Math.max(8,Math.round(90*(x.packets||0)/mx))+'%"></i>';
          }).join('');
        } else { sig.innerHTML='<i style="height:4%"></i>'.repeat(24); }
      }
      var profs=d.profiles||[];
      var infer=profs.some(function(p){return p.traffic&&p.traffic.reason!=='no_prediction_yet';});
      var assess=profs.some(function(p){return p.verified_configuration_risk&&p.verified_configuration_risk.score!=null;});
      var steps=[[1,live],[2,(st.packets||0)>0],[3,infer],[4,assess]];
      var waiting=false;
      steps.forEach(function(sx){
        var n=document.getElementById('ph-'+sx[0]); if(!n) return;
        n.classList.remove('active','done','wait');
        if(sx[1]) n.classList.add('done');
        else if(!waiting){ n.classList.add('active'); waiting=true; }
        else n.classList.add('wait');
      });
      var p0=profs[0];
      if(p0){
        var tp=p0.traffic||{};
        var reason=tp.reason||'no_prediction_yet';
        var label=tp.label||'Unknown';
        var probs=tp.probabilities||{};
        var keys=Object.keys(probs).sort(function(a,b){return probs[b]-probs[a];});
        var top=keys.length ? keys[0] : null;
        set('ml-provenance', reason==='no_prediction_yet' ? 'Not available yet' : "AI's guess");
        var probsEl=document.getElementById('ml-probs');
        if(probsEl){
          probsEl.innerHTML = keys.length ? keys.map(function(k){ return '<div class="pbar"><span>'+prettyLabel(k)+'</span><span class="tr"><i style="width:'+Math.max(0,Math.min(100,Math.round(probs[k]*100)))+'%"></i></span><span>'+fmtPct(probs[k])+'</span></div>'; }).join('') : '';
        }
        if(reason==='no_prediction_yet'){
          set('ml-label','Traffic classification: Not evaluated yet');
          set('ml-conf','—');
          set('ml-status','Not evaluated yet');
          set('ml-reason-text',['No rolling ML window ','has been evaluated yet.'].join(''));
          set('ml-detail','');
        } else if(reason==='ok'){
          set('ml-label','Predicted traffic: '+prettyLabel(label));
          set('ml-conf',fmtPct(tp.confidence));
          set('ml-status','Accepted');
          set('ml-reason-text','Model produced a prediction above the confidence threshold.');
          set('ml-detail','ML inferred');
        } else if(reason==='below_threshold'){
          set('ml-label','Predicted traffic: Unknown');
          set('ml-conf',fmtPct(tp.confidence));
          set('ml-status','Abstained');
          set('ml-reason-text','Confidence below 60% acceptance threshold.');
          set('ml-detail', top ? ('Top candidate: '+prettyLabel(top)+' / Threshold: 60%') : 'Threshold: 60%');
        } else {
          set('ml-label','Predicted traffic: '+prettyLabel(label));
          set('ml-conf',fmtPct(tp.confidence));
           set('ml-status',reason.replace(/_/g,' ').replace(/\\b\\w/g,function(m){return m.toUpperCase();}));
          set('ml-reason-text', reason.replace(/_/g,' '));
          set('ml-detail','');
        }
      }
      var feed=document.getElementById('feed');
      var recent=d.recent_events||[];
      if(feed && recent.length){
        var gws=(d.profiles&&d.profiles[0]&&d.profiles[0].gateways)||[];
        recent.forEach(function(ev){
          var key=[ev.ts,ev.kind,ev.spi,ev.src,ev.dst].join('|');
          if(seenEvents[key]) return;
          seenEvents[key]=1;
          pulses.push({ts:Date.now()/1000,size:ev.size||0,forward:!(gws.length && ev.src && ev.src===gws[1])});
          var row=document.createElement('div');
          row.className='evt in';
          row.innerHTML='<span class="k">'+esc(String(ev.kind||'pkt').toUpperCase())+'</span> <b>'+esc(String(ev.size||0))+' bytes</b> <span class="t">'+esc(new Date((ev.ts||0)*1000).toLocaleString())+'</span><small>'+esc(String(ev.src||'?'))+' -> '+esc(String(ev.dst||'?'))+'</small>';
          feed.appendChild(row);
          var root=document.getElementById('toasts');
          if(root){
            var toast=document.createElement('div');
            toast.className='toast';
            toast.innerHTML='<b>'+esc(String(ev.kind||'packet').toUpperCase())+' '+esc(String(ev.size||0))+' bytes</b><small>'+esc(new Date((ev.ts||0)*1000).toLocaleString())+' / '+esc(String(ev.src||'?'))+' -> '+esc(String(ev.dst||'?'))+'</small>';
            root.appendChild(toast);
            setTimeout(function(){ if(toast&&toast.parentNode) toast.parentNode.removeChild(toast); }, 3300);
          }
        });
        while(feed.children.length>8) feed.removeChild(feed.firstChild);
        if(!feed.children.length){ feed.innerHTML='<div class="evt"><span class="k">WAIT</span> <b>idle</b> <span class="t">awaiting the next packet burst</span></div>'; }
      }
      drawNet();
    }).catch(function(){ var el=document.getElementById('hb'); if(el){ el.textContent='link lost'; el.className='stale'; } });
  }
  window.addEventListener('resize', resize);
  resize();
  setInterval(poll,1000); poll();
  setInterval(drawNet,120);
})();
</script>"""



