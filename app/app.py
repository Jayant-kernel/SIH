#!/usr/bin/env python3
"""SENTINEL local dashboard: offline analyzer + live monitor + reports.

Standard library only. Accepts local paths only and never uploads data.
Presentation lives in ui.theme so the analyzer, live monitor, and reports
share one visual language.
"""
import argparse, json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integration.analyze import analyze
from reports.generate_report import executive, technical, traffic as traffic_pred, report_topbar
from monitor.dashboard import live_contract, render_live
from monitor.report_bridge import live_report_input
from ui.theme import THEME_CSS, icon, chip, spectrum, seal, meter

LIVE_STATE = Path(__file__).resolve().parents[1] / "monitor" / "state" / "live_profiles.json"

FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E"
    "%3Cpath d='M12 2l8 3.2v6.3c0 5-3.3 8.6-8 10.5-4.7-1.9-8-5.5-8-10.5V5.2z' "
    "fill='%230d0b09' stroke='%23ff9a45' stroke-width='1.4'/%3E"
    "%3Cpath d='M9.3 12.2l1.9 1.9 3.6-3.9' fill='none' stroke='%23ff9a45' "
    "stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E"
)

_NAV = [("Analyzer", "/"), ("Live monitor", "/live"),
        ("Executive", "/executive"), ("Technical", "/technical")]


def _page(body, active="/", status="Local analyzer", state="off", title="IPSEC // SENTINEL"):
    nav = "".join(
        "<a href='%s'%s>%s</a>" % (href, " aria-current='page'" if href == active else "", label)
        for label, href in _NAV
    )
    desc = ("Evidence-first IPsec VPN analyzer: passive encrypted-flow telemetry, "
            "provenance-aware security assessment, and local ML inference. No payload decryption.")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='description' content='%s'>"
        "<meta name='color-scheme' content='light'>"
        "<title>%s</title><link rel='icon' href=\"%s\"><style>%s</style></head><body>"
        "<a class='skip' href='#main'>Skip to content</a><div class='shell'>"
        "<nav class='topbar' aria-label='Primary'>"
        "<span class='glyph' aria-hidden='true'>%s</span>"
        "<span class='brand'>IPSEC <i>//</i> SENTINEL</span>"
        "<span class='nav'>%s</span>"
        "<span class='status' data-state='%s'>%s</span></nav>"
        "<main id='main'>%s</main>"
        "<footer class='foot'><span>LOCAL PROCESSING // EVIDENCE FIRST // NO PAYLOAD DECRYPTION</span>"
        "<span>Unknown is a result, not a failure.</span>"
        "<span class='sr'>AI-Driven IPsec VPN Security Analyzer</span>"
        "<span class='sr'>IKEv2</span><span class='sr'>Unknown</span></footer>"
        "</div></body></html>" % (desc, title, FAVICON, THEME_CSS,
                                  icon("shield"), nav, state, status, body)
    )


def _field(ev):
    """Normalise a field dict from either the offline or live result shape."""
    if not isinstance(ev, dict):
        return {"value": ev, "evidence_type": "unknown", "source": ""}
    et = ev.get("evidence_type") or ev.get("provenance") or "unknown"
    return {"value": ev.get("value"), "evidence_type": et,
            "source": ev.get("source") or "", "reason": ev.get("reason")}


def _prov_counts(fields):
    counts = {"observed": 0, "derived": 0, "ml": 0, "unknown": 0}
    keymap = {"directly_observed": "observed", "Observed": "observed",
              "deterministically_derived": "derived", "Derived": "derived",
              "ml_inferred": "ml", "ML Inferred": "ml"}
    for ev in fields.values():
        counts[keymap.get((ev or {}).get("evidence_type") or (ev or {}).get("provenance"), "unknown")] += 1
    return counts


def _stat(label, value, prov="unknown", source=""):
    text = "Unknown" if value in (None, "", []) else str(value)
    cls = "v unknown" if text == "Unknown" else "v"
    src = "<div class='src'>%s</div>" % source if source else ""
    return ("<div class='stat'><div class='k'>%s</div><div class='%s'>%s</div>%s%s</div>"
            % (label, cls, _e(text), src, chip(prov)))


def _e(value):
    import html as h
    return h.escape(str(value if value is not None else "Unknown"))


def _kv(label, value):
    return "<div class='row'><label>%s</label><strong>%s</strong></div>" % (label, _e(value))


def _notice(kind, title, text):
    return ("<div class='notice' data-v='%s'><span class='ic'>%s</span><div>"
            "<h4>%s</h4><p>%s</p></div></div>" % (kind, icon(kind if kind in ("alert", "info") else "info"), title, text))


def _analyzer_form(run="", pcap=""):
    """Working input for the offline analyzer. Local paths only, GET params."""
    return (
        "<form class='form' method='get' action='/' style='text-align:left;margin:22px auto 0;max-width:780px'>"
        "<div class='field'><label for='run'>Run directory</label>"
        "<input id='run' name='run' type='text' value='%s' autocomplete='off' spellcheck='false' "
        "placeholder='dataset_v3_5_v2_full/T04/20260903-143933-601'></div>"
        "<div class='field'><label for='pcap'>PCAP file</label>"
        "<input id='pcap' name='pcap' type='text' value='%s' autocomplete='off' spellcheck='false' "
        "placeholder='captures/monitor/live_current.pcap'></div>"
        "<button class='btn' type='submit'><span class='orb' aria-hidden='true'>%s</span>Analyze</button>"
        "<a class='btn ghost' href='/live'>Live monitor</a>"
        "</form>"
        % (_e(run), _e(pcap), icon("search"))
    )


def _intro():
    samples = ("<div class='samples'>"
               "<a href='/?run=dataset_v3_5_v2_full%2FT04%2F20260903-143933-601'>"
               "dataset_v3_5_v2_full/T04/20260903-143933-601</a>"
               "<a href='/?run=D%3A%5Cruns%5CT03'>D:\\runs\\T03</a>"
               "<a href='/?pcap=captures%5Cmonitor%5Clive_current.pcap'>"
               "captures\\monitor\\live_current.pcap</a></div>")
    return ("<section class='panel rise landing' style='--i:0'>"
            "<div class='dots' aria-hidden='true'></div>"
            "<div class='float-card fc-tl' aria-hidden='true'><span class='pin'></span>"
            "<b>No decryption. Ever.</b><small>Only envelopes &mdash; sizes, timing, direction.</small></div>"
            "<div class='float-card fc-tr' aria-hidden='true'>"
            "<b><span class='livedot'></span>Passive tap</b><small>ESP + IKE copies only. Nothing injected.</small></div>"
            "<div class='float-card fc-bl' aria-hidden='true'>"
            "<b>What we read</b><div class='fbars'>"
            "<div>Sizes<i style='--w:72%%'></i></div>"
            "<div>Timing<i style='--w:54%%'></i></div>"
            "<div>Direction<i style='--w:38%%'></i></div></div></div>"
            "<div class='float-card fc-br' aria-hidden='true'>"
            "<b>Every fact labeled</b><div class='fchips'>"
            "<span class='o'>Observed</span><span class='d'>Derived</span><span class='m'>AI's guess</span></div></div>"
            "<div class='empty landing-core'>"
            "<div class='orb' aria-hidden='true'>%s</div>"
            "<h1 class='display hero'>Read the wire.<br><span class='grey'>Trust the evidence.</span></h1>"
            "%s%s"
            "<div class='samples' style='margin-top:18px'><span class='sec-note'>Start the live "
            "capture with <code style='padding:4px 8px'>scripts/start-live-monitor.ps1</code></span></div>"
            "</div></section>" % (icon("wave"), _analyzer_form(), samples))


def _error_state(message, hint=""):
    return ("<section class='panel rise' style='--i:0'>"
            "<div class='panel-h'><span class='code'>INPUT / ERROR</span><h3>Nothing to analyze</h3></div>"
            "%s%s</section>"
            % (_notice("error", "The supplied local input could not be read", _e(message)),
               _analyzer_form()))


def render(result):
    if not result:
        return _intro()
    if result.get("_error"):
        return _error_state(result["_error"], result.get("hint", ""))

    fields = (result.get("protocol_analysis") or {}).get("fields") or {}
    risk = result.get("risk") or {}
    tp = traffic_pred(result)
    findings = (result.get("security_assessment") or {}).get("security_findings") or []
    threats = result.get("threat_matrix") or []
    limitations = result.get("limitations") or []
    inp = result.get("input") or {}
    comps = result.get("components") or {}

    def f(name):
        return _field(fields.get(name))

    score = risk.get("score")
    level = risk.get("level")
    completeness = risk.get("evidence_completeness")
    comp_pct = None if completeness is None else round(float(completeness) * 100, 1)

    prov = _prov_counts(fields)
    counts = {"pass": 0, "warning": 0, "fail": 0, "unknown": 0}
    for fd in findings:
        counts[fd.get("status") if fd.get("status") in counts else "unknown"] += 1

    # ---- header ----
    # Plain-language verdict FIRST: a bare "0 / 100" reads as failure to
    # non-technical viewers, so the meaning lands before the number.
    if score is None:
        verdict, vv = "Risk not evaluated", "unknown"
    elif score == 0:
        verdict, vv = "ZERO RISK", "good"
    else:
        verdict, vv = ("Risk %d of 100 \u2014 %s"
                       % (score, str(level or "unknown").replace("-", " ").title())), "bad"
    passive = ("<div style='margin-top:16px'>%s</div>"
               % _notice("warn", "Passive capture only",
                         "No runtime snapshots were supplied, so encryption algorithm, key size, "
                         "mode, PFS, DH group and replay protection cannot be verified.")
               if inp.get("type") == "pcap" else "")
    header = (
        "<section class='panel rise c12' style='--i:0'>"
        "<div class='panel-h'><span class='code'>MOD 00 / ASSESSMENT</span>"
        "<h3>%s</h3><span class='meta'>%s</span></div>"
        "<div class='bento'><div class='c5 seal-wrap' style='grid-column:span 5'>%s"
        "<div><div class='eyebrow'>Verified configuration risk</div>"
        "<div class='verdict' data-v='%s'>%s</div>"
        "<h1 class='display' style='font-size:30px;margin:.2em 0 .35em'>%s</h1>"
        "<p class='sec-note' style='max-width:34ch'>%s</p></div></div>"
        "<div class='c7 stack' style='grid-column:span 7'>"
        "<div><div class='eyebrow'>Evidence completeness</div>%s"
        "<p class='sec-note' style='margin-top:8px'>%s of VPN properties verified from the supplied evidence.</p></div>"
        "<div><div class='eyebrow'>Provenance mix</div>%s</div>"
        "<div class='kv'>%s%s%s</div></div></div>%s</section>"
        % (_e(inp.get("source") or "local input"),
           _e(result.get("generated_at") or ""),
           seal(score, level),
           vv, _e(verdict),
           ("%s / 100" % score) if score is not None else "&mdash;",
           ("No proven rule failures. Unknowns remain unknown &mdash; this is not a clean bill of health."
            if score == 0 else "Penalty is the sum of proven rule failures only."),
           meter(comp_pct if comp_pct is not None else 0),
           _e("Unknown" if completeness is None else completeness),
           spectrum(prov),
           _kv("Analysis version", result.get("analysis_version")),
           _kv("Model version", comps.get("model_version")),
           _kv("Security engine", comps.get("security_version")),
           passive))

    # ---- KPI tiles ----
    kpis = (
        "<section class='panel rise c12' style='--i:1'><div class='panel-h'>"
        "<span class='code'>MOD 01 / OVERVIEW</span><h3>Key readings</h3></div>"
        "<div class='stats'>%s%s%s%s%s%s%s%s</div></section>"
        % (_stat("Protocol", f("protocol")["value"], f("protocol")["evidence_type"], f("protocol")["source"]),
           _stat("IKE version", f("ike_version")["value"], f("ike_version")["evidence_type"], f("ike_version")["source"]),
           _stat("Mode", f("mode")["value"], f("mode")["evidence_type"], f("mode")["source"]),
           _stat("Encryption", f("encryption_algorithm")["value"], f("encryption_algorithm")["evidence_type"], f("encryption_algorithm")["source"]),
           _stat("PFS", f("pfs")["value"], f("pfs")["evidence_type"], f("pfs")["source"]),
           _stat("Traffic type", tp.get("label") or "Unknown", "ML Inferred", "local ML inference"),
           _stat("Risk score", ("%s / %s" % (score, level)) if score is not None else None, "derived", "proven failures only"),
           _stat("Completeness", ("%s%%" % comp_pct) if comp_pct is not None else None, "derived", "evidence coverage")))

    # ---- evidence tiles ----
    order = ["protocol", "ike_version", "mode", "encryption_algorithm",
             "encryption_key_length", "integrity_algorithm", "dh_group", "pfs",
             "replay", "rekey_status", "ike_proposal", "lifetime", "spi_count",
             "protected_ip_version", "aead", "local_ts", "remote_ts"]
    tiles = []
    for name in order:
        if name not in fields:
            continue
        fd = _field(fields[name])
        val = "Unknown" if fd["value"] in (None, "", []) else fd["value"]
        reason = fd.get("reason") or ("Not observable from the supplied evidence."
                                      if val == "Unknown" else "")
        tiles.append("<div class='ev'><div class='k'>%s</div><div class='v%s'>%s</div>%s%s</div>"
                     % (name, " unknown" if val == "Unknown" else "", _e(val),
                        chip(fd["evidence_type"]),
                        "<div class='r'>%s</div>" % _e(reason) if reason else ""))
    evidence = ("<section class='panel rise c8' style='--i:2'><div class='panel-h'>"
                "<span class='code'>MOD 02 / EVIDENCE</span><h3>Protocol and field provenance</h3>"
                "<span class='meta'>%d fields</span></div><div class='ev-grid'>%s</div></section>"
                % (len(fields), "".join(tiles) or "<p class='sec-note'>No field evidence supplied.</p>"))

    # ---- traffic ML ----
    probs = tp.get("probabilities") or {}
    bars = "".join(
        "<div class='row'><span class='lbl'>%s</span><span class='tr'><i style='width:%d%%'></i></span>"
        "<span class='pc'>%.1f%%</span></div>" % (_e(k), int(round(float(v) * 100)), float(v) * 100)
        for k, v in sorted(probs.items(), key=lambda kv: -kv[1]))
    conf = tp.get("confidence")
    conf_txt = ("%.1f%%" % (float(conf) * 100)) if isinstance(conf, (int, float)) else "Not evaluated"
    ml = ("<section class='panel rise c4' style='--i:3'><div class='panel-h'>"
          "<span class='code'>MOD 03 / INFERENCE</span><h3>Traffic behaviour</h3></div>"
          "<div class='stat' style='background:#faf9fe'><div class='k'>Predicted class</div>"
          "<div class='v'>%s</div>%s</div>"
          "<div class='bars' style='margin-top:14px'>%s</div>"
          "<div class='kv' style='margin-top:14px'>%s%s</div>"
          "<p class='sec-note' style='margin-top:12px'>ML inference from encrypted-flow metadata only. "
          "It never decrypts payloads and is an estimate, not certainty.</p></section>"
          % (_e(tp.get("label")), chip("ML Inferred"), bars or "<p class='sec-note'>No probability vector.</p>",
             _kv("Confidence", conf_txt), _kv("Reason", tp.get("reason") or "n/a")))

    # ---- findings ----
    sev_cards = []
    for fd in findings:
        status = fd.get("status") if fd.get("status") in ("pass", "warning", "fail", "unknown") else "unknown"
        rec = fd.get("recommendation")
        sev_cards.append(
            "<article class='fcard'><div class='sev'><span class='badge' data-s='%s'>"
            "<span class='sevdot' data-s='%s' aria-hidden='true'></span>%s</span>"
            "<span class='sec-note'>%s</span></div><div><h4>%s</h4><p>%s</p>%s</div></article>"
            % (status, status, status, _e(fd.get("severity")), _e(fd.get("title")),
               _e(fd.get("description")),
               "<p class='rec'>%s</p>" % _e(rec) if rec else ""))
    findings_panel = (
        "<section class='panel rise c7' style='--i:4'><div class='panel-h'>"
        "<span class='code'>MOD 04 / SECURITY</span><h3>Findings</h3>"
        "<span class='meta'>%d pass &middot; %d warn &middot; %d fail &middot; %d unknown</span></div>"
        "<div class='find'>%s</div></section>"
        % (counts["pass"], counts["warning"], counts["fail"], counts["unknown"],
           "".join(sev_cards) or "<p class='sec-note'>No findings were produced.</p>"))

    # ---- threat matrix ----
    threat_rows = "".join(
        "<tr><td>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td></tr>"
        % (_e(t.get("threat")), _e(t.get("condition")),
           chip("Observed" if t.get("evidence_type") == "directly_observed" else t.get("evidence_type")),
           _e(t.get("risk")))
        for t in threats)
    threat_panel = (
        "<section class='panel rise c5' style='--i:5'><div class='panel-h'>"
        "<span class='code'>MOD 05 / THREATS</span><h3>Residual threat matrix</h3></div>"
        "<div class='tbl-wrap'><table class='tbl'><thead><tr><th>Threat</th><th>Condition</th>"
        "<th>Evidence</th><th>Risk</th></tr></thead><tbody>%s</tbody></table></div>"
        "<p class='sec-note' style='margin-top:12px'>These are conditions that remain observable "
        "regardless of proven configuration. They are not rule failures.</p></section>"
        % (threat_rows or "<tr><td colspan='4' class='sec-note'>No residual threats recorded.</td></tr>"))

    # ---- full table ----
    rows = "".join(
        "<tr><td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td></tr>"
        % (_e(k), "<span class='missing'>Unknown</span>" if (v or {}).get("value") in (None, "", []) else _e((v or {}).get("value")),
           chip((v or {}).get("evidence_type")), _e((v or {}).get("source")))
        for k, v in fields.items())
    table = ("<section class='panel rise c12' style='--i:6'><div class='panel-h'>"
             "<span class='code'>MOD 06 / LEDGER</span><h3>Full evidence ledger</h3></div>"
             "<div class='tbl-wrap'><table class='tbl'><thead><tr><th>Field</th><th>Value</th>"
             "<th>Provenance</th><th>Source</th></tr></thead><tbody>%s</tbody></table></div></section>"
             % (rows or "<tr><td colspan='4' class='sec-note'>No fields.</td></tr>"))

    # ---- limitations ----
    lim = ""
    if limitations:
        items = "".join("<li style='margin-bottom:7px'>%s</li>" % _e(x) for x in limitations)
        lim = ("<section class='panel rise c12' style='--i:7'><div class='panel-h'>"
               "<span class='code'>MOD 07 / LIMITS</span><h3>Limitations and unknowns</h3></div>"
               "<ul style='margin:0;padding-left:20px;color:var(--muted)'>%s</ul></section>" % items)

    src = inp.get("source") or ""
    is_pcap = inp.get("type") == "pcap"
    back = ("<section class='panel rise c12' style='--i:8'><div class='panel-h'>"
            "<span class='code'>INPUT / NEW</span><h3>Analyze another capture</h3></div>"
            "%s</section>" % _analyzer_form("" if is_pcap else src, src if is_pcap else ""))
    return ("<div class='bento'>%s%s%s%s%s%s%s%s%s</div>"
            % (header, kpis, evidence, ml, findings_panel, threat_panel, table, lim, back))


def _tail_jsonl(path, limit=12):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def live_snapshot():
    """Read the monitor state and attach heartbeat/pubsub fields plus an
    honest live/stale/unavailable classification. Read-only."""
    import time
    state = None
    if LIVE_STATE.exists():
        try:
            state = json.loads(LIVE_STATE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = None
    contract = live_contract(state or {})
    heartbeat = {}
    hb = LIVE_STATE.parent / "heartbeat.json"
    if hb.exists():
        try:
            heartbeat = json.loads(hb.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            heartbeat = {}
    heartbeat_ts = heartbeat.get("ts")
    age = None if heartbeat_ts is None else max(0, int(time.time() - heartbeat_ts))
    contract["heartbeat_ts"] = heartbeat_ts
    contract["heartbeat_status"] = heartbeat.get("status")
    contract["heartbeat_age"] = age
    contract["live_active"] = bool(heartbeat.get("status") == "LIVE"
                                   and (age is None or age <= 5))
    contract["recent_events"] = _tail_jsonl(LIVE_STATE.parent / "events.jsonl", 14)
    contract["state_available"] = bool(state and contract.get("profiles"))
    if not contract["state_available"]:
        contract["live_state"] = "unavailable"
        contract["live_state_reason"] = ("no live monitor state file"
                                         if not state else "no VPN profile observed yet")
    elif contract["live_active"]:
        contract["live_state"] = "live"
        contract["live_state_reason"] = ""
    else:
        contract["live_state"] = "stale"
        status = heartbeat.get("status")
        if status and status != "LIVE":
            contract["live_state_reason"] = "monitor status is %s" % status
        elif age is not None:
            contract["live_state_reason"] = "heartbeat is %ss old" % age
        else:
            contract["live_state_reason"] = "no fresh heartbeat"
    return contract


def report_banner(contract):
    """Prominent banner so a stale/unavailable snapshot is never mistaken
    for a live assessment."""
    state = contract.get("live_state")
    gen = contract.get("generated_at")
    try:
        gen_txt = (datetime.fromtimestamp(gen).strftime("%Y-%m-%d %H:%M:%S")
                   if isinstance(gen, (int, float)) else "unknown")
    except (OSError, OverflowError, ValueError):
        gen_txt = "unknown"
    base = ("padding:.8rem 1.1rem;margin:0 0 1.1rem;border-radius:12px;"
            "font:13px/1.5 var(--font-sans);border:1px solid ")
    if state == "live":
        return ("<div style='%s#bfe6cd;background:#eaf7ef;color:#0f5a2a'>"
                "LIVE SENSOR &middot; fresh passive monitor state &middot; snapshot %s</div>"
                % (base, gen_txt))
    if state == "stale":
        reason = contract.get("live_state_reason") or "no fresh heartbeat"
        return ("<div style='%s#efd9a8;background:#fdf6e6;color:#7a5300'>"
                "STALE SNAPSHOT &middot; live sensor data is not fresh (%s) &middot; snapshot %s</div>"
                % (base, reason, gen_txt))
    return ("<div style='%s#d9ddef;background:#f4f5fb;color:#56597a'>"
            "LIVE MONITOR STATE UNAVAILABLE &middot; this report has no live data</div>" % base)


def unavailable_report(kind):
    active = "/executive" if kind == "Executive" else "/technical"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='color-scheme' content='light'>"
        "<title>%s report unavailable</title><style>%s</style></head><body><div class='shell'>"
        "%s"
        "<main id='main' style='padding-top:18px'><section class='panel'>"
        "<div class='panel-h'><span class='code'>REPORT / UNAVAILABLE</span>"
        "<h3>%s report unavailable</h3></div><div class='empty'>"
        "<div class='orb' aria-hidden='true'>%s</div>"
        "<h1 class='display' style='font-size:26px'>No live monitor state</h1>"
        "<p class='lede' style='margin:0 auto'>SENTINEL looked for <code class='mono'>%s</code> and found "
        "nothing to report on. Start the passive monitor, then reload this page.</p>"
        "<div class='samples'><code>scripts/start-live-monitor.ps1</code></div>"
        "</div></section></main>"
        "<footer class='foot'><span>LOCAL PROCESSING // EVIDENCE FIRST // NO PAYLOAD DECRYPTION</span>"
        "<span>Unknown is a result, not a failure.</span></footer>"
        "</div></body></html>"
        % (kind, THEME_CSS, report_topbar(active), kind, icon("alert"), _e(str(LIVE_STATE))))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        parts = urlparse(self.path)
        if parts.path == "/live.json":
            try:
                payload = json.dumps(live_snapshot()).encode()
            except Exception:
                payload = b"{}"
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store'); self.end_headers(); self.wfile.write(payload)
            return
        if parts.path in ("/executive", "/technical"):
            kind = "Executive" if parts.path == "/executive" else "Technical"
            try:
                contract = live_snapshot()
            except Exception:
                contract = {"live_state": "unavailable", "live_state_reason": "monitor state could not be read"}
            if contract.get("live_state") == "unavailable":
                body = unavailable_report(kind).encode()
            else:
                result = live_report_input(contract, LIVE_STATE)
                doc = executive(result) if parts.path == "/executive" else technical(result)
                body = doc.replace("</nav>", "</nav>" + report_banner(contract), 1).encode()
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store'); self.end_headers(); self.wfile.write(body)
            return
        if parts.path == "/live":
            try:
                contract = live_snapshot()
                if contract.get("state_available"):
                    body = render_live(contract)
                else:
                    body = ("<section class='panel'><div class='empty'><div class='orb'>%s</div>"
                            "<h1 class='display' style='font-size:26px'>Awaiting signal</h1>"
                            "<p class='lede' style='margin:0 auto'>No monitor state yet. Start the passive "
                            "monitor, then reload.</p><div class='samples'><code>scripts/start-live-monitor.ps1"
                            "</code></div></div></section>" % icon("wave"))
                status = "Live sensor" if contract.get("live_state") == "live" else "Stale snapshot"
                st = "live" if contract.get("live_state") == "live" else "stale"
            except Exception:
                body = _error_state("Monitor state could not be read.")
                status, st = "Stale snapshot", "stale"
            data = _page(body, active="/live", status=status, state=st, title="Live // IPSEC SENTINEL")
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers(); self.wfile.write(data.encode())
            return

        q = parse_qs(parts.query); result = None
        run = (q.get('run') or [None])[0]
        pcap = (q.get('pcap') or [None])[0]
        try:
            if run and not Path(run).exists():
                result = {"_error": "Run directory not found: %s" % run,
                          "hint": "Check the path and that it is visible from this machine."}
            elif pcap and not Path(pcap).exists():
                result = {"_error": "Capture file not found: %s" % pcap,
                          "hint": "Check the path and that it is visible from this machine."}
            elif run:
                result = analyze(run_dir=run)
            elif pcap:
                result = analyze(pcap=pcap)
        except Exception:
            result = {"_error": "The supplied local input could not be analyzed."}
        body = render(result)
        data = _page(body, active="/", status="Local analyzer", state="off")
        self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers(); self.wfile.write(data.encode())

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8501)
    a = ap.parse_args()
    print(f"Dashboard: http://{a.host}:{a.port}")
    HTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
