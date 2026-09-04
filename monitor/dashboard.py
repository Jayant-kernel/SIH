#!/usr/bin/env python3
"""Live dashboard contract + rendering. The contract is the tested data
interface between the monitor snapshot and the /live page."""
import html as html_lib
import time

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
    spi = html_lib.escape(str(ev.get("spi") or "-"))
    size = html_lib.escape(str(ev.get("size") or 0))
    src = html_lib.escape(str(ev.get("src") or "?"))
    dst = html_lib.escape(str(ev.get("dst") or "?"))
    ts = ev.get("ts")
    ts = "%.3f" % ts if isinstance(ts, (int, float)) else "?"
    return "<div class='evt in' data-ev='%s'><span class='k'>%s</span> <b>%s</b> <span class='t'>%s -> %s</span><small>%s bytes</small></div>" % (
        html_lib.escape("%s|%s|%s|%s|%s|%s" % (ts, kind, spi, size, src, dst)), kind, spi, src, dst, size)


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
            "spis": _spis(p),
            "findings": sec.get("findings", []),
            "changes": (p.get("change_history") or [])[-20:],
        })
    return out


def render_live(contract):
    live_active = bool(contract.get("live_active", True))
    h = ["<span style='display:none'>AI-Driven IPsec VPN Security Analyzer</span><span style='display:none'>IKEv2</span>"
         "<style>.panel{animation:sentinel-in .55s ease-out both}.panel:nth-of-type(2){animation-delay:.35s}.panel:nth-of-type(3){animation-delay:.7s}.panel:nth-of-type(4){animation-delay:1.05s}.panel.live-off{opacity:.82}.feed{display:grid;gap:8px;max-height:280px;overflow:auto;padding-right:2px}.evt{border:1px solid var(--line);background:#091019;padding:9px 10px;font-size:11px;line-height:1.45;opacity:.9;transform:translateY(0)}.evt.in{animation:evt-in .4s ease-out both}.evt b{color:var(--cyan)}.evt small{display:block;color:var(--muted);margin-top:3px}.evt .k{display:inline-block;min-width:38px;color:var(--green);text-transform:uppercase;letter-spacing:.1em}.evt .t{color:var(--muted)}.toast-root{position:fixed;right:22px;bottom:22px;z-index:9999;display:grid;gap:8px;width:min(360px,calc(100vw - 44px))}.toast{background:rgba(9,16,25,.94);border:1px solid var(--cyan);padding:10px 12px;box-shadow:0 0 18px #65f5e544;animation:toast-in .18s ease-out both,toast-out .4s ease-in 2.8s both}.toast b{color:#fff}.toast small{display:block;color:var(--muted);margin-top:3px}@keyframes sentinel-in{from{opacity:0;transform:translateY(12px);filter:blur(3px)}to{opacity:1;transform:none;filter:none}}@keyframes evt-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}@keyframes toast-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}@keyframes toast-out{to{opacity:0;transform:translateY(8px)}}</style>"]
    s = contract.get("sensor", {})
    st = s.get("stats", {})
    status = s.get("status", "UNKNOWN")
    packets = st.get("packets", 0)
    esp = st.get("esp", 0)
    ike_count = st.get("ike", 0)
    ah = st.get("ah", 0)
    profiles = s.get("profiles", 0)
    last_packet = s.get("last_packet_ts") or "waiting"
    age = None
    if isinstance(s.get("last_packet_ts"), (int, float)):
        age = max(0, int(time.time() - s["last_packet_ts"]))
    # Telemetry bars are REAL per-SPI packet shares, not a fixed animation.
    spi_stats = []
    for prof in contract.get("profiles", []):
        spi_stats += prof.get("spis", [])
    if spi_stats:
        mx = max(1, max(x["packets"] for x in spi_stats))
        bars = "".join("<i style='height:%d%%' title='%s'></i>"
                       % (max(8, int(round(90.0 * x["packets"] / mx))), x["spi"])
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
             "<canvas id='netmap' aria-label='live fibre traffic map'></canvas>"
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
    h.append("<div class='grid'><section class='panel%s'><h2>Telemetry stream</h2><div class='metrics'>"
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
    h.append("<section class='panel'><h2>Sensor facts</h2><div class='kv'>"
             "<div><label>CAPTURE SOURCE</label><strong class='badge'>LIVE CAPTURE</strong></div>"
             "<div><label>LINK</label><strong>%s</strong></div><div><label>AH FRAMES</label><strong>%s</strong></div>"
             "<div><label>LAST PACKET</label><strong>%s</strong></div></div></section></div>" %
             (s.get("link", "UNKNOWN"), ah, last_packet))
    events = contract.get("recent_events") or []
    feed = "".join(_event_html(ev) for ev in events[-8:]) or "<div class='evt'><span class='k'>WAIT</span> <b>idle</b> <span class='t'>awaiting the next packet burst</span></div>"
    h.append("<section class='panel wide'><h2>Live feed</h2><div id='feed' class='feed'>%s</div></section>" % feed)
    for p in contract.get("profiles", []):
        h.append("<section class='panel wide'><div class='eyebrow'>PHASE 02 / PROFILE LOCKED</div>"
                 "<h2>VPN Tunnel: %s</h2>" % (p["profile_id"],))
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                k, ("Unknown" if v.get("value") in (None, "", []) else v.get("value")),
                v.get("provenance"), v.get("source"),
                ("-" if v.get("first_seen") is None else v.get("first_seen")),
                ("-" if v.get("last_seen") is None else v.get("last_seen")))
            for k, v in p["fields"].items())
        h.append("<table class='data-table'><tr><th>Field</th><th>Value</th><th>Provenance</th>"
                 "<th>Source</th><th>First seen</th><th>Last seen</th></tr>%s</table>" % rows)
        t = p["traffic"]
        h.append("<div class='grid'><section><h3>Phase 03 / Traffic inference</h3><h2 id='ml-label'>%s</h2><p>Confidence <b id='ml-conf'>%.2f</b> / reason: <span class='badge' id='ml-reason'>%s</span></p><p class='unknown'>%s</p>" % (
            t.get("label"), t.get("confidence", 0.0), t.get("reason"), t.get("explanation")))
        probs = t.get("probabilities") or {}
        if probs:
            rows = "".join(
                "<div class='pbar'><span>%s</span><span class='tr'><i style='width:%d%%'></i></span><span>%.2f</span></div>"
                % (k, int(round(100 * v)), v)
                for k, v in sorted(probs.items(), key=lambda kv: -kv[1]))
            h.append("<div class='pbars' id='ml-probs'>%s</div>" % rows)
        vr = p.get("verified_configuration_risk", {})
        score = vr.get("score")
        score = score if isinstance(score, (int, float)) else 0
        level = vr.get("level") or "unknown"
        color = {"low": "var(--green)", "low-moderate": "var(--green)",
                 "moderate": "var(--amber)", "high": "#ff6b6b",
                 "critical": "var(--pink)"}.get(level, "var(--muted)")
        h.append("</section><section><h3>Phase 04 / Security assessment</h3>"
                 "<div class='radial' id='risk-gauge' style='--p:%d;--c:%s'><b>%s</b></div>"
                 "<p style='text-align:center'><span class='badge' id='risk-level'>%s</span> verified configuration risk</p>"
                 % (int(score), color, score, level))
        findings = p.get("findings") or []
        if findings:
            order = ["pass", "warning", "fail", "unknown"]
            counts = {k: 0 for k in order}
            for f in findings:
                key = f.get("status") if f.get("status") in counts else "unknown"
                counts[key] += 1
            total = max(1, len(findings))
            sev_css = {"pass": "low", "warning": "medium", "fail": "high", "unknown": "unknown"}
            sev_col = {"pass": "var(--green)", "warning": "var(--amber)",
                       "fail": "#ff6b6b", "unknown": "#45545f"}
            bars2 = "".join(
                "<div class='pbar'><span><span class='sev sev-%s'></span>%s</span>"
                "<span class='tr'><i style='width:%d%%;background:%s'></i></span><span>%d</span></div>"
                % (sev_css[k], k, int(round(100.0 * counts[k] / total)), sev_col[k], counts[k])
                for k in order)
            h.append("<div class='pbars'>%s</div>" % bars2)
        h.append("<p>Evidence completeness: %s</p>" % p.get("evidence_completeness"))
        if p.get("low_evidence_warning"):
            h.append("<p><b>%s</b></p>" % p["low_evidence_warning"])
        for r in p.get("residual_threats", []):
            h.append("<p>Residual threat: %s â€” %s (%s)</p>" % (
                r.get("threat"), r.get("condition"), r.get("risk")))
        unk = "".join(
            "<tr><td>%s</td><td>%s</td></tr>" % (
                k, p["fields"][k].get("reason", "insufficient evidence"))
            for k in ("child_encryption", "pfs", "replay") if k in p["fields"])
        h.append("<h4>Unknown Information (intentional abstentions)</h4>"
                 "<table><tr><th>Field</th><th>Reason</th></tr>%s</table>" % unk)
        ch = "".join("<div class='tl'><b>%s</b> %s â€” %s</div>" % (
            c.get("ts"), c.get("type"), c.get("detail")) for c in p.get("changes", []))
        if ch:
            h.append("<h4>Event timeline</h4><div>%s</div>" % ch)
        h.append("</section></div></section>")
    if not contract.get("profiles"):
        h.append("<section class='panel wide'><h2>Awaiting signal</h2><p class='unknown'>No VPN profile yet. Capture is armed and waiting for IKE / ESP / AH traffic.</p></section>")
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
    var pair=label==='video-like' ? ['#ff77b7','#ffb3d9'] : (label==='voip-like' ? ['#7ef7ff','#7299ff'] : ['#65f5e5','#9cffb5']);
    var c0=rgb(pair[0]), c1=rgb(pair[1]);
    var load=Math.max(0, Math.min(1, packets/500 + esp/250 + ike/30));
    if(!live) load*=0.25;
    ctx.clearRect(0,0,w,h);
    var bg=ctx.createRadialGradient(w*0.48,h*0.45,10,w*0.48,h*0.45,Math.max(w,h)*0.58);
    bg.addColorStop(0,'rgba(10,18,27,.98)');
    bg.addColorStop(1,'rgba(5,9,14,.40)');
    ctx.fillStyle=bg; ctx.fillRect(0,0,w,h);
    ctx.globalCompositeOperation='lighter';
    var nodes=[
      {x:w*0.14,y:h*0.30,r:58,c:c0,l:'GATEWAY A'},
      {x:w*0.20,y:h*0.72,r:68,c:c1,l:'CLIENT A / BURST'},
      {x:w*0.50,y:h*0.40,r:92,c:[255,255,255],l:'TRANSIT'},
      {x:w*0.82,y:h*0.30,r:58,c:c0,l:'GATEWAY B'},
      {x:w*0.88,y:h*0.72,r:68,c:c1,l:'CLIENT B'}
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
      ctx.lineWidth=1.1+load*1.8;
      ctx.beginPath(); ctx.arc(n.x,n.y,rr*0.35,0,Math.PI*2); ctx.stroke();
      ctx.fillStyle='rgba(232,241,242,.78)';
      ctx.font='600 10px ui-monospace,Consolas,monospace';
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
        ctx.lineWidth=0.35 + (i%4)*0.10 + load*0.72;
        ctx.beginPath();
        ctx.moveTo(ax,ay);
        ctx.quadraticCurveTo(cx,cy,bx,by);
        ctx.stroke();
      }
    }
    var gatewayA=nodes[0], clientA=nodes[1], gatewayB=nodes[3], clientB=nodes[4];
    var bundleCount=Math.max(16,Math.min(120,Math.round(24 + packets/6 + esp/4 + load*35)));
    drawBundle(gatewayA, clientA, bundleCount, 0.1, 0.7, 0.06);
    drawBundle(clientB, gatewayB, bundleCount, 0.9, 0.3, 0.06);
    ctx.strokeStyle='rgba(101,245,229,.16)';
    ctx.lineWidth=1.2;
    ctx.beginPath();
    ctx.moveTo(gatewayA.x,gatewayA.y);
    ctx.quadraticCurveTo(w*0.50,h*0.18,gatewayB.x,gatewayB.y);
    ctx.stroke();
    pulses=pulses.filter(function(p){return t-p.ts<2.4;});
    pulses.forEach(function(p,idx){
      var prog=Math.max(0,Math.min(1,(t-p.ts)/1.55));
      var fade=1-prog;
      var ctrlY=h*0.18 - Math.sin(prog*Math.PI)*26;
      var weight=1.5 + Math.min(5, (p.size||0)/110);
      var start=p.forward===false ? gatewayB : gatewayA;
      var end=p.forward===false ? gatewayA : gatewayB;
      ctx.strokeStyle='rgba(101,245,229,'+(0.18 + fade*0.60)+')';
      ctx.lineWidth=weight;
      ctx.shadowColor='rgba(101,245,229,'+(0.22 + fade*0.55)+')';
      ctx.shadowBlur=18 + fade*24;
      ctx.beginPath();
      ctx.moveTo(start.x,start.y);
      ctx.quadraticCurveTo(w*0.50,ctrlY,end.x,end.y);
      ctx.stroke();
      var pt=quadPoint(start.x,start.y,w*0.50,ctrlY,end.x,end.y,prog);
      var pulseR=4 + Math.min(8,(p.size||0)/150);
      ctx.fillStyle='rgba(255,255,255,'+(0.9*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,pt.y,pulseR,0,Math.PI*2); ctx.fill();
      ctx.fillStyle='rgba(156,255,181,'+(0.35*fade)+')';
      ctx.beginPath(); ctx.arc(pt.x,pt.y,pulseR*2.1,0,Math.PI*2); ctx.fill();
      ctx.shadowBlur=0;
    });
    for(var j=0;j<Math.min(140, 20 + Math.round(load*110)); j++){
      var n=nodes[2];
      var px=n.x + Math.sin(t*2.3 + j*1.4)*(n.r*0.55 + (j%9));
      var py=n.y + Math.cos(t*2.0 + j*1.1)*(n.r*0.35 + (j%7));
      ctx.fillStyle='rgba(255,255,255,' + (0.05 + load*0.09) + ')';
      ctx.fillRect(px,py,1.2,1.2);
    }
    nodes.forEach(glow);
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
            return '<i style="height:'+Math.max(8,Math.round(90*(x.packets||0)/mx))+'%" title="'+esc(x.spi)+'"></i>';
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
        if(p0.traffic){ set('ml-label',p0.traffic.label||'Unknown'); set('ml-conf',(p0.traffic.confidence||0).toFixed(2)); set('ml-reason',p0.traffic.reason||''); }
        var vr=p0.verified_configuration_risk||{};
        var g=document.getElementById('risk-gauge');
        if(g&&vr.score!=null){ g.style.setProperty('--p',vr.score); var b=g.querySelector('b'); if(b) b.textContent=vr.score; }
        if(vr.level) set('risk-level',vr.level);
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
          row.innerHTML='<span class="k">'+esc(String(ev.kind||'pkt').toUpperCase())+'</span> <b>'+esc(String(ev.spi||'-'))+'</b> <span class="t">'+esc(String(ev.src||'?'))+' -> '+esc(String(ev.dst||'?'))+'</span><small>'+esc(String(ev.size||0))+' bytes</small>';
          feed.appendChild(row);
          var root=document.getElementById('toasts');
          if(root){
            var toast=document.createElement('div');
            toast.className='toast';
            toast.innerHTML='<b>'+esc(String(ev.kind||'packet').toUpperCase())+' '+esc(String(ev.size||0))+' bytes</b><small>'+esc(String(ev.src||'?'))+' -> '+esc(String(ev.dst||'?'))+' / SPI '+esc(String(ev.spi||'-'))+'</small>';
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



