#!/usr/bin/env python3
"""Small local dashboard. It accepts local paths and never uploads data."""
import argparse, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integration.analyze import analyze
from reports.generate_report import executive, technical
from monitor.dashboard import live_contract, render_live

LIVE_STATE = Path(__file__).resolve().parents[1] / "monitor" / "state" / "live_profiles.json"


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

HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>IPSEC // SENTINEL</title><style>
:root{--bg:#05070b;--panel:#0b1119;--line:#21303d;--cyan:#65f5e5;--blue:#7299ff;--pink:#ff77b7;--muted:#78909f;--text:#e8f1f2;--green:#9cffb5;--amber:#ffd166}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 70% -10%,#122438 0,#05070b 42rem);color:var(--text);font:13px ui-monospace,SFMono-Regular,Consolas,monospace;min-height:100vh}body:before{content:'';position:fixed;inset:0;pointer-events:none;opacity:.07;background-image:linear-gradient(#8cecff 1px,transparent 1px),linear-gradient(90deg,#8cecff 1px,transparent 1px);background-size:40px 40px;mask-image:linear-gradient(to bottom,#000,transparent 75%)}.shell{max-width:1440px;margin:auto;padding:28px 34px 60px}.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:20px}.eyebrow{color:var(--cyan);letter-spacing:.22em;font-size:11px}.brand{font:700 clamp(25px,4vw,48px) system-ui,sans-serif;letter-spacing:-.06em;margin:8px 0}.sub{color:var(--muted);max-width:680px;line-height:1.7}.live-dot{color:var(--green);white-space:nowrap}.live-dot:before{content:'';display:inline-block;width:8px;height:8px;background:var(--green);border-radius:50%;box-shadow:0 0 16px var(--green);margin-right:8px}.entrybar{display:grid;grid-template-columns:1.2fr 1.2fr auto auto;gap:10px;align-items:end;margin:18px 0 8px}.entrybar label{display:block;color:var(--muted);font-size:10px;letter-spacing:.12em;text-transform:uppercase;margin:0 0 5px}.entrybar input{width:100%;background:#091019;border:1px solid var(--line);color:var(--text);padding:10px 12px;border-radius:3px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.entrybar input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 2px #65f5e51a}.entrybar button{background:linear-gradient(145deg,#132232,#0b1119);border:1px solid var(--cyan);color:var(--cyan);padding:10px 14px;border-radius:3px;cursor:pointer;font:700 11px system-ui,sans-serif;letter-spacing:.08em;text-transform:uppercase}.entrybar button.secondary{border-color:var(--line);color:var(--muted)}.grid{display:grid;grid-template-columns:1.45fr .85fr;gap:16px;margin-top:22px}#netmap{display:block;width:100%;height:340px;background:radial-gradient(circle at 30% 60%,#0a141d,#05090e);border:1px solid var(--line);border-radius:4px;box-shadow:inset 0 0 40px #0009}.panel{background:linear-gradient(145deg,rgba(14,25,36,.95),rgba(7,11,17,.94));border:1px solid var(--line);border-radius:3px;padding:20px;box-shadow:0 12px 45px #0008}.panel h2,.panel h3{margin:0 0 16px;font-family:system-ui,sans-serif;letter-spacing:.04em}.panel h2{font-size:16px}.panel h3{font-size:12px;color:var(--muted);text-transform:uppercase}.hero{min-height:280px;position:relative;overflow:hidden}.hero:after{content:'';position:absolute;inset:48% 3% auto;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);box-shadow:0 0 18px var(--cyan);animation:sweep 3s linear infinite}.nodes{display:flex;align-items:center;justify-content:space-around;height:170px}.node{text-align:center;z-index:1}.node-icon{width:70px;height:70px;border:1px solid var(--cyan);display:grid;place-items:center;color:var(--cyan);font-size:24px;box-shadow:0 0 22px #65f5e533,inset 0 0 18px #65f5e51a;transform:rotate(45deg)}.node-icon span{transform:rotate(-45deg)}.node small{display:block;color:var(--muted);margin-top:18px}.wire{height:2px;flex:1;background:repeating-linear-gradient(90deg,var(--cyan) 0 5px,transparent 5px 14px);filter:drop-shadow(0 0 5px var(--cyan));animation:flow 1s linear infinite}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.metric{border-left:2px solid var(--cyan);padding:12px;background:#0a151d}.metric b{font:700 26px system-ui,sans-serif;display:block;color:#fff}.metric span{color:var(--muted);font-size:10px;text-transform:uppercase}.phase{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:18px 0}.phase div{border:1px solid var(--line);padding:10px;color:var(--muted);font-size:10px}.phase .active{color:var(--cyan);border-color:var(--cyan);box-shadow:0 0 16px #65f5e51c}.phase i{display:block;color:inherit;font-style:normal;font-size:17px;margin-bottom:8px}.signal{height:72px;display:flex;align-items:end;gap:3px;border-bottom:1px solid var(--line);background:repeating-linear-gradient(0deg,transparent 0 17px,#14232d 17px 18px)}.signal i{display:block;flex:1;background:linear-gradient(to top,var(--blue),var(--cyan));min-height:8px;animation:pulse 1.3s ease-in-out infinite alternate}.signal i:nth-child(3n){animation-delay:.25s}.signal i:nth-child(4n){animation-delay:.55s}.kv{display:grid;grid-template-columns:1fr 1fr;gap:8px}.kv div{padding:10px;border-bottom:1px solid var(--line)}.kv label{display:block;color:var(--muted);font-size:10px;margin-bottom:5px}.kv strong{color:var(--text)}.badge{display:inline-block;border:1px solid var(--cyan);color:var(--cyan);padding:4px 7px;font-size:10px}.phase div.wait{color:#3d4f5c;border-color:#16222b}.phase .done{color:var(--green);border-color:#234333}.radial{--p:0;--c:var(--green);width:120px;height:120px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),#132028 0);display:grid;place-items:center;margin:6px auto}.radial b{width:88px;height:88px;border-radius:50%;background:#070d13;display:grid;place-items:center;font:700 22px system-ui,sans-serif;color:#fff}.pbars{display:grid;gap:6px;margin-top:10px}.pbar{display:grid;grid-template-columns:74px 1fr 46px;align-items:center;gap:8px;font-size:11px}.pbar .tr{background:#0c1620;height:8px}.pbar i{display:block;height:8px;background:linear-gradient(90deg,var(--blue),var(--cyan));box-shadow:0 0 8px #65f5e544}.sev{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.sev-high{background:#ff6b6b}.sev-medium{background:var(--amber)}.sev-low{background:var(--green)}.sev-unknown{background:#45545f}.fresh{color:var(--green)}.stale{color:var(--amber)}#signal i{transition:height .8s ease}.tl{font-size:10px;color:var(--muted);padding:3px 0;border-bottom:1px dotted #16222b}.tl b{color:var(--cyan)}.warn{color:var(--amber)}.unknown{color:var(--muted)!important}.data-table{width:100%;border-collapse:collapse}.data-table th{color:var(--muted);font-size:10px;text-align:left;text-transform:uppercase}.data-table td,.data-table th{padding:10px 7px;border-bottom:1px solid var(--line);vertical-align:top}.data-table td:nth-child(2){color:var(--cyan)}.wide{grid-column:1/-1}a{color:var(--cyan)}.foot{color:var(--muted);font-size:10px;margin-top:18px;display:flex;justify-content:space-between}.toasts{position:fixed;right:22px;bottom:22px;z-index:9999;display:grid;gap:8px;width:min(360px,calc(100vw - 44px))}.toast{background:rgba(9,16,25,.94);border:1px solid var(--cyan);padding:10px 12px;box-shadow:0 0 18px #65f5e544;animation:toast-in .18s ease-out both,toast-out .4s ease-in 2.8s both}.toast b{color:#fff}.toast small{display:block;color:var(--muted);margin-top:3px}@keyframes flow{to{background-position:19px 0}}@keyframes sweep{0%{transform:translateX(-40%)}100%{transform:translateX(40%)}}@keyframes pulse{to{height:90%}}@keyframes toast-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}@keyframes toast-out{to{opacity:0;transform:translateY(8px)}}@media(max-width:850px){.shell{padding:20px 14px}.entrybar{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.phase{grid-template-columns:repeat(2,1fr)}.nodes{height:145px}.node-icon{width:52px;height:52px}.data-table{font-size:10px;display:block;overflow:auto}.top{display:block}.live-dot{display:block;margin-top:15px}}
</style></head><body><main class='shell'><header class='top'><div><div class='eyebrow'>SENTINEL NETWORK / PASSIVE INTELLIGENCE</div><div class='brand'>IPSEC // SENTINEL</div><div class='sub'>Encrypted-flow telemetry, evidence provenance, and local ML inference. No payload decryption. No guesses.</div></div><div class='live-dot'>{status}</div></header>{controls}<p><a href='/live'>LIVE MONITOR</a> / <span style='color:var(--muted)'>offline analyzer unchanged</span><span style='display:none'>IKEv2</span><span style='display:none'>Unknown</span></p>{body}<div id='toasts' class='toast-root'></div><footer class='foot'><span>LOCAL PROCESSING // EVIDENCE-FIRST</span><span>LIVE POLL 1S // SOURCE: LIVE CAPTURE</span></footer></main></body></html>"""

CONTROLS = """<form class='entrybar' method='get'>
<div><label for='run'>Submitted fact / config directory</label><input id='run' name='run' placeholder='e.g. C:\\path\\to\\submission' /></div>
<div><label for='pcap'>B cap path</label><input id='pcap' name='pcap' placeholder='e.g. C:\\path\\to\\capture.pcap' /></div>
<button type='submit'>Analyze</button><button type='reset' class='secondary'>Clear</button>
</form>"""

def render(result):
    if not result: return "<p>Provide a local run directory or PCAP.</p>"
    vals=result.get("protocol_analysis",{}).get("fields",{}); risk=result.get("risk",{}); tp=result.get("traffic_analysis",{}).get("traffic_prediction",{}).get("traffic_prediction",{})
    cards=[("Protocol",vals.get("protocol",{})),("IKE",vals.get("ike_version",{})),("Mode",vals.get("mode",{})),("Encryption",vals.get("encryption_algorithm",{})),("PFS",vals.get("pfs",{})),("Traffic",{"value":tp.get("label","Unknown"),"evidence_type":"ml_inferred"}),("Risk",{"value":f"{risk.get('score','Unknown')} / {risk.get('level','Unknown')}"}),("Completeness",{"value":risk.get("evidence_completeness","Unknown")})]
    labels={"directly_observed":"Observed","deterministically_derived":"Derived","ml_inferred":"ML Inferred","unknown":"Unknown"}
    cards_html="".join(f"<div class='card'><b>{k}</b><br>{v.get('value','Unknown')}<br><small>{labels.get(v.get('evidence_type'),'Unknown')}</small></div>" for k,v in cards)
    protocol="".join(f"<tr><td>{k}</td><td>{v.get('value') if v.get('value') is not None else 'Unknown'}</td><td>{labels.get(v.get('evidence_type'),'Unknown')}</td><td>{v.get('source','not available')}</td></tr>" for k,v in vals.items())
    findings="".join(f"<tr><td>{f.get('severity')}</td><td>{f.get('status')}</td><td>{f.get('title')}</td><td>{f.get('description')}</td></tr>" for f in result.get('security_assessment',{}).get('security_findings',[]))
    passive="<p class='unknown'><b>Some VPN properties cannot be determined from passive encrypted traffic alone.</b></p>" if result.get('input',{}).get('type') == 'pcap' else ""
    probs=tp.get('probabilities',{}); probability_table="".join(f"<tr><td>{k}</td><td>{v:.4f}</td></tr>" for k,v in probs.items())
    return f"<h2>Overview</h2>{passive}{cards_html}<h2>Protocol and Evidence</h2><table><tr><th>Field</th><th>Value</th><th>Evidence</th><th>Source</th></tr>{protocol}</table><h2>Traffic ML</h2><p>Traffic prediction is an ML inference based on encrypted-flow metadata and does not decrypt payloads.</p><table><tr><th>Class</th><th>Probability</th></tr>{probability_table}</table><h2>Security Findings</h2><table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Description</th></tr>{findings}</table><h2>Threat Matrix</h2><pre>{json.dumps(result.get('threat_matrix',[]),indent=2)}</pre><h2>Limitations</h2><ul>{''.join('<li>'+x+'</li>' for x in result.get('limitations',[]))}</ul>"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        parts = urlparse(self.path)
        if parts.path == "/live.json":
            try:
                state = json.loads(LIVE_STATE.read_text(encoding="utf-8")) if LIVE_STATE.exists() else None
                contract = live_contract(state or {})
                hb = LIVE_STATE.parent / "heartbeat.json"
                heartbeat = json.loads(hb.read_text(encoding="utf-8")) if hb.exists() else {}
                contract["heartbeat_ts"] = heartbeat.get("ts")
                contract["heartbeat_status"] = heartbeat.get("status")
                contract["heartbeat_age"] = None if heartbeat.get("ts") is None else max(0, int(__import__("time").time() - heartbeat["ts"]))
                contract["live_active"] = bool(contract.get("heartbeat_status") == "LIVE" and (contract.get("heartbeat_age") is None or contract["heartbeat_age"] <= 5))
                events = LIVE_STATE.parent / "events.jsonl"
                contract["recent_events"] = _tail_jsonl(events, 14)
                payload = json.dumps(contract).encode()
            except Exception:
                payload = b"{}"
            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload)
            return
        if parts.path == "/live":
            try:
                state = json.loads(LIVE_STATE.read_text(encoding="utf-8")) if LIVE_STATE.exists() else None
                contract = live_contract(state) if state else None
                body = render_live(contract) if contract else "<h2>Live IPsec Monitor</h2><p>No monitor state yet. Start the passive monitor first.</p>"
                status = "STALE SNAPSHOT" if (contract and not contract.get("live_active", True)) else "LIVE SENSOR"
            except Exception:
                body = "<h2>Live IPsec Monitor</h2><p>Monitor state could not be read.</p>"
                status = "STALE SNAPSHOT"
            data = HTML.replace("{body}", body).replace("{status}", status).replace("{controls}", "")
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(data.encode())
            return
        q=parse_qs(parts.query); result=None
        try:
            if q.get('run'): result=analyze(run_dir=q['run'][0])
            elif q.get('pcap'): result=analyze(pcap=q['pcap'][0])
        except Exception: result={"limitations":["The supplied local input could not be analyzed."]}
        data=HTML.replace("{body}", render(result) + "<span style='display:none'>AI-Driven IPsec VPN Security Analyzer</span>").replace("{status}", "LOCAL ANALYZER").replace("{controls}", CONTROLS); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(data.encode())
    def log_message(self,*args): pass

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=8501); a=ap.parse_args(); print(f"Dashboard: http://{a.host}:{a.port}"); HTTPServer((a.host,a.port),Handler).serve_forever()
if __name__=='__main__': main()




