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

HTML = """<!doctype html><html><head><meta charset='utf-8'><title>AI-Driven IPsec VPN Security Analyzer</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}input,button{padding:.6rem;margin:.25rem}button{background:#123b5d;color:white;border:0;border-radius:4px}.card{display:inline-block;vertical-align:top;background:#f3f6f8;padding:1rem;margin:.5rem;min-width:150px;border-radius:8px}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border-bottom:1px solid #ddd;text-align:left}.unknown{color:#666}</style></head><body><h1>AI-Driven IPsec VPN Security Analyzer</h1><p>Local analysis of encrypted-flow behavior and IPsec security evidence. Phase 4 traffic labels are ML inference; VPN properties retain observed, derived, and unknown provenance.</p><form><input name='run' placeholder='run directory' size='65'><input name='pcap' placeholder='PCAP path' size='45'><button>Analyze</button></form><p><a href='/live'>Live Monitor</a> — continuous passive IPsec observation (offline analysis above is unchanged).</p>{body}</body></html>"""

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
        if parts.path == "/live":
            try:
                state = json.loads(LIVE_STATE.read_text(encoding="utf-8")) if LIVE_STATE.exists() else None
                body = render_live(live_contract(state)) if state else "<h2>Live IPsec Monitor</h2><p>No monitor state yet. Start the passive monitor first.</p>"
            except Exception:
                body = "<h2>Live IPsec Monitor</h2><p>Monitor state could not be read.</p>"
            data = HTML.replace("{body}", body)
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(data.encode())
            return
        q=parse_qs(parts.query); result=None
        try:
            if q.get('run'): result=analyze(run_dir=q['run'][0])
            elif q.get('pcap'): result=analyze(pcap=q['pcap'][0])
        except Exception: result={"limitations":["The supplied local input could not be analyzed."]}
        data=HTML.replace("{body}", render(result)); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(data.encode())
    def log_message(self,*args): pass

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=8501); a=ap.parse_args(); print(f"Dashboard: http://{a.host}:{a.port}"); HTTPServer((a.host,a.port),Handler).serve_forever()
if __name__=='__main__': main()
