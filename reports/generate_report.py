#!/usr/bin/env python3
"""Generate JSON, executive HTML, and technical HTML from a Phase 6 result."""
import argparse, html, json
from pathlib import Path


def esc(value): return html.escape(str(value if value is not None else "Unknown"))
def field_rows(fields):
    return "".join(f"<tr><td>{esc(k)}</td><td>{esc(v.get('value'))}</td><td><span class='badge {esc(v.get('evidence_type'))}'>{esc(v.get('evidence_type'))}</span></td><td>{esc(v.get('source'))}</td></tr>" for k,v in fields.items())
def findings(result):
    fs = result.get("security_assessment", {}).get("security_findings", [])
    return "".join(f"<tr><td>{esc(f.get('severity'))}</td><td>{esc(f.get('status'))}</td><td>{esc(f.get('title'))}</td><td>{esc(f.get('description'))}</td><td>{esc(f.get('recommendation'))}</td></tr>" for f in fs)
def base(title, body): return f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(title)}</title><style>body{{font:15px system-ui;margin:2rem;color:#17202a}}h1{{color:#123b5d}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #d5dde5;padding:.45rem;text-align:left}}.badge{{padding:.15rem .4rem;border-radius:4px;font-size:.8rem}}.directly_observed{{background:#d7f5e5}}.deterministically_derived{{background:#dcecff}}.ml_inferred{{background:#fff0bd}}.unknown{{background:#eee;color:#555}}.risk{{font-size:2rem}}</style></head><body>{body}</body></html>"


def executive(result):
    risk=result.get("risk",{}); tp=result.get("traffic_analysis",{}).get("traffic_prediction",{}).get("traffic_prediction",{})
    fs=result.get("security_assessment",{}).get("security_findings",[]); top=[f for f in fs if f.get("status") in {"fail","warning"}][:5]
    bullet="".join(f"<li>{esc(f.get('title'))}: {esc(f.get('recommendation') or f.get('description'))}</li>" for f in top) or "<li>No proven failing security rules.</li>"
    body=f"<h1>IPsec VPN Executive Assessment</h1><p>Generated {esc(result.get('generated_at'))}</p><p class='risk'>Risk score: {esc(risk.get('score'))}/100, {esc(risk.get('level'))}</p><p>Evidence completeness: {esc(risk.get('evidence_completeness'))}</p><h2>Traffic behavior</h2><p>{esc(tp.get('label'))} (model confidence: {esc(tp.get('confidence'))})</p><h2>Priority findings</h2><ul>{bullet}</ul><h2>Limitations</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in result.get('limitations',[]))}</ul>"
    return base("Executive IPsec Assessment",body)


def technical(result):
    fields=result.get("protocol_analysis",{}).get("fields",{}); sec=result.get("security_assessment",{}); tp=result.get("traffic_analysis",{})
    threat="".join(f"<tr><td>{esc(x.get('threat'))}</td><td>{esc(x.get('condition'))}</td><td>{esc(x.get('risk'))}</td><td>{esc(x.get('evidence_type'))}</td></tr>" for x in result.get('threat_matrix',[]))
    body=f"<h1>IPsec VPN Technical Assessment</h1><p>Analysis version: {esc(result.get('analysis_version'))}; source: {esc(result.get('input',{}).get('source'))}</p><h2>Risk</h2><pre>{esc(json.dumps(result.get('risk',{}),indent=2))}</pre><h2>Protocol and evidence provenance</h2><table><tr><th>Field</th><th>Value</th><th>Evidence</th><th>Source</th></tr>{field_rows(fields)}</table><h2>Traffic ML</h2><pre>{esc(json.dumps(tp,indent=2))}</pre><h2>Security findings</h2><table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Description</th><th>Recommendation</th></tr>{findings(result)}</table><h2>Threat matrix</h2><table><tr><th>Threat</th><th>Condition</th><th>Risk</th><th>Evidence</th></tr>{threat}</table><h2>Limitations</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in result.get('limitations',[]))}</ul>"
    return base("Technical IPsec Assessment",body)


def generate(result, out_dir, stem):
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    (out/f"assessment_{stem}.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (out/f"executive_{stem}.html").write_text(executive(result),encoding="utf-8")
    (out/f"technical_{stem}.html").write_text(technical(result),encoding="utf-8")


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--input",required=True); ap.add_argument("--out",default="reports/results"); ap.add_argument("--stem")
    a=ap.parse_args(); result=json.loads(Path(a.input).read_text(encoding="utf-8")); stem=a.stem or Path(result.get("input",{}).get("source","assessment")).name or "assessment"; generate(result,a.out,stem)

if __name__ == "__main__": main()
