#!/usr/bin/env python3
"""Generate JSON, executive HTML, and technical HTML from a Phase 6 result."""
import argparse, html, json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    from ui.theme import THEME_CSS, icon, seal
except ImportError:
    THEME_CSS = ""
    icon = lambda *a, **k: ""
    seal = lambda *a, **k: ""

_NAV = [("Analyzer", "/"), ("Live monitor", "/live"),
        ("Executive", "/executive"), ("Technical", "/technical")]

REPORT_CSS = r"""
main h1{font-size:clamp(31px,4vw,48px);letter-spacing:-.04em;margin-bottom:.35em;color:var(--ink)}
main h2{font-size:23px;font-weight:800;letter-spacing:-.02em;margin:1.7em 0 .5em;padding-top:.5em;border-top:1px solid var(--line)}
main h2:first-of-type{border-top:0;margin-top:.4em}
main p{color:var(--muted);max-width:78ch}
main p.risk{font:700 36px/1.05 var(--font-display);color:var(--accent);letter-spacing:-.04em;margin:.2em 0}
main ul{color:var(--muted);padding-left:20px}
main li{margin-bottom:6px}
.statement{background:#ffffff;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:var(--r-lg);padding:20px 22px;margin:.8em 0 1.4em;box-shadow:var(--sh);font-size:19px;line-height:1.55;color:var(--ink)}
.statement b{font-weight:800}
.statement .sub{display:block;margin-top:8px;font-size:15px;color:var(--muted)}
.panel-lite{background:#faf9fe;border:1px solid var(--line);border-radius:var(--r-lg);padding:22px 24px;margin:.8em 0 1.4em}
.statrow{display:flex;gap:12px;margin-top:18px;flex-wrap:wrap}
.mini{flex:1;min-width:140px;background:#ffffff;border:1px solid var(--line);border-radius:var(--r);padding:12px 14px}
.mini b{display:block;font-size:22px;color:var(--ink)}
.mini b small{font-size:13px;color:var(--muted);font-weight:600}
.mini span{display:block;margin-top:4px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
main table{width:100%;border-collapse:collapse;font-size:12.5px;margin:.6em 0 1.3em;background:#faf9fe;border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
main th{text-align:left;padding:9px 12px;background:#f3f2fb;color:var(--muted);font:600 10px/1.3 var(--font-mono);letter-spacing:.12em;text-transform:uppercase;border-bottom:1px solid var(--line)}
main td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;color:var(--ink)}
main pre{font:12px/1.6 var(--font-mono);color:#33314d;background:#f7f6fd;border:1px solid var(--line);border-radius:var(--r);padding:14px;overflow:auto;max-height:420px}
main code{font-family:var(--font-mono);color:var(--accent)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;border:1px solid var(--line-2);font:600 9.5px/1.7 var(--font-mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.badge.directly_observed{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.badge.deterministically_derived{color:var(--p-der);border-color:color-mix(in srgb,var(--p-der) 40%,transparent)}
.badge.ml_inferred{color:var(--p-ml);border-color:color-mix(in srgb,var(--p-ml) 40%,transparent)}
.badge.unknown{color:var(--p-unk)}
.flow{position:relative;display:flex;justify-content:space-between;gap:10px;margin:1em 0 .4em;padding:26px 12px 16px;flex-wrap:wrap}
.flow .track{position:absolute;left:28px;right:28px;top:45px;height:3px;border-radius:2px;background:var(--line)}
.fdot{position:absolute;top:39px;left:28px;width:15px;height:15px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent);animation:fdot 8s linear infinite}
@keyframes fdot{0%{left:28px;opacity:0}5%{opacity:1}90%{opacity:1}96%,100%{left:calc(100% - 43px);opacity:0}}
.fblock{position:relative;z-index:1;flex:1;min-width:120px;max-width:220px;text-align:center;background:#ffffff;border:1.5px solid var(--line-2);border-radius:var(--r);padding:12px 8px;animation-duration:8s;animation-iteration-count:infinite;animation-timing-function:ease-in-out}
.fblock b{display:block;font-size:15px;color:var(--ink)}
.fblock span{display:block;margin-top:4px;font-size:12.5px;color:var(--muted)}
.fb1{animation-name:fglow1}.fb2{animation-name:fglow2}.fb3{animation-name:fglow3}.fb4{animation-name:fglow4}
@keyframes fglow1{0%,5%{border-color:var(--line-2);box-shadow:none;background:#fff}12%{border-color:var(--accent);box-shadow:0 0 0 3px rgba(179,78,0,.20),0 0 18px rgba(224,123,26,.5);background:#fff8f1}22%,100%{border-color:var(--line-2);box-shadow:none;background:#fff}}
@keyframes fglow2{0%,30%{border-color:var(--line-2);box-shadow:none;background:#fff}37%{border-color:var(--accent);box-shadow:0 0 0 3px rgba(179,78,0,.20),0 0 18px rgba(224,123,26,.5);background:#fff8f1}47%,100%{border-color:var(--line-2);box-shadow:none;background:#fff}}
@keyframes fglow3{0%,55%{border-color:var(--line-2);box-shadow:none;background:#fff}62%{border-color:var(--accent);box-shadow:0 0 0 3px rgba(179,78,0,.20),0 0 18px rgba(224,123,26,.5);background:#fff8f1}72%,100%{border-color:var(--line-2);box-shadow:none;background:#fff}}
@keyframes fglow4{0%,80%{border-color:var(--line-2);box-shadow:none;background:#fff}87%{border-color:var(--accent);box-shadow:0 0 0 3px rgba(179,78,0,.20),0 0 18px rgba(224,123,26,.5);background:#fff8f1}97%,100%{border-color:var(--line-2);box-shadow:none;background:#fff}}
@media (prefers-reduced-motion:reduce){.fdot,.fblock{animation:none}}
"""


def esc(value): return html.escape(str(value if value is not None else "Unknown"))
def _short_ts(value):
    s = str(value or "")
    return s[:16].replace("T", " ") if len(s) >= 16 else (s or "Unknown")
def _pct(conf):
    return f"{conf * 100:.1f}%" if isinstance(conf, (int, float)) else "Unknown"
_EVIDENCE_WORDS = {"directly_observed": "Seen directly",
                   "deterministically_derived": "Worked out",
                   "ml_inferred": "AI's guess"}
def field_rows(fields):
    """Demo view: only properties with a real value. SPI hashes stay hidden
    and every Unknown collapses into the one-liner below the table."""
    rows = []
    for k, v in (fields or {}).items():
        if k == "spis" or (v or {}).get("value") in (None, "", [], "Unknown"):
            continue
        et = esc((v or {}).get("evidence_type"))
        words = _EVIDENCE_WORDS.get((v or {}).get("evidence_type"), et)
        rows.append(f"<tr><td>{esc(k)}</td><td>{esc(v.get('value'))}</td><td><span class='badge {et}'>{words}</span></td><td>{esc(v.get('source'))}</td></tr>")
    return "".join(rows)
def unknown_count(fields):
    return sum(1 for v in (fields or {}).values()
               if (v or {}).get("value") in (None, "", [], "Unknown"))
def unknown_line(fields):
    n = unknown_count(fields)
    if not n:
        return ""
    return (f"<p class='unknown'>+{n} more properties honestly reported as Unknown "
            f"&mdash; SENTINEL does not guess.</p>")
def findings(result):
    fs = result.get("security_assessment", {}).get("security_findings", [])
    return "".join(f"<tr><td>{esc(f.get('severity'))}</td><td>{esc(f.get('status'))}</td><td>{esc(f.get('title'))}</td><td>{esc(f.get('description'))}</td><td>{esc(f.get('recommendation'))}</td></tr>" for f in fs)
def traffic(result):
    """Traffic prediction from either a Phase 6 result or a live result."""
    ta = result.get("traffic_analysis") or {}
    tp = ta.get("traffic_prediction") or {}
    if isinstance(tp.get("traffic_prediction"), dict):
        tp = tp["traffic_prediction"]
    return tp
def outsider_statement(result):
    """One plain-language container for what a passive observer can still
    see. Rendered only when the result actually carries such threats."""
    if not (result.get("threat_matrix") or result.get("residual_threats")):
        return ""
    return ("<h2>What an outsider can still see</h2><div class='statement'>"
            "Message sizes, timing and endpoints stay visible on the wire &mdash; "
            "moderate risk. The message contents stay encrypted.%s</div>"
            % _outsider_sub(result))
def _outsider_sub(result):
    rows = result.get("threat_matrix") or result.get("residual_threats") or []
    if not rows:
        return ""
    r = rows[0]
    return (f"<span class='sub'>Observed on the wire: {esc(r.get('condition'))} "
            f"&middot; Risk: {esc(r.get('risk'))}.</span>")
def _runner_up(tp):
    probs = (tp or {}).get("probabilities") or {}
    label = str((tp or {}).get("label") or "").lower()
    cands = sorted(((k, v) for k, v in probs.items()
                    if str(k).lower() != label and isinstance(v, (int, float))),
                   key=lambda kv: -kv[1])
    if not cands:
        return ""
    name, conf = cands[0]
    pretty = {"icmp": "ICMP", "web": "Web"}.get(str(name).lower(),
                                                str(name).replace("_", " ").title())
    return (f"<span class='sub'>Runner-up: {esc(pretty)} {_pct(conf)} "
            f"&mdash; the AI weighed this option too.</span>")
def limitations_line():
    return ("<h2>Limitations and unknowns</h2><div class='statement'>"
            "Some checks need a look inside the tunnel. Those stay Unknown "
            "&mdash; reported, never guessed.</div>")
def report_topbar(active=""):
    nav = "".join(
        "<a href='%s'%s>%s</a>" % (href, " aria-current='page'" if href == active else "", label)
        for label, href in _NAV
    )
    return ("<a class='skip' href='#main'>Skip to content</a>"
            "<nav class='topbar' aria-label='Primary'>"
            "<span class='glyph' aria-hidden='true'>%s</span>"
            "<span class='brand'>IPSEC <i>//</i> SENTINEL</span>"
            "<span class='nav'>%s</span></nav>" % (icon("shield"), nav))


def _risk_block(result):
    """Verified-configuration risk seal, surfaced on the executive report."""
    risk = result.get("risk", {}) or {}
    score = risk.get("score")
    level = risk.get("level")
    completeness = risk.get("evidence_completeness")
    if score == 0:
        note = ("No proven rule failures. Unknowns remain unknown &mdash; "
                "this is not a clean bill of health.")
    elif score is None:
        note = "Risk was not evaluated for this snapshot."
    else:
        note = "Penalty is the sum of proven rule failures only."
    try:
        comp = "Unknown" if completeness is None else f"{float(completeness) * 100:.0f}%"
    except (TypeError, ValueError):
        comp = "Unknown"
    level_txt = str(level).replace("-", " ").title() if level else "Unknown"
    score_txt = esc(score) if score is not None else "&ndash;"
    return (
        "<h2>Verified configuration risk</h2>"
        "<div class='panel-lite'><div class='seal-wrap'>%s<div><p class='sec-note' style='max-width:48ch'>%s</p>"
        "<p class='sec-note' style='margin-top:8px'>Evidence completeness: <b>%s</b></p>"
        "</div></div>"
        "<div class='statrow'><div class='mini'><b>%s<small>/100</small></b><span>Penalty score</span></div>"
        "<div class='mini'><b>%s</b><span>Risk level</span></div>"
        "<div class='mini'><b>%s</b><span>Evidence coverage</span></div></div></div>"
        % (seal(score, level), note, comp, score_txt, esc(level_txt), comp)
    )


def base(title, body, active=""):
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta name='color-scheme' content='light'><title>{esc(title)}</title>"
            f"<style>{THEME_CSS}{REPORT_CSS}</style></head><body>"
            f"<div class='shell'>{report_topbar(active)}"
            f"<main id='main' style='padding-top:18px'>{body}</main>"
            f"<footer class='foot'><span>IPSEC // SENTINEL &middot; LOCAL PROCESSING &middot; "
            f"NO PAYLOAD DECRYPTION</span><span>Unknown is a result, not a failure.</span>"
            f"<span class='sr'>AI-Driven IPsec VPN Security Analyzer</span>"
            f"<span class='sr'>IKEv2</span><span class='sr'>Unknown</span></footer>"
            f"</div></body></html>")


def executive(result):
    tp=traffic(result)
    fs=result.get("security_assessment",{}).get("security_findings",[]); top=[f for f in fs if f.get("status") in {"fail","warning"}][:5]
    bullet="".join(f"<li>{esc(f.get('title'))}: {esc(f.get('recommendation') or f.get('description'))}</li>" for f in top) or "<li>No proven failing security rules.</li>"
    body=(f"<h1>IPsec VPN Executive Assessment</h1><p>Generated {_short_ts(result.get('generated_at'))}</p>"
          f"{_risk_block(result)}"
          f"<h2>Traffic behavior</h2><div class='statement'>AI's guess: <b>{esc(tp.get('label'))}</b> &mdash; {_pct(tp.get('confidence'))} confident.{_runner_up(tp)}</div>"
          f"{outsider_statement(result)}"
          f"<h2>Priority findings</h2><ul>{bullet}</ul>"
          f"{limitations_line()}")
    return base("Executive IPsec Assessment",body,active="/executive")


def technical(result):
    fields=result.get("protocol_analysis",{}).get("fields",{}); sec=result.get("security_assessment",{}); tp=traffic(result)
    risk=result.get("risk",{}) or {}; score=risk.get("score"); level=risk.get("level")
    if score is None:
        risk_stmt="Risk was not evaluated for this snapshot."
    elif score == 0:
        risk_stmt="Verified risk: <b>0 (low)</b> &mdash; no proven rule failures."
    else:
        risk_stmt=f"Verified risk: <b>{esc(score)} ({esc(level)})</b> &mdash; from proven rule failures only."
    sec_findings=sec.get("security_findings",[]) or []
    findings_html=(f"<h2>Security findings</h2><table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Description</th><th>Recommendation</th></tr>{findings(result)}</table>" if sec_findings else "")
    body=(f"<h1>IPsec VPN Technical Assessment</h1><p>Analysis version: {esc(result.get('analysis_version'))}</p>"
          f"<h2>How it works</h2><div class='flow' role='img' aria-label='Data flows from capture to parse to infer to assess'>"
          f"<div class='track'></div><div class='fdot'></div>"
          f"<div class='fblock fb1'><b>1 &middot; Capture</b><span>Listen</span></div>"
          f"<div class='fblock fb2'><b>2 &middot; Parse</b><span>Read packets</span></div>"
          f"<div class='fblock fb3'><b>3 &middot; Infer</b><span>AI guesses</span></div>"
          f"<div class='fblock fb4'><b>4 &middot; Assess</b><span>Safety verdict</span></div></div>"
          f"<h2>Risk</h2><div class='statement'>{risk_stmt}</div>"
          f"<h2>Protocol and evidence provenance</h2><table><tr><th>Field</th><th>Value</th><th>Evidence</th><th>Source</th></tr>{field_rows(fields)}</table>{unknown_line(fields)}"
          f"<h2>Traffic ML</h2><div class='statement'>AI's guess: <b>{esc(tp.get('label'))}</b> &mdash; {_pct(tp.get('confidence'))} confident.{_runner_up(tp)}</div>"
          f"{findings_html}{outsider_statement(result)}{limitations_line()}")
    return base("Technical IPsec Assessment",body,active="/technical")


def generate(result, out_dir, stem):
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    (out/f"assessment_{stem}.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (out/f"executive_{stem}.html").write_text(executive(result),encoding="utf-8")
    (out/f"technical_{stem}.html").write_text(technical(result),encoding="utf-8")


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--input",required=True); ap.add_argument("--out",default="reports/results"); ap.add_argument("--stem")
    a=ap.parse_args(); result=json.loads(Path(a.input).read_text(encoding="utf-8")); stem=a.stem or Path(result.get("input",{}).get("source","assessment")).name or "assessment"; generate(result,a.out,stem)

if __name__ == "__main__": main()
