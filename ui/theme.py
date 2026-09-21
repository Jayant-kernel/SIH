"""Shared presentation layer for SENTINEL.

One source of truth for the analyzer shell, the live monitor, and the
reports: design tokens, HUD components, and inline SVG builders.

Pure CSS + inline SVG + locally bundled fonts. No external CDNs or build
step, so the dashboard stays fully offline and standard-library-only. Noto
Sans is embedded as base64 @font-face so single-file reports stay portable.
"""
import base64
import html as _html
import math as _math
from pathlib import Path

_FONT_DIR = Path(__file__).resolve().parent / "fonts"


def _font_css():
    faces = []
    for weight in (400, 500, 600, 700):
        path = _FONT_DIR / f"noto-sans-{weight}.woff2"
        if not path.exists():
            continue
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        faces.append(
            "@font-face{font-family:'Noto Sans';font-style:normal;font-weight:%d;"
            "font-display:swap;src:url(data:font/woff2;base64,%s) format('woff2')}"
            % (weight, data)
        )
    cyber = _FONT_DIR / "orbitron-cyber.woff2"
    if cyber.exists():
        data = base64.b64encode(cyber.read_bytes()).decode("ascii")
        faces.append(
            "@font-face{font-family:'Orbitron';font-style:normal;font-weight:700 900;"
            "font-display:swap;src:url(data:font/woff2;base64,%s) format('woff2')}"
            % data
        )
    return "".join(faces)


FONT_CSS = _font_css()

# --------------------------------------------------------------------------
# Design tokens + component CSS.
# Typography is Noto Sans (bundled locally) for UI and display text, with a
# monospace face reserved for data, IDs, and tabular figures.
# --------------------------------------------------------------------------
THEME_CSS = FONT_CSS + r"""
:root{
  /* Government light palette: indigo structure, saffron accent, green success. */
  --bg:#ffffff; --bg-2:#f4f2fb; --panel:#ffffff; --panel-2:#ffffff;
  --line:#e6e3f2; --line-2:#cfc9e8;
  --ink:#1c1b33; --muted:#57556f; --dim:#8b89a3;
  --accent:#b34e00; --accent-2:#e07b1a;
  --brand:#2b2158; --brand-2:#4a2bc2;
  --ok:#0f7a37; --warn:#a8690a; --bad:#c0392b; --crit:#a11b52;
  --p-obs:#0f7a37; --p-der:#2f5bd0; --p-ml:#a8690a; --p-unk:#8b89a3;
  --r-xl:20px; --r-lg:14px; --r:10px; --r-sm:8px; --r-xs:5px;
  --sp:8px; --gap:24px; --gap-lg:32px;
  --sh:0 14px 34px -22px rgba(43,33,88,.28),0 2px 8px -6px rgba(43,33,88,.12);
  --sh-in:inset 0 1px 0 rgba(255,255,255,.7);
  --ease:cubic-bezier(.32,.72,0,1);
  --font-display:"Noto Sans","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
  --font-cyber:"Orbitron","Noto Sans","Segoe UI",system-ui,sans-serif;
  --font-garamond:"Garamond","Adobe Garamond Pro","Palatino Linotype","Book Antiqua",Palatino,Georgia,serif;
  --font-sans:"Noto Sans","Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
  --font-mono:"Noto Sans Mono","Cascadia Code","Cascadia Mono",ui-monospace,Consolas,"SFMono-Regular",monospace;
  --nav-h:64px;
}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{
  margin:0;min-height:100dvh;color:var(--ink);background:var(--bg);
  font:17px/1.65 var(--font-sans);letter-spacing:.003em;
  font-variant-numeric:tabular-nums;
  text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;
}
body::before{
  content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;
  background:
    radial-gradient(60rem 40rem at 84% -14%,rgba(74,43,194,.09),transparent 60%),
    radial-gradient(46rem 32rem at 6% 2%,rgba(224,123,26,.07),transparent 58%),
    linear-gradient(180deg,#ffffff 0,#f7f6fd 44rem);
}
body::after{
  content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.6;
  background-image:radial-gradient(rgba(74,43,194,.045) 1px,transparent 1px);
  background-size:3px 3px;
  -webkit-mask-image:linear-gradient(180deg,#000,transparent 70%);
  mask-image:linear-gradient(180deg,#000,transparent 70%);
}
h1,h2,h3,h4{margin:0;font-family:var(--font-display);font-weight:650;line-height:1.1}
p{margin:0 0 1em}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
button{font:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-xs)}
.skip{position:absolute;left:-999px;top:0;background:#000;color:#fff;padding:10px 16px;z-index:100}
.skip:focus{left:12px;top:12px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

/* ---------- shell ---------- */
.shell{max-width:1320px;margin:0 auto;padding:0 22px 72px}
main{display:block}
.topbar{
  position:sticky;top:12px;z-index:40;display:flex;align-items:center;gap:18px;
  margin:14px 0 34px;padding:12px 14px 12px 18px;border-radius:999px;
  background:rgba(255,255,255,.9);border:1px solid var(--line);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);box-shadow:var(--sh);
}
.glyph{
  width:30px;height:30px;flex:0 0 auto;border-radius:9px;display:grid;place-items:center;
  background:linear-gradient(150deg,rgba(179,78,0,.24),rgba(255,192,113,.12));
  border:1px solid var(--line-2);box-shadow:var(--sh-in)
}
.glyph svg{width:17px;height:17px}
.brand{font-family:var(--font-display);font-weight:650;letter-spacing:-.02em;font-size:16px;white-space:nowrap}
.brand i{color:var(--accent);font-style:normal}
.nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
.nav a{
  color:var(--muted);padding:7px 13px;border-radius:999px;font-size:12.5px;letter-spacing:.02em;
  transition:color .25s var(--ease),background .25s var(--ease)
}
.nav a:hover{color:var(--ink);background:rgba(255,255,255,.05);text-decoration:none}
.nav a[aria-current=page]{color:#ffffff;background:var(--accent);font-weight:600}
.status{
  display:inline-flex;align-items:center;gap:7px;color:var(--muted);font:11px/1 var(--font-mono);
  letter-spacing:.14em;text-transform:uppercase;white-space:nowrap
}
.status::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok)}
.status[data-state=stale]::before{background:var(--warn);box-shadow:0 0 12px var(--warn)}
.status[data-state=off]::before{background:var(--dim);box-shadow:none}

/* ---------- type ---------- */
.eyebrow{
  display:inline-flex;align-items:center;gap:8px;color:var(--accent);
  font:600 10.5px/1 var(--font-mono);letter-spacing:.24em;text-transform:uppercase
}
.eyebrow::before{content:"";width:16px;height:1px;background:linear-gradient(90deg,var(--accent),transparent)}
h1.display{font-size:clamp(34px,5vw,58px);letter-spacing:-.04em;text-wrap:balance;margin:.24em 0 .3em}
h1.display.hero{font-family:"Helvetica Neue",Helvetica,Arial,"Noto Sans",sans-serif;font-weight:700;font-size:clamp(37px,5.4vw,64px);letter-spacing:-.02em;line-height:1.1}
h2.sec{font-size:clamp(22px,2.6vw,30px);letter-spacing:-.02em}
.lede{color:var(--muted);max-width:66ch;line-height:1.7;font-size:18px}
.mono{font-family:var(--font-mono)}
.sec-note{color:var(--dim);font-size:12.5px}

/* ---------- panels (HUD modules) ---------- */
.panel{
  position:relative;background:var(--panel);
  border:1px solid var(--line);border-radius:var(--r-xl);padding:26px 26px 28px;box-shadow:var(--sh)
}
.panel::before,.panel::after{
  content:"";position:absolute;width:15px;height:15px;border:1.5px solid var(--line-2);pointer-events:none
}
.panel::before{top:11px;left:11px;border-right:0;border-bottom:0;border-top-left-radius:7px}
.panel::after{bottom:11px;right:11px;border-left:0;border-top:0;border-bottom-right-radius:7px}
.panel-h{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.panel-h .code{color:var(--dim);font:600 10.5px/1 var(--font-mono);letter-spacing:.2em;text-transform:uppercase}
.panel-h .meta{margin-left:auto;color:var(--dim);font:11px/1 var(--font-mono)}
.panel-h h3{font-size:17px;letter-spacing:-.01em}

/* ---------- grid ---------- */
.bento{display:grid;grid-template-columns:repeat(12,1fr);gap:var(--gap)}
.c3{grid-column:span 3}.c4{grid-column:span 4}.c5{grid-column:span 5}
.c6{grid-column:span 6}.c7{grid-column:span 7}.c8{grid-column:span 8}.c12{grid-column:span 12}
.stack{display:grid;gap:var(--gap);align-content:start}

/* ---------- form ---------- */
.form{display:grid;grid-template-columns:1.35fr 1.35fr auto auto;gap:14px;align-items:end}
.field label{display:block;color:var(--muted);font:600 18px/1.2 var(--font-mono);letter-spacing:.16em;text-transform:uppercase;margin-bottom:9px}
.field input{
  width:100%;background:#faf9fe;border:1px solid var(--line);color:var(--ink);
  padding:16px 18px;border-radius:var(--r);font:29px var(--font-garamond);
  transition:border-color .25s var(--ease),box-shadow .25s var(--ease)
}
.field input:hover{border-color:var(--line-2)}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(179,78,0,.18)}
.field .hint{color:var(--dim);font-size:11.5px;margin-top:6px}

/* ---------- buttons ---------- */
.btn{
  display:inline-flex;align-items:center;gap:10px;border-radius:999px;cursor:pointer;
  padding:13px 10px 13px 20px;border:1px solid var(--accent);color:#ffffff;font-weight:650;font-size:15px;
  background:linear-gradient(180deg,var(--accent),#d9741f);
  transition:transform .2s var(--ease),box-shadow .2s var(--ease),filter .2s var(--ease)
}
.btn:hover{box-shadow:0 12px 26px -14px rgba(179,78,0,.9);filter:saturate(1.08)}
.btn:active{transform:scale(.98)}
.btn .orb{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;background:rgba(255,255,255,.22)}
.btn .orb svg{width:13px;height:13px}
.btn.ghost{background:transparent;color:var(--muted);border-color:var(--line-2);padding:11px 18px}
.btn.ghost:hover{color:var(--ink);border-color:var(--muted);box-shadow:none}
.btn[disabled]{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}

/* ---------- provenance chips ---------- */
.chip{
  display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:999px;
  font:600 10px/1.7 var(--font-mono);letter-spacing:.1em;text-transform:uppercase;
  border:1px solid var(--line-2);color:var(--muted);white-space:nowrap
}
.chip .d{width:7px;height:7px;border-radius:2px;transform:rotate(45deg)}
.chip[data-p=observed]{color:var(--p-obs);border-color:color-mix(in srgb,var(--p-obs) 40%,transparent)}
.chip[data-p=observed] .d{background:var(--p-obs)}
.chip[data-p=derived]{color:var(--p-der);border-color:color-mix(in srgb,var(--p-der) 40%,transparent)}
.chip[data-p=derived] .d{background:var(--p-der);border-radius:50%}
.chip[data-p=ml]{color:var(--p-ml);border-color:color-mix(in srgb,var(--p-ml) 40%,transparent)}
.chip[data-p=ml] .d{background:var(--p-ml);border-radius:50%;box-shadow:inset 0 0 0 2px var(--panel)}
.chip[data-p=unknown]{color:var(--p-unk);border-color:var(--line)}
.chip[data-p=unknown] .d{background:transparent;border:1px solid var(--p-unk)}

/* ---------- spectrum ribbon (repeated motif) ---------- */
.spectrum{border:1px solid var(--line);border-radius:var(--r);overflow:hidden;background:#faf9fe}
.spectrum .bar{display:flex;height:12px}
.spectrum .seg{transition:flex-grow .6s var(--ease)}
.seg[data-p=observed]{background:var(--p-obs)}.seg[data-p=derived]{background:var(--p-der)}
.seg[data-p=ml]{background:var(--p-ml)}.seg[data-p=unknown]{background:var(--p-unk)}
.spectrum .legend{display:flex;flex-wrap:wrap;gap:6px 16px;padding:9px 12px;border-top:1px solid var(--line)}
.spectrum .legend span{color:var(--muted);font:11px/1.5 var(--font-mono)}
.spectrum .legend b{color:var(--ink)}

/* ---------- risk seal ---------- */
.seal-wrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.seal{position:relative;width:172px;height:172px;flex:0 0 auto}
.seal svg{width:100%;height:100%;transform:rotate(-90deg)}
.seal .val{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.seal .val b{font:700 44px/1 var(--font-display);letter-spacing:-.04em;display:block}
.seal .val span{display:block;margin-top:4px;font:600 12.5px/1 var(--font-mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}
.verdict{font:800 clamp(28px,3.4vw,44px)/1.1 var(--font-display);letter-spacing:-.02em;margin:.12em 0 .1em}
.verdict[data-v=good]{color:var(--ok)}
.verdict[data-v=bad]{color:var(--bad)}
.verdict[data-v=unknown]{color:var(--muted)}

/* ---------- meters & bars ---------- */
.meter{margin:10px 0 0}
.meter .track{height:8px;border-radius:99px;background:#ece9fa;border:1px solid var(--line);overflow:hidden}
.meter .fill{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--accent-2),var(--accent));transition:width .7s var(--ease)}
.bars{display:grid;gap:9px;margin-top:4px}
.bars .row{display:grid;grid-template-columns:104px 1fr 54px;align-items:center;gap:10px}
.bars .row .lbl{font:12.5px var(--font-mono);color:var(--ink);text-transform:capitalize}
.bars .row .tr{height:9px;border-radius:99px;background:#ece9fa;border:1px solid var(--line);overflow:hidden}
.bars .row .tr i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,rgba(179,78,0,.5),var(--accent));transition:width .7s var(--ease)}
.bars .row .pc{text-align:right;font:12px var(--font-mono);color:var(--muted)}

/* ---------- stat tiles ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:12px}
.stat{
  position:relative;background:#faf9fe;border:1px solid var(--line);border-radius:var(--r-lg);
  padding:15px 15px 14px;transition:border-color .25s var(--ease),transform .25s var(--ease)
}
.stat:hover{border-color:var(--line-2);transform:translateY(-2px)}
.stat .k{color:var(--muted);font:600 10px/1 var(--font-mono);letter-spacing:.16em;text-transform:uppercase}
.stat .v{font:650 22px/1.15 var(--font-display);letter-spacing:-.02em;margin:11px 0 9px;word-break:break-word}
.stat .v.sm{font-size:16px}
.stat .src{color:var(--dim);font:11px/1.4 var(--font-mono)}

/* ---------- evidence tiles ---------- */
.ev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:12px}
.ev{background:#faf9fe;border:1px solid var(--line);border-radius:var(--r);padding:13px 14px;transition:border-color .25s var(--ease)}
.ev:hover{border-color:var(--line-2)}
.ev .k{color:var(--muted);font:600 10px/1 var(--font-mono);letter-spacing:.14em;text-transform:uppercase}
.ev .v{font:15px/1.3 var(--font-mono);margin:9px 0 10px;word-break:break-word}
.ev .v.unknown{color:var(--dim)}
.ev .r{color:var(--dim);font-size:11.5px;line-height:1.5;border-top:1px dashed var(--line);padding-top:8px;margin-top:8px}

/* ---------- tables ---------- */
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r-lg);background:#faf9fe}
table.tbl{width:100%;border-collapse:collapse;font-size:13px}
table.tbl th{
  text-align:left;padding:11px 14px;color:var(--muted);font:600 10px/1 var(--font-mono);
  letter-spacing:.16em;text-transform:uppercase;border-bottom:1px solid var(--line);white-space:nowrap;
  position:sticky;top:0;background:#f3f2fb
}
table.tbl td{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
table.tbl tr:last-child td{border-bottom:0}
table.tbl tbody tr{transition:background .2s var(--ease)}
table.tbl tbody tr:hover{background:rgba(43,33,88,.04)}
table.tbl td.mono{font-family:var(--font-mono);font-size:12.5px}
table.tbl td .missing{color:var(--dim)}

/* ---------- findings ---------- */
.find{display:grid;gap:11px}
.fcard{display:grid;grid-template-columns:96px 1fr;gap:14px;padding:13px 14px;border:1px solid var(--line);border-radius:var(--r);background:#faf9fe}
.fcard .sev{display:flex;flex-direction:column;gap:7px;align-items:flex-start}
.fcard h4{font-size:13.5px;letter-spacing:-.01em;margin-bottom:4px}
.fcard p{color:var(--muted);font-size:12.5px;margin:0}
.fcard .rec{color:var(--accent);font-size:12.5px;margin-top:7px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:var(--r-xs);font:600 10px/1.7 var(--font-mono);letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--line-2);color:var(--muted)}
.badge[data-s=pass]{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 38%,transparent)}
.badge[data-s=warning]{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 38%,transparent)}
.badge[data-s=fail]{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 42%,transparent)}
.badge[data-s=unknown]{color:var(--dim)}
.sevdot{width:9px;height:9px;border-radius:3px;display:inline-block}
.sevdot[data-s=pass]{background:var(--ok)}.sevdot[data-s=warning]{background:var(--warn)}
.sevdot[data-s=fail]{background:var(--bad)}.sevdot[data-s=unknown]{background:var(--p-unk)}

/* ---------- notices / states ---------- */
.notice{display:flex;gap:12px;padding:14px 16px;border-radius:var(--r);border:1px solid var(--line);background:#faf9fe}
.notice .ic{flex:0 0 auto;width:20px;height:20px;color:var(--accent-2)}
.notice .ic svg{width:20px;height:20px}
.notice h4{font-size:13px;margin-bottom:3px}
.notice p{margin:0;color:var(--muted);font-size:12.5px}
.notice[data-v=warn]{border-color:color-mix(in srgb,var(--warn) 34%,transparent)}
.notice[data-v=warn] .ic{color:var(--warn)}
.notice[data-v=error]{border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
.notice[data-v=error] .ic{color:var(--bad)}
.empty{text-align:center;padding:54px 22px}
.empty > .orb{width:64px;height:64px;margin:0 auto 18px;border-radius:20px;display:grid;place-items:center;background:linear-gradient(150deg,rgba(179,78,0,.18),rgba(224,123,26,.10));border:1px solid var(--line-2)}
.empty > .orb svg{width:30px;height:30px}
.empty h3{font-size:19px;margin-bottom:8px}
.empty p{color:var(--muted);max-width:56ch;margin:0 auto 8px}
.samples{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:16px}
.samples code,.samples a{font:12px var(--font-mono);color:var(--accent);background:#faf9fe;border:1px solid var(--line);padding:6px 10px;border-radius:var(--r-sm);cursor:pointer}
.samples code:hover,.samples a:hover{border-color:var(--accent);text-decoration:none}
.json{font:12px/1.6 var(--font-mono);color:#33314d;background:#f7f6fd;border:1px solid var(--line);border-radius:var(--r);padding:14px;overflow:auto;max-height:340px;margin:0}

/* ---------- landing hero (centered, dotted, floating cards; orange/black/white) ---------- */
.landing{position:relative;overflow:hidden}
.landing .dots{position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(rgba(43,33,88,.12) 1px,transparent 1.3px);background-size:18px 18px;-webkit-mask-image:radial-gradient(ellipse 72% 68% at 50% 42%,#000 25%,transparent 78%);mask-image:radial-gradient(ellipse 72% 68% at 50% 42%,#000 25%,transparent 78%)}
.landing-core{position:relative;z-index:2}
.landing-core h1.hero{margin-bottom:38px}
h1.display.hero .grey{color:#a3a0b8}
.float-card{position:absolute;z-index:1;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:var(--sh);padding:12px 14px;color:var(--ink);max-width:190px;text-align:left;animation:floaty 7s ease-in-out infinite}
.float-card b{display:block;font-size:12.5px;margin-bottom:2px}
.float-card small{display:block;color:var(--muted);font-size:11.5px;line-height:1.5}
.float-card .pin{position:absolute;top:-6px;left:50%;width:12px;height:12px;border-radius:50%;background:var(--accent);box-shadow:0 2px 6px rgba(179,78,0,.5)}
.fc-tl{top:54px;left:4%;--rot:-4deg;transform:rotate(-4deg);background:#fff8f1}
.fc-tr{top:64px;right:4%;--rot:3deg;transform:rotate(3deg);animation-delay:-2s}
.fc-bl{bottom:120px;left:5%;--rot:2deg;transform:rotate(2deg);animation-delay:-4s}
.fc-br{bottom:110px;right:5%;--rot:-3deg;transform:rotate(-3deg);animation-delay:-5.5s}
@keyframes floaty{0%,100%{transform:translateY(0) rotate(var(--rot,0deg))}50%{transform:translateY(-9px) rotate(var(--rot,0deg))}}
.fbars{display:grid;gap:6px;margin-top:8px}
.fbars div{display:grid;grid-template-columns:58px 1fr;gap:8px;align-items:center;font-size:10.5px;color:var(--muted)}
.fbars i{display:block;height:6px;border-radius:99px;background:#ece9fa;overflow:hidden;position:relative}
.fbars i::after{content:"";position:absolute;inset:0;width:var(--w,50%);border-radius:99px;background:linear-gradient(90deg,rgba(179,78,0,.55),var(--accent))}
.livedot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px;box-shadow:0 0 8px var(--ok)}
.fchips{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.fchips span{font-size:10px;font-weight:700;padding:3px 8px;border-radius:99px;border:1px solid var(--line-2);color:var(--muted)}
.fchips .o{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,transparent)}
.fchips .d{color:var(--p-der);border-color:color-mix(in srgb,var(--p-der) 45%,transparent)}
.fchips .m{color:var(--p-ml);border-color:color-mix(in srgb,var(--p-ml) 45%,transparent)}
@media(max-width:1100px){.float-card{display:none}}
@media (prefers-reduced-motion:reduce){.float-card{animation:none}}

/* ---------- misc ---------- */
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.kv{display:grid;gap:10px}
.kv .row{display:flex;justify-content:space-between;gap:14px;padding-bottom:9px;border-bottom:1px solid var(--line)}
.kv .row:last-child{border-bottom:0;padding-bottom:0}
.kv .row label{color:var(--muted);font:600 10px/1.4 var(--font-mono);letter-spacing:.14em;text-transform:uppercase}
.kv .row strong{font:13px var(--font-mono);text-align:right}
.foot{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:var(--dim);font:11px var(--font-mono);letter-spacing:.08em;margin-top:26px;padding-top:16px;border-top:1px solid var(--line)}
.foot a{color:var(--muted)}

/* ---------- motion ---------- */
@keyframes rise{from{opacity:0;transform:translateY(14px);filter:blur(4px)}to{opacity:1;transform:none;filter:none}}
@keyframes pulse{0%,100%{opacity:.5}50%{opacity:1}}
@keyframes sweep{0%{transform:translateY(-100%)}100%{transform:translateY(400%)}}
.rise{animation:rise .6s var(--ease) both;animation-delay:calc(var(--i,0)*60ms)}
.pulse{animation:pulse 1.8s var(--ease) infinite}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
  html{scroll-behavior:auto}
}

/* ---------- responsive ---------- */
@media(max-width:980px){
  .c3,.c4,.c5,.c6,.c7,.c8{grid-column:span 12}
  .form{grid-template-columns:1fr;}
  .grid-2{grid-template-columns:1fr}
  .topbar{border-radius:var(--r-lg);flex-wrap:wrap}
  .nav{margin-left:0;order:3;width:100%}
}
@media(max-width:560px){
  .shell{padding:0 14px 56px}
  .panel{padding:16px;border-radius:var(--r-lg)}
  .seal{margin:0 auto}
}

/* ---------- print (reports) ---------- */
@media print{
  body{background:#fff;color:#111}
  body::before,body::after{display:none}
  .panel{box-shadow:none;break-inside:avoid;border-color:#ccc}
  .topbar,.btn{display:none}
}
"""


def _esc(value):
    return _html.escape(str(value if value is not None else "Unknown"))


# Provenance label -> chip key
_PROV_KEY = {
    "Observed": "observed", "observed": "observed", "directly_observed": "observed",
    "Derived": "derived", "derived": "derived", "deterministically_derived": "derived",
    "ML Inferred": "ml", "ml": "ml", "ml_inferred": "ml",
    "Unknown": "unknown", "unknown": "unknown",
}
_PROV_LABEL = {"observed": "Observed", "derived": "Derived", "ml": "ML Inferred", "unknown": "Unknown"}


def chip(provenance):
    """Provenance chip. Shape + text carry meaning, so color is never alone."""
    key = _PROV_KEY.get(str(provenance), "unknown")
    return ('<span class="chip" data-p="%s" title="Evidence provenance: %s">'
            '<span class="d" aria-hidden="true"></span>%s</span>'
            % (key, _PROV_LABEL[key], _PROV_LABEL[key]))


def spectrum(counts, total=None):
    """Repeated motif: proportional provenance ribbon + legend."""
    order = ["observed", "derived", "ml", "unknown"]
    vals = {k: max(0, int(counts.get(k, 0))) for k in order}
    total = total or sum(vals.values())
    if total <= 0:
        segs = '<span class="seg" data-p="unknown" style="flex:1 1 100%"></span>'
    else:
        segs = "".join(
            '<span class="seg" data-p="%s" style="flex:%d 1 0%%" title="%s: %d"></span>'
            % (k, vals[k], _PROV_LABEL[k], vals[k])
            for k in order if vals[k]
        )
    legend = "".join(
        '<span><b>%d</b> %s</span>' % (vals[k], _PROV_LABEL[k]) for k in order
    )
    return ('<div class="spectrum"><div class="bar" role="img" aria-label="provenance mix">%s</div>'
            '<div class="legend">%s</div></div>' % (segs, legend))


def seal(score, level):
    """Tick-dial risk gauge. Lit ticks = score/100 in the level color.
    0 is framed as 'no proven failures', never 'secure'."""
    score = 0 if score is None else max(0, min(100, int(score)))
    colors = {"low": "var(--ok)", "low-moderate": "var(--ok)", "moderate": "var(--warn)",
              "high": "var(--bad)", "critical": "var(--crit)", None: "var(--muted)"}
    color = colors.get(level, "var(--muted)")
    ticks, total = [], 48
    lit = int(round(score / 100.0 * total))
    for i in range(total):
        a = 2 * _math.pi * i / total
        x1, y1 = 66 + 50 * _math.cos(a), 66 + 50 * _math.sin(a)
        x2, y2 = 66 + 59 * _math.cos(a), 66 + 59 * _math.sin(a)
        if i < lit:
            ticks.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" '
                         'stroke-width="3.4" stroke-linecap="round" opacity=".95"/>'
                         % (x1, y1, x2, y2, color))
        else:
            ticks.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#e6e3f2" '
                         'stroke-width="3" stroke-linecap="round" opacity=".85"/>'
                         % (x1, y1, x2, y2))
    label = (str(level).replace("-", " ").title() if level else "Unknown")
    return (
        '<div class="seal" role="img" aria-label="Verified configuration risk %d of 100, level %s">'
        '<svg viewBox="0 0 132 132" aria-hidden="true">%s</svg>'
        '<span class="val"><b>%d</b><span>/100 &middot; %s</span></span></div>'
        % (score, _esc(label), "".join(ticks), score, _esc(label))
    )


def meter(pct, color="var(--accent)"):
    pct = 0 if pct is None else max(0.0, min(100.0, float(pct)))
    return ('<div class="meter"><div class="track" role="progressbar" aria-valuenow="%.1f" '
            'aria-valuemin="0" aria-valuemax="100"><div class="fill" style="width:%.1f%%;background:%s"></div>'
            '</div></div>' % (pct, pct, color))


# Light, precise stroke icons (no thick Lucide/Material defaults).
ICONS = {
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"/><path d="M9.5 12.2l1.8 1.8 3.4-3.6"/></svg>',
    "wave": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M2 12h3l2-6 3 12 3-9 2 5 2-2h5"/></svg>',
    "alert": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 16H3z"/><path d="M12 10v4"/><circle cx="12" cy="17.2" r=".6" fill="currentColor"/></svg>',
    "info": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><circle cx="12" cy="8" r=".6" fill="currentColor"/></svg>',
    "bolt": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M13 3L5 13h6l-1 8 8-10h-6z"/></svg>',
    "search": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/></svg>',
    "arrow": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7"/><path d="M9 7h8v8"/></svg>',
    "grid": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/></svg>',
}


def icon(name, cls=""):
    svg = ICONS.get(name, ICONS["info"])
    return svg.replace("<svg", '<svg class="%s"' % cls, 1) if cls else svg
