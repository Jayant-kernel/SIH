# Dashboard and Reports (Phase 6)

## Launch

```bash
python app/app.py
```

The dashboard binds to `http://127.0.0.1:8501` by default (override with `--host`/`--port`). It uses only the Python standard library, keeps all analysis local, and uploads nothing.

When the host has no Python, run it in the analysis container with port mapping:

```bash
docker run --rm -p 127.0.0.1:8501:8501 -v "${PWD}:/work" -w /work python:3.11 \
  sh -c "pip install -q -r requirements.txt && python -u app/app.py --host 0.0.0.0 --port 8501"
```

Startup prints: `Dashboard: http://0.0.0.0:8501` (use the mapped local URL `http://127.0.0.1:8501`).

## Input modes

| Mode | How | Expected evidence |
|---|---|---|
| Full run directory | `?run=<path-to-run>` | Rich deterministic assessment (runtime + metadata + features + ML) |
| PCAP-only | `?pcap=<path>` | Passive observation + traffic ML; crypto fields Unknown |
| Evidence bundle | CLI flags on `integration/analyze.py` (`--features`, `--metadata`, `--pcap`) | Whatever is supplied |

Passive-only pages show a visible notice: `Some VPN properties cannot be determined from passive encrypted traffic alone.`

## Sections

- Overview: protocol, IKE, mode, encryption, PFS, traffic label, risk score/level, evidence completeness.
- Protocol and Evidence: every field with value, evidence badge (`Observed` / `Derived` / `ML Inferred` / `Unknown`), and source.
- Traffic ML: probability table plus the disclaimer that prediction is ML inference on encrypted-flow metadata and does not decrypt payloads.
- Security Findings: severity, status (pass/fail/warning/unknown), title, description — unknown findings are never hidden.
- Threat Matrix: only threats supported by actual evidence, each with recommendation.
- Limitations: rendered on every page.

## Reports

```bash
python integration/analyze.py --run dataset_v3_5_v2_full/T04/20260903-143933-601 --output /tmp/t04.json
python reports/generate_report.py --input /tmp/t04.json --out reports/results
```

Generates `assessment_<stem>.json`, `executive_<stem>.html`, and `technical_<stem>.html`. The executive report targets management (risk level, top findings, recommendations, limitations); the technical report includes the full field/provenance tables, findings, threat matrix, and ML probabilities. JSON is the primary data source; HTML is rendered from it. Sample outputs are in `reports/results/`.

## Error handling

Missing input renders the landing page; invalid paths, empty/malformed PCAPs, and incomplete run directories render `Unknown` values with an explanatory limitations note. No Python tracebacks are shown; the server keeps running.

## Runtime validation record

See `docs/dashboard-validation.txt` for the recorded launch command, startup output, HTTP checks, and data/error-handling results.
