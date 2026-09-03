# Phase 6 Integration

The integration layer joins the existing Phase 4 predictor and Phase 5 assessment without duplicating either implementation. `integration/analyze.py` accepts a complete run directory, a PCAP, or features/evidence paths and emits a stable `phase6-v1` JSON object. PCAP-only mode extracts passive features into a temporary file and deletes it after analysis.

```text
python integration/analyze.py --run dataset_v3_5_v2_full/T04/<run-id> --output /tmp/t04.json
python integration/analyze.py --pcap capture.pcap --output /tmp/passive.json
python reports/generate_report.py --input /tmp/t04.json --out reports/results
python app/app.py
```

The local dashboard uses the Python standard library and binds to localhost by default. Reports are Markdown-equivalent HTML and JSON; no external upload or arbitrary script execution is performed. Evidence badges preserve `directly_observed`, `deterministically_derived`, `ml_inferred`, and `unknown`. Unknown VPN properties remain unknown in passive-only mode. The model predicts synthetic encrypted-flow behavior and does not decrypt payloads or identify real applications.
