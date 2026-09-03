# User Guide

All commands run from the repository root. On the development machine Python runs inside the `python:3.11` container; on a host with Python 3.11 the same commands work directly (drop the `docker run` prefix).

## 1. Start testbed

```bash
docker compose -f testbed/compose/testbed.yml up -d --build
```

For T15 add the override: `-f testbed/compose/t15.yml`.

## 2. Verify testbed

```bash
powershell -File testbed/scripts/check-testbed.ps1
powershell -File testbed/scripts/check-phase2.ps1
```

## 3. Run a scenario (capture traffic)

```bash
powershell -File testbed/scripts/run-scenario.ps1 -Scenario T04 -Traffic "icmp,web,voip-like,video-like" -Runs 3 -DatasetRoot dataset_v3_5_v2_final
```

This initiates the SA, captures the transit, and writes `capture.pcap`, `metadata.json`, `features.json`, swanctl/XFRM evidence, and validation files per run.

## 4. Extract features from a PCAP (standalone)

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python analyzer/pcap_features.py dataset_v3_5_v2_full/T04/20260903-143933-601/capture.pcap --out /tmp/features.json
```

## 5. Run the ML classifier (Phase 4)

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python ml_v2/predict_traffic.py --features dataset_v3_5_v2_full/T04/20260903-143933-601/features.json
# or from a PCAP directly:
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python ml_v2/predict_traffic.py --pcap dataset_v3_5_v2_full/T04/20260903-143933-601/capture.pcap
```

## 6. Run the security assessment (Phase 5)

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python security/assess_ipsec.py --run dataset_v3_5_v2_full/T04/20260903-143933-601 --summary
```

## 7. Run the unified analysis (Phase 6)

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  sh -c "pip install -q -r requirements.txt && python integration/analyze.py --run dataset_v3_5_v2_full/T04/20260903-143933-601 --output /tmp/t04.json"
```

PCAP-only mode: replace `--run ...` with `--pcap <path>`.

## 8. Start the dashboard

```bash
python app/app.py            # host with Python
# or containerized:
docker run --rm -p 127.0.0.1:8501:8501 -v "${PWD}:/work" -w /work python:3.11 \
  sh -c "pip install -q -r requirements.txt && python -u app/app.py --host 0.0.0.0 --port 8501"
```

Open `http://127.0.0.1:8501/` and paste a run directory or PCAP path.

## 9. Generate a report

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python reports/generate_report.py --input /tmp/t04.json --out reports/results
```

Outputs `assessment_<stem>.json`, `executive_<stem>.html`, `technical_<stem>.html` in `reports/results/`.

## 10. Run final validation

```bash
powershell -ExecutionPolicy Bypass -File scripts/final-validation.ps1
```
