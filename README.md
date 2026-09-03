# AI-Driven IPsec VPN Security Analyzer

An end-to-end research prototype that generates controlled IPsec VPN traffic in a Docker testbed, extracts passive encrypted-flow features, classifies traffic behavior with machine learning, performs an evidence-first security assessment, and presents results through a local dashboard and executive/technical reports.

## Purpose

Demonstrate, with scientific discipline, how much VPN security posture can be determined **without decrypting traffic**:

- Deterministic protocol/runtime evidence (strongSwan, XFRM) establishes crypto configuration.
- Passive packet observation establishes what remains visible to an eavesdropper.
- ML classifies synthetic traffic behavior from encrypted-flow metadata only.
- Unknown is reported as unknown — never guessed.

## Key capabilities

1. **Working testbed** — four-container site-to-site IPsec VPN (strongSwan 5.9.8, swanctl/vici, XFRM) covering ESP/AH, tunnel/transport, CBC/GCM, IPv4/IPv6, DH groups, PFS, and a real rekey scenario (T01-T15).
2. **Training/testing dataset** — `dataset_v3_5_v2_full` (version `3.5-v2`): 180 valid balanced runs (15 scenarios x 4 traffic classes x 3), corrected T15 with clean ESP-only captures.
3. **AI classifier (Phase 4)** — Random Forest on 36 passive features; grouped scenario CV macro F1 `0.9483 ± 0.0480`; unseen-scenario holdout macro F1 `0.9143`; thresholded confidence with `unknown` handling.
4. **Security assessment engine (Phase 5)** — deterministic, evidence-provenance-aware rules for protocol, confidentiality, integrity, DH strength, PFS, rekey, replay, and metadata exposure; transparent 0-100 risk score; configurable policy.
5. **Dashboard (Phase 6)** — local web UI with provenance badges (Observed / Derived / ML Inferred / Unknown), findings, threat matrix, risk, and passive-only warnings.
6. **Reports** — JSON + executive HTML + technical HTML generated from the unified pipeline.

## Architecture

```text
IPsec Testbed -> Traffic Generator -> Packet Capture -> Feature Extraction
      -> Phase 4 Traffic ML  (ml inference)
      -> Phase 5 Security Assessment (deterministic rules)
      -> Phase 6 Unified Pipeline -> Dashboard + Reports
```

Containers:

```text
Client A -> Gateway A -> Untrusted Transit -> Gateway B -> Client B
```

See `docs/ARCHITECTURE.md`.

## Repository layout

```text
testbed/                 four-container testbed (compose, strongSwan configs, scenarios, runner scripts)
analyzer/                passive PCAP feature extraction + ML dataset builder
ml_v2/                   Phase 4 model, schema, prediction CLI, results
security/                Phase 5 assessment engine, policy, tests, results
integration/             Phase 6 unified pipeline, validation artifacts, tests
app/                     local dashboard (standard library only)
reports/                 report generator + generated samples
dataset_v3_5_v2_full/    final dataset (3.5-v2) — frozen
dataset_exports_v2/      ML CSV exports — frozen inputs of record
docs/                    full documentation set
scripts/                 demo.ps1, final-validation.ps1
```

## Prerequisites

- Docker Desktop (WSL2 backend on Windows).
- Python 3.11 (used inside the `python:3.11` container; `requirements.txt`: numpy, scipy, scikit-learn, joblib, scapy).

## Quick start

```bash
# 1. Testbed
docker compose -f testbed/compose/testbed.yml up -d --build
powershell -File testbed/scripts/check-testbed.ps1

# 2. Analyze an existing dataset run end-to-end (Phase 6 pipeline)
docker run --rm -v "${PWD}:/work" -w /work python:3.11 sh -c \
  "pip install -q -r requirements.txt && python integration/analyze.py --run dataset_v3_5_v2_full/T04/20260903-143933-601 --summary"

# 3. Reports
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  python reports/generate_report.py --input integration/results/t15_result.json --out reports/results

# 4. Dashboard
python app/app.py          # http://127.0.0.1:8501
```

## Common tasks

| Task | Command |
|---|---|
| Start testbed | `docker compose -f testbed/compose/testbed.yml up -d --build` (add `-f testbed/compose/t15.yml` for T15) |
| Verify testbed | `powershell -File testbed/scripts/check-testbed.ps1` |
| Run a scenario | `powershell -File testbed/scripts/run-scenario.ps1 -Scenario T04 -Traffic "icmp,web,voip-like,video-like" -Runs 3 -DatasetRoot dataset_v3_5_v2_final` |
| Analyze a run (unified) | `python integration/analyze.py --run <run-dir>` |
| Analyze PCAP-only | `python integration/analyze.py --pcap <capture.pcap>` |
| ML prediction | `python ml_v2/predict_traffic.py --features <features.json>` or `--pcap <capture.pcap>` |
| Security assessment | `python security/assess_ipsec.py --run <run-dir> --summary` |
| Dashboard | `python app/app.py` |
| Generate reports | `python reports/generate_report.py --input <phase6.json> --out reports/results` |
| Final validation | `powershell -ExecutionPolicy Bypass -File scripts/final-validation.ps1` |

(On hosts without Python, prefix commands with `docker run --rm -v "${PWD}:/work" -w /work python:3.11`.)

## Documentation

Start with `docs/README.md`: installation, user guide, architecture, testbed, dataset, ML model, security engine, dashboard, results, limitations, demo guide, and the final validation record.

## Known limitations

- No payload decryption; AES key size, GCM vs CBC, mode, PFS, and replay are reported only from runtime/config evidence — `unknown` otherwise.
- Traffic classes are synthetic behavior categories; the model does not identify real applications.
- Small, controlled, synthetic dataset; real-world generalization is not proven.
- `project_default_policy` is a project policy, not a regulatory compliance certification.
- Metadata side channels (sizes, timing, directionality, endpoints) remain observable.

Details: `docs/LIMITATIONS.md`.
