# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

> The system acts as a security observer for encrypted IPsec VPN traffic. It studies packet behavior, uses machine learning to classify likely traffic types, evaluates VPN security using reliable evidence, and clearly shows what is observed, derived, inferred, or unknown.

---

## 1. Project Overview

A Virtual Private Network (VPN) encrypts traffic so outsiders cannot read it. That same encryption makes the traffic hard to inspect — even for the network's own security analysts.

This project answers a focused question: **how much can we learn about a VPN's behavior and security posture without decrypting anything?**

It does this by combining:

- **Controlled packet capture** from a Docker-based IPsec testbed.
- **Passive feature extraction** — sizes, timing, direction, counts (never payload contents).
- **Machine learning (ML)** — a Random Forest classifier that guesses likely traffic behavior (for example, steady ICMP versus bursty video-like flow).
- **Deterministic security rules** — checks for encryption presence, key size, integrity, Diffie-Hellman (DH) strength, Perfect Forward Secrecy (PFS), mode, rekey behavior, and replay protection, using only evidence that can actually prove each claim.
- **A live monitor, dashboard, and reports** — the same pipeline runs offline on saved captures and live on a growing capture file.

The system **does not decrypt protected user data**. It analyzes encrypted traffic behavior plus trusted VPN evidence (strongSwan runtime state, Linux kernel state, configuration declarations), and it supports both **offline analysis** and **live monitoring**.

---

## 2. Problem Statement

VPNs encrypt network traffic end to end. Traditional inspection tools that read packet payloads become blind: an Encapsulating Security Payload (ESP) packet looks like opaque ciphertext.

However, encryption does not hide everything. Useful **metadata** stays visible on the wire:

| Visible metadata | What it tells you |
|---|---|
| Packet size | Rough activity level, application rhythm |
| Timing / inter-arrival time | Burstiness, steadiness, idle gaps |
| Direction | Who talks to whom, request/response balance |
| Packet rate | Packets per second |
| Byte rate | Bytes per second |
| Burst behavior | Clusters of packets versus steady streams |
| Outer IP addresses | Tunnel endpoints (gateways) |
| Internet Key Exchange (IKE) activity | Tunnel negotiation events |
| ESP activity | Encrypted data flow is present |
| Security Parameters Index (SPI) values | Security Association (SA) identity and lifecycle |

Security analysts need a disciplined way to turn this visible metadata — plus trusted endpoint evidence — into traffic-behavior insight and configuration assessment **without decrypting traffic**. That is what this project provides.

---

## 3. Proposed Solution

The complete pipeline:

```text
Encrypted IPsec traffic
  -> packet capture (tcpdump sidecar)
  -> feature extraction (analyzer/pcap_features.py)
  -> ML traffic classification (ml_v2/predict_traffic.py)
  -> deterministic VPN/security analysis (security/*)
  -> risk and evidence assessment (transparent 0-100 score)
  -> dashboard and reports (app/, reports/, monitor/dashboard.py)
```

Two strict separations keep the system honest:

1. **ML is only used for traffic-behavior inference** — guessing whether a flow looks like `icmp`, `web`, `voip-like`, or `video-like` from metadata. It never decides security properties.
2. **VPN properties are decided deterministically** — encryption algorithm, key size, integrity transform, DH group, PFS, tunnel/transport mode, rekey behavior, and replay protection are proven only from evidence that can actually prove them (packet observations, strongSwan runtime, kernel state, configuration declarations). Anything else stays **Unknown**.

---

## 4. System Architecture

### 4.1 Testbed topology

```text
Client A (10.77.1.10)
  -> Gateway A (protected 10.77.1.1 / transit 10.77.0.10)
    -> encrypted IPsec transit network (10.77.0.0/24)
      -> Gateway B (transit 10.77.0.20 / protected 10.77.2.1)
        -> Client B (10.77.2.10)
```

Defined in `testbed/compose/testbed.yml` (project name `sih-ipsec-testbed`).

### 4.2 Monitoring path (offline and live)

```text
Gateway A eth1
  -> tcpdump
  -> PCAP
  -> feature extraction (analyzer/pcap_features.py)
  -> ML classifier (ml_v2/predict_traffic.py)
  -> security engine (security/assess_ipsec.py, security/rules.py)
  -> unified result (integration/analyze.py)
  -> dashboard / reports
```

### 4.3 Live path

```text
Gateway A eth1
  -> /captures/monitor/live_current.pcap          (tcpdump sidecar, host view)
  -> /work/captures/monitor/live_current.pcap    (same file, container view)
  -> monitor.run --tail                          (monitor/run.py)
  -> /work/monitor/state/live_profiles.json      (same file, container view)
  -> /live dashboard                             (http://127.0.0.1:8501/live)
```

Started with a single command:

```powershell
.\scripts\start-live-monitor.ps1
```

---

## 5. Technologies Used

| Technology | Role in this project |
|---|---|
| Docker | Runs the 4-container IPsec testbed, the monitor, and the dashboard in isolated, reproducible environments |
| Docker Desktop / WSL2 | Container runtime on Windows hosts |
| strongSwan (5.9.8) | Internet Key Exchange version 2 (IKEv2) negotiation and IPsec tunnel management inside the gateways |
| swanctl / VICI | strongSwan's command tool (`swanctl`) and protocol (Versatile IKE Configuration Interface, VICI) used to list, initiate, terminate, and rekey connections |
| Linux XFRM | Kernel framework that performs the actual packet encryption, decryption, and policy transformations |
| tcpdump | Passive packet capture sidecar on Gateway A; writes the PCAP the monitor tails |
| Python (3.11 in containers) | Implementation language for the monitor, analyzer, ML bridge, security engine, dashboard, and reports |
| Scapy | Packet parsing (feature extraction, IKE parsing, local sniffing mode) |
| pandas / NumPy | Dataset handling and numeric feature computation during training |
| scikit-learn | Model training and evaluation (Logistic Regression, Random Forest, HistGradientBoosting, KNN, SVM) |
| joblib | Serialization of the trained Random Forest model (`ml_v2/models/traffic_classifier.joblib`) |
| HTML / local web dashboard | Server-rendered UI (standard library only, no frontend framework): Analyzer, Live monitor, Executive, Technical |
| PowerShell automation | Testbed checks, scenario runner, live demo, validation (`testbed/scripts/*.ps1`, `scripts/*.ps1`) |
| JSON / CSV / HTML reporting | Machine-readable results (`assessment_*.json`), feature exports (`*.csv`), human reports (`executive_*.html`, `technical_*.html`) |

---

## 6. VPN Testbed

Four Docker containers on three isolated bridge networks (`testbed/compose/testbed.yml`):

| Node | Container | IPv4 | IPv6 |
|---|---|---|---|
| Client A | `sih-client-a` | 10.77.1.10 | fd77:77:1::10 |
| Gateway A | `sih-gateway-a` | protected 10.77.1.1, transit 10.77.0.10 | transit fd77:77:0::10 |
| Gateway B | `sih-gateway-b` | transit 10.77.0.20, protected 10.77.2.1 | transit fd77:77:0::20 |
| Client B | `sih-client-b` | 10.77.2.10 | fd77:77:2::10 |

Docker networks:

- `sih-transit` — 10.77.0.0/24 (+ fd77:77:0::/64): the untrusted network where encrypted ESP and IKE travel.
- `sih-protected-a` — 10.77.1.0/24 (+ fd77:77:1::/64): Client A's private LAN.
- `sih-protected-b` — 10.77.2.0/24 (+ fd77:77:2::/64): Client B's private LAN.

Gateways run privileged with `NET_ADMIN` so they can manage XFRM state and forward packets. **strongSwan** performs IKE/IPsec setup (negotiation, authentication, SA installation); **Linux XFRM** performs the kernel-level packet transformations (encrypt on the way out,
decrypt on the way in, drop what policy forbids).

## 7. IPsec Protocols Covered

- **IPsec (Internet Protocol Security)** - the framework that protects IP packets with authentication and encryption.
- **IKE (Internet Key Exchange, here IKEv2)** - the negotiation protocol that authenticates peers and agrees on algorithms, keys, and parameters before any data flows.
- **ESP (Encapsulating Security Payload)** - the protocol that carries encrypted data. What you see on the wire is ciphertext plus headers.
- **AH (Authentication Header)** - a protocol that authenticates packets (proves integrity and origin) but does **not** encrypt them, so it provides no confidentiality.
- **Security Association (SA)** - a one-way agreement between two endpoints: algorithms, keys, SPIs, lifetimes. A tunnel needs SAs in both directions.
- **SPI (Security Parameters Index)** - a 32-bit number in every ESP/AH header identifying which SA a packet belongs to. SPIs are visible and are the monitor's main lifecycle signal.
- **Tunnel mode** - the whole original IP packet is encrypted and wrapped in a new outer IP header:

```text
Tunnel mode:    [New outer IP][ESP][encrypted original IP packet]
```

- **Transport mode** - only the upper-layer payload is encrypted; the original IP header stays visible:

```text
Transport mode: [Original IP][ESP][encrypted upper-layer payload]
```

- **PFS (Perfect Forward Secrecy)** - fresh DH key exchange for Child SAs, so a compromised long-term key cannot decrypt past traffic.
- **Rekey** - replacing SAs before they expire, visible as SPI transitions (old SPI stops, new SPI starts).

**Important:** passive ESP ciphertext alone may not reliably reveal tunnel versus transport mode. In tunnel mode the inner header is encrypted, but without trusted endpoint evidence the mode stays **Unknown** in arbitrary captures.

## 8. Supported VPN Scenarios

Verified scenario configurations in `testbed/scenarios/` (T01-T15, plus `baseline-s01`):

| Scenario | Verified configuration |
|---|---|
| T01 | Baseline: IKEv2 ESP tunnel, AES-256-CBC, SHA256, MODP3072, PFS, IPv4, dual-stack |
| T02 | ESP tunnel, AES-128-CBC, SHA256, MODP2048, PFS, IPv4 |
| T03 | ESP tunnel, AES-256-CBC, SHA256, MODP2048, PFS disabled |
| T04 | ESP tunnel, AES-128-GCM, MODP3072, PFS, IPv4 |
| T05 | ESP tunnel, AES-256-GCM, MODP3072, PFS, IPv4 |
| T06 | ESP transport, AES-128-CBC, SHA256, MODP2048, host-to-host |
| T07 | ESP transport, AES-128-GCM, MODP3072, host-to-host |
| T08 | AH tunnel, SHA256, MODP2048, IPv4 |
| T09 | AH transport, SHA256, MODP2048, host-to-host |
| T10 | IPv6 IKE, ESP tunnel, AES-256-CBC, SHA384, MODP2048, dual-stack |
| T11 | IPv6 IKE, ESP tunnel, AES-128-GCM, MODP3072 |
| T12 | ESP tunnel, AES-128-CBC, SHA256, ECP256 (DH group 19), PFS |
| T13 | ESP tunnel, AES-128-CBC, SHA384, MODP3072, PFS |
| T14 | Rekey scenario: ESP tunnel, AES-256-CBC, SHA256, MODP3072, short rekey triggers `CREATE_CHILD_SA` |
| T15 | Edge case: ESP tunnel, AES-192-CBC, SHA256, MODP3072, PFS disabled, IPv6 protected side |

Coverage across the suite: ESP and AH, tunnel and transport mode, AES-128/192/256, AES-CBC and AES-GCM, HMAC-based integrity, multiple DH groups (MODP2048, MODP3072, ECP256), PFS enabled and disabled, IPv4 and IPv6, and rekey scenarios. Each scenario is exercised by `testbed/scripts/run-scenario.ps1` with `icmp`, `web`, `voip-like`, and `video-like` traffic.

## 9. Dataset

The final cleaned dataset is **`dataset_v3_5_v2_full`**:

```text
15 scenarios x 4 traffic classes x 3 repetitions = 180 runs
```

Traffic classes: `icmp`, `web`, `voip-like`, `video-like` - 45 samples per class.

Feature exports in `dataset_exports_v2/`:

- `dataset_exports_v2/traffic_features.csv` (39 KB) - the 36 ML input features per run.
- `dataset_exports_v2/vpn_observable_features.csv` (37 KB) - VPN-observable attributes per run.

Two facts must not be confused:

1. The **known generated traffic type** is used as the training **label** (we know what the generator sent).
2. The **ML input features** come only from **encrypted transit-traffic metadata** (sizes, timing, counts).

Plaintext packet contents are never ML features.

## 10. Traffic Generation

Supported behavior profiles in `testbed/traffic/generator.py`:

- **ICMP** - steady ping-style echo traffic.
- **Web** - HTTP request/response patterns.
- **VoIP-like** - small-packet UDP stream to port 5001.
- **Video-like** - sustained UDP stream to port 5002.

These are **controlled synthetic behavior categories**. The project does not identify commercial applications such as WhatsApp or YouTube (see `ml_v2/model_card.md` limitations).

Example commands from the repository:

```powershell
# Simple ICMP transfer, Client A -> Client B
docker exec sih-client-a ping -c 100 10.77.2.10

# VoIP-like: small UDP packets to port 5001
docker exec sih-gateway-a python3 /traffic/generator.py --profile voip-like --duration 20 --seed 20260904 --peer 10.77.12.10

# Video-like: sustained UDP stream to port 5002
docker exec sih-gateway-a python3 /traffic/generator.py --profile video-like --duration 20 --seed 20260904 --peer 10.77.12.10
```

Background service endpoints (HTTP 8000, iPerf 5201, UDP 5001-5003) are started with:

```powershell
docker exec sih-client-a python3 /traffic/generator.py --profile icmp --start-servers
```

## 11. Feature Extraction

`analyzer/pcap_features.py` reduces a capture to 36 numeric features (`ml_v2/feature_schema.json`). Categories:

**Capture totals** - total packets, total bytes, duration, IPv4/IPv6 counts, IKE packets, ESP packets, AH packets, packets per second, bytes per second.

**Packet size** - mean, median, min, max, standard deviation, coefficient of variation (spread relative to the mean), small/medium/large ratios.

**Direction** - A-to-B packets, B-to-A packets, packet ratio, byte ratio.

**Timing** - mean/median/standard-deviation of inter-arrival time, timing coefficient of variation. *Inter-arrival time* is simply the gap between one packet and the next; steady traffic has small, even gaps, bursty traffic has clusters separated by idle gaps.

**Burstiness** - burst count, average burst size, average burst duration, idle gap count.

**ESP/AH and rekey** - SPI counts, unique SPIs, rekey lifecycle observations (temporal SPI transitions; two SPIs in opposite directions alone do **not** imply rekey).

Raw SPI values are kept for evidence but the model uses counts only.

## 12. Machine Learning Model

`ml/train_traffic_classifier.py` evaluates five models with grouped cross-validation:

- Logistic Regression
- Random Forest
- HistGradientBoosting
- KNN (k=7)
- SVM (probability enabled)

**Random Forest was selected** (`ml_v2/models/traffic_classifier.joblib`). Actual results (`ml_v2/model_card.md`):

Grouped cross-validation (5-fold, grouped by scenario):

- Accuracy: approximately **0.9500**
- Macro F1: approximately **0.9483**

Held-out unseen scenarios (**T13, T14, T15**):

- Accuracy: approximately **0.9167**
- Macro F1: approximately **0.9143**

**Why grouped validation matters:** data from the same VPN scenario must not leak into both training and testing groups. Grouping by scenario proves the model recognizes traffic *behavior*, not scenario fingerprints.

Prediction code: `ml_v2/predict_traffic.py` (schema: `ml_v2/feature_schema.json`).

## 13. ML Confidence and Unknown Handling

Acceptance threshold: **0.60** (`DEFAULT_THRESHOLD` in `monitor/ml_bridge.py`, `--threshold` in `monitor/run.py`).

Three states (`monitor/session.py`, `monitor/monitor.py`):

1. `no_prediction_yet` - no rolling window evaluated yet.
2. **Accepted prediction** - confidence at or above threshold.
3. **Below-threshold abstention** - confidence under threshold, reported as Unknown.

Example - accepted:

```text
icmp probability = 0.715, threshold = 0.60  ->  accepted as icmp
```

Example - abstained:

```text
web probability = 0.585, threshold = 0.60  ->  reported as Unknown
```

Unknown here is intentional and scientifically safer than forcing a label. ML abstentions never become security findings.

## 14. Evidence Provenance

Every value carries one of four provenance labels, so assumptions are never presented as facts:

| Label | Meaning | Example |
|---|---|---|
| Observed | Seen directly on the wire or in runtime state | ESP detected; SPI values |
| Derived | Computed deterministically from observations | No rekey seen from the SPI timeline |
| ML Inferred | Model estimate with confidence | Traffic class (`video-like`, 97.5%) |
| Unknown | Not provable from available evidence | AES key size not externally visible |

## 15. Security Assessment Engine

Deterministic, provenance-aware rule evaluation. Relevant source files:

- `security/assess_ipsec.py` - full-evidence assessment entry point
- `security/evidence.py` - evidence builders
- `security/rules.py` - rule evaluation (`assess`)
- `security/scoring.py` - transparent scoring (`calculate`)
- `security/schema.py` - evidence data model
- `security/generate_artifacts.py` - artifact generation (including passive-vs-full comparison)
- `security/policy/default_policy.json` - tunable thresholds and penalties
- `monitor/security_bridge.py` - live path: builds passive-only evidence, reuses the same rules/scorer without changing semantics

Rule categories:

- ESP/AH/IKE presence and version
- Encryption algorithm and key size
- Integrity/authentication transform
- DH strength
- PFS (Perfect Forward Secrecy)
- Tunnel/transport mode
- Rekey lifecycle
- Replay protection
- Metadata exposure (residual passive threat)
- AH confidentiality (AH authenticates but does not encrypt)

Hard separation: **ML traffic predictions are never used to infer encryption, mode, PFS, DH group, replay protection, or lifecycle.** Those come only from evidence the monitor can actually prove.

## 16. Risk Scoring

Transparent rule-based score from **0 to 100** (`security/scoring.py`): the score is the sum of penalties for **proven failures only**, capped at 100.

Risk bands:

- `low`
- `low-moderate`
- `moderate`
- `high`
- `critical`

**Unknown evidence does not automatically add a penalty.** The formula is literally `sum(rule penalties for proven failures); unknown adds no penalty`.

**Evidence completeness** (0.0-1.0) measures how many VPN properties could actually be verified. Example:

> A risk score of 0 with completeness 0.222 does not prove that the VPN has zero risk. It means no penalty was found among the properties that were actually verified.

Below 0.5 completeness the monitor adds an explicit low-evidence warning (`LOW_EVIDENCE_TEXT` in `monitor/security_bridge.py`).

## 17. Passive-Only vs Full-Evidence Analysis

| | Passive-only | Full evidence |
|---|---|---|
| Inputs | Packet capture only | Capture + strongSwan runtime + Linux XFRM state/policy + configuration declarations |
| Sees | ESP/IP version/SPIs, IKE offers, timing/sizes | Above, plus negotiated transforms, key lengths, DH groups, PFS, lifetimes |
| Unknowns | Many crypto/security values stay Unknown | Deeper deterministic analysis possible |
| Code path | `monitor/security_bridge.py` | `security/assess_ipsec.py` |

`security/generate_artifacts.py` produces a `passive_vs_full` comparison so the gap between the two views is explicit, not hidden.

## 18. Live Monitoring

The live monitor (`monitor/run.py`, `monitor/monitor.py`) tails a growing capture and publishes snapshots plus heartbeat:

Canonical pipeline (`scripts/start-live-monitor.ps1`):

```text
Gateway A eth1
  -> tcpdump
  -> captures/monitor/live_current.pcap
  -> monitor.run --tail
  -> monitor/state/live_profiles.json
  -> dashboard /live  (http://127.0.0.1:8501/live)
```

Behavior, verified in code (`monitor/monitor.py`, `monitor/run.py`):

- Rolling ML window: 10 s (`--window 10`); evaluation at most every 15 s (`--ml-interval 15`); minimum 10 packets per window (`WINDOW_MIN_PACKETS`).
- SPIs unseen for 30 s are retired (`RETIRE_AFTER`).
- Snapshots publish periodically (every 200 ingested packets and every second while idle via a publisher thread).
- **Heartbeat continues while idle** even when no packets arrive.
- Packet counters stop when traffic stops.
- Live monitoring tails the sidecar capture; it does not substitute historical PCAPs.

`scripts/live-demo.ps1` runs the full scripted demo: testbed health check, SA teardown, capture-before-negotiation, fresh `IKE_SA_INIT`, traffic generation, ESP/ML verification, and passive-vs-ground-truth evaluation.

## 19. Interactive Dashboard

`app/app.py` (standard library only) serves offline and live modes:

- Live URL: `http://127.0.0.1:8501/live` (JSON: `/live.json`)
- Analyzer: `http://127.0.0.1:8501/` (`?run=<dir>` or `?pcap=<file>`)
- Executive: `http://127.0.0.1:8501/executive`
- Technical: `http://127.0.0.1:8501/technical`

The live page shows: sensor status, packet count, ESP count, IKE count, profile count, VPN gateway pair, protocol, outer IP version, SPIs, rekey status, ML prediction, confidence, class probabilities, security findings, evidence completeness, unknown fields, and event/change history. Every value retains its provenance label.

## 20. Reports

Generator: `reports/generate_report.py`

```powershell
python reports/generate_report.py --input <phase6.json> --out reports/results
```

Verified outputs in `reports/results/` include `sample_executive.html`, `sample_technical.html`, `assessment_full.json`, and `assessment_passive.json` (plus per-run `executive_*` / `assessment_*` files).

- **Executive report** - one-page summary: verified-configuration risk gauge, traffic behavior, threat matrix, priority findings, residual threats, limitations, data provenance. Written for decision-makers.
- **Technical report** - full detail: risk JSON, protocol/evidence table with per-field provenance, traffic ML probabilities plus raw prediction JSON, security findings table, threat matrix, limitations, provenance. Written for analysts.

## 21. How to Run the Project

1. **Start/verify the Docker testbed:**

```powershell
docker compose -f testbed/compose/testbed.yml up -d --build
powershell -File testbed/scripts/check-testbed.ps1
```

2. **Verify containers** (expect `sih-gateway-a`, `sih-gateway-b`, `sih-client-a`, `sih-client-b` running):

```powershell
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

3. **Start the live monitor:**

```powershell
.\scripts\start-live-monitor.ps1
```

4. **Open the dashboard:**

```text
http://127.0.0.1:8501/live
```

5. **Generate ICMP traffic:**

```powershell
docker exec sih-client-a ping -c 100 10.77.2.10
```

6. **Optionally generate VoIP-like and Video-like traffic** with the existing traffic generator:

```powershell
docker exec sih-gateway-a python3 /traffic/generator.py --profile voip-like --duration 20 --seed 20260904 --peer 10.77.12.10
docker exec sih-gateway-a python3 /traffic/generator.py --profile video-like --duration 20 --seed 20260904 --peer 10.77.12.10
```

7. **Observe** the packet/ESP counters rising and the ML prediction once a 10-second window holds enough packets.

## 22. Example Live Demonstration

1. Start the live monitor (`scripts/start-live-monitor.ps1`) and open `/live`.
2. Generate ICMP (`docker exec sih-client-a ping -c 100 10.77.2.10`) and watch the ESP count rise.
3. Wait for an ML window (10 s window, evaluated at most every 15 s) and show the ICMP classification if accepted.
4. Generate another traffic type (for example video-like) and show the updated behavior.
5. Open the security findings and the residual threat matrix.
6. Open `/executive` and `/technical` for the one-page and full-detail reports.

Note: rolling windows may contain mixed traffic when types are sent back-to-back, so controlled demos should use clean/fresh windows when comparing classes.

## 23. Testing and Validation

Actual current result (run locally): **69 passed**.

Test categories (from `tests/` and `integration/tests/`):

- Monitor flows, session correlation, IKE parsing, ML bridge, publication/heartbeat, replay parity, change/risk tracking, dashboard rendering, live rendering
- Security engine: evidence builders, rules, scoring
- Integration: end-to-end pipeline, report generation
- Passive-vs-full evidence comparison artifacts

Command from the repository:

```powershell
docker run --rm -v "${PWD}:/work" -w /work ipsec-test `
  python -m pytest tests/ integration/tests/ -p no:cacheprovider -q
```

Local equivalent: `python -m pytest -q`.

## 24. Live Verification Evidence

Live traffic monitoring was validated with an idle baseline, ICMP, and video-like flows (VoIP-like uses the same generator path):

- tcpdump observed current ESP on the transit interface.
- The canonical PCAP (`captures/monitor/live_current.pcap`) grew during transfer.
- `monitor/state/live_profiles.json` updated (packets, ESP/SPI counts, IKE sessions).
- The `/live` dashboard updated (counters, feed, ML label).
- Counters stabilized after traffic stopped.
- Heartbeat continued during idle.
- Historical captures were not substituted for live traffic.

## 25. Limitations

Mandatory reading. Passive encrypted ESP traffic alone **cannot reliably reveal**:

- AES-128 vs AES-256 (key size is not visible in ciphertext)
- AES-GCM vs AES-CBC (mode/integrity transform need endpoint evidence)
- Child-SA DH group
- PFS (needs negotiated/runtime DH evidence)
- Replay protection (endpoint/runtime property)
- SA lifetime (lives on the endpoints)
- Tunnel vs Transport mode in arbitrary captures

These values remain **Unknown** unless trusted runtime/configuration evidence is available.

Also:

- ML traffic classification is probabilistic; confidence is not certainty.
- Classes are behavioral categories, not real applications.
- Live rolling windows may contain mixed traffic.
- Controlled synthetic traffic may not represent every real-world application.
- ~95% validation performance does not mean every live sample will be classified correctly.

## 26. Security and Privacy Considerations

- The system does **not** decrypt user payloads.
- It analyzes encrypted **metadata** (sizes, timing, direction, endpoints).
- Metadata itself can reveal behavioral information — this residual traffic-analysis exposure is a genuine privacy risk and is reported as a moderate residual threat with shaping/padding guidance.
- Use this system only on networks you are authorized to monitor. The testbed exists precisely so validation happens on synthetic traffic, not other people's data.

## 27. Expected Deliverables and Proof

| Deliverable | Implementation / Proof |
|---|---|
| Working software prototype | Docker IPsec testbed (`testbed/`), offline pipeline (`integration/analyze.py`), live monitor (`monitor/run.py --tail`) |
| AI classification engine | Random Forest model (`ml_v2/models/traffic_classifier.joblib`) and evaluation results (`ml_v2/model_card.md`) |
| Interactive dashboard | Offline Analyzer (`/`) and live monitor (`/live`) in `app/` + `monitor/dashboard.py` |
| Security assessment report | Executive, technical, and JSON reports via `reports/generate_report.py` |
| Demonstration workflow/video | End-to-end demo process (`scripts/live-demo.ps1`, Section 22) |
| Technical documentation | This `documentation.md` plus `docs/` and `ml_v2/model_card.md` |
| Training/testing dataset | 180-run cleaned dataset (`dataset_v3_5_v2_full`) and feature exports (`dataset_exports_v2/`) |

Each item is demonstrated by running the commands in Section 21 and inspecting the dashboard, reports, dataset, and test output.

## 28. Repository Structure

Verified top-level layout (only paths that exist):

```text
app/                     dashboard server (standard library only)
integration/             unified offline pipeline (analyze.py) + tests
ml_v2/                   model, schema, prediction CLI, model card
ml/                      legacy training/evaluation scripts
monitor/                 live monitor, session correlator, bridges, dashboard contract
reports/                 report generator + generated samples
security/                assessment engine, policy, tests
testbed/                 compose file, configs, scenarios, scripts, traffic generator
tests/                   regression suite (monitor, security, reports)
scripts/                 start-live-monitor.ps1, live-demo.ps1, final-validation.ps1, demo.ps1
docs/                    full documentation set + UI screenshots (docs/images/)
dataset_exports_v2/      traffic_features.csv, vpn_observable_features.csv
dataset_v3_5_v2_full/    frozen reference dataset (180 runs)
analyzer/                passive PCAP feature extraction
ui/                      shared theme (Noto Sans, design tokens, components)
captures/                scenario captures + live monitor captures
```

## 29. Key Project Results

- Working strongSwan IPsec testbed (4 containers, IKEv2, XFRM).
- ESP/AH, tunnel/transport scenarios; IPv4 and IPv6.
- 180 validated runs across 15 scenarios and four traffic classes.
- Random Forest model: ~95% grouped CV accuracy (~0.9483 macro F1), ~91.7% unseen-scenario accuracy (~0.9143 macro F1).
- Deterministic evidence-first security assessment with transparent 0-100 scoring.
- Offline analysis, live monitoring with heartbeat, dashboard, and executive/technical reports.
- Regression suite passing (69 passed).

## 30. Conclusion

The project demonstrates that useful traffic behavior and security evidence can be extracted from encrypted IPsec VPN environments without decrypting user data.

The system combines:

- passive encrypted-flow analysis
- machine learning (only where inference is appropriate)
- deterministic security rules
- live monitoring with heartbeat
- evidence provenance on every value
- executive and technical reporting

Project principle:

> Observe what can be observed.
> Derive what can be proven.
> Use machine learning only where inference is appropriate.
> Report everything else as Unknown.