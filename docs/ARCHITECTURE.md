# Architecture

## End-to-end pipeline

```text
IPsec Testbed (4 containers, strongSwan)
        |  deterministic runtime evidence (swanctl, XFRM) + packet captures
        v
Traffic Generator (icmp / web / voip-like / video-like)
        |  controlled, seeded traffic
        v
Packet Capture (tcpdump on transit)
        |
        v
Feature Extraction (analyzer/pcap_features.py)
        |  passive observation: sizes, timing, bursts, direction, SPI counts
        v
Phase 4 Traffic ML (ml_v2)                      Phase 5 Security Assessment (security/)
        |  ML inference only                           |  deterministic rules + policy
        v                                              v
Phase 6 Unified Pipeline (integration/analyze.py)
        |  one stable phase6-v1 JSON result
        v
Dashboard (app/app.py)  +  Reports (reports/generate_report.py)
```

## Stage classification

| Stage | Nature |
|---|---|
| Testbed runtime evidence (swanctl, XFRM) | Deterministic, authoritative |
| Traffic generation | Deterministic, controlled ground truth |
| Packet capture / feature extraction | Passive observation |
| Phase 4 classifier | ML inference (synthetic behavior classes only) |
| Phase 5 rules, PFS/DH/rekey/replay logic | Deterministic derivation from runtime/config evidence |
| Phase 6 integration | Deterministic join; provenance preserved |

## Four-container topology

```text
Client A (10.77.1.10, fd77:77:1::10)
   |
Gateway A (strongSwan; inside 10.77.1.1, transit 10.77.0.10)
   |
Untrusted Transit (10.77.0.0/24, fd77:77:0::/64)  <- ESP/AH captured here
   |
Gateway B (strongSwan; transit 10.77.0.20, inside 10.77.2.1)
   |
Client B (10.77.2.10, fd77:77:2::10)
```

All IPsec protection applies between the gateways across the transit network; clients see plain traffic on their protected LANs.

## Evidence provenance model

Every assessed field carries one of exactly four evidence types:

- `directly_observed` — parsed from packets or runtime output
- `deterministically_derived` — computed from authoritative runtime/config evidence
- `ml_inferred` — Phase 4 prediction (traffic behavior only)
- `unknown` — insufficient evidence (confidence 0.0)

Priority: runtime XFRM/swanctl > controlled-testbed metadata > passive PCAP/features > ML. Conflicts are recorded, and equal-authority conflicts resolve to `unknown` rather than a silent guess.
