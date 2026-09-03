# Security Engine (Phase 5)

## Design

`security/assess_ipsec.py` is an evidence-first IPsec assessment engine. It never uses scenario IDs as inference shortcuts and never infers cryptographic properties from ciphertext appearance.

## Evidence provenance

Every assessed field carries one of exactly four evidence types:

- `directly_observed` — parsed from packets or runtime output
- `deterministically_derived` — computed from authoritative runtime/config evidence
- `ml_inferred` — Phase 4 traffic-behavior prediction only
- `unknown` — insufficient evidence (confidence 0.0)

Priority: runtime XFRM/swanctl > negotiated/installed-SA text > controlled-testbed metadata > passive PCAP/features > ML. Conflicts are recorded in the result; equal-authority conflicts resolve to `unknown` instead of a silent pick.

## Rule categories

- Protocol: ESP/AH present, IKE version, tunnel/transport mode
- Confidentiality: encryption present, cipher family, key size (runtime/config only), AEAD vs CBC+HMAC, AH-only has no confidentiality
- Integrity/authentication: AEAD, HMAC-SHA256/384/512; MD5/SHA1 would be flagged if present
- Key management: DH strength table (MODP1024 weak; MODP2048 acceptable; MODP3072 strong; ECP256 strong), PFS
- Lifecycle: SA rekey status, replay protection
- Metadata exposure: outer IPs, sizes, timing, directionality, rate, duration, SPIs remain visible

## PFS logic

PFS is derived only from Child-SA DH evidence (a DH group in the negotiated child proposal, or configuration). IKE SA DH alone never implies PFS. An omitted child-DH field yields `unknown`, not `disabled`.

## Rekey logic (corrected in final validation)

- Two directional SPIs are normal and never imply rekey.
- Passive heuristics (SPI counts, IKE packet text in captures) can only produce `possible_rekey`.
- `rekey_observed` requires authoritative runtime lifecycle evidence: an SPI-set change between before/after runtime snapshots (XFRM or swanctl).
- Correction applied before final freeze: the feature extractor's `rekey_observed` flag was found to fire on benign text ("rekeying in ...") plus a bogus `0x0` ESP SPI from NAT-T IKE dissection. T08's `rekey_observed` was an artifact (swanctl before/after show identical child SA #177 and SPIs); it now correctly reports `no_rekey` from runtime comparison. T14 (the dedicated 60s rekey scenario) shows a genuine SPI transition (child SA #201 `c238723c/c1395af4` -> #202 `c59309f6/c61e3f06`) and correctly reports `rekey_observed`.
- The frozen dataset and feature extractor were not modified; only the Phase 5 evidence interpretation changed.

## Replay protection

Assessed only from explicit XFRM `replay-window` evidence. Ambiguous or missing evidence yields `unknown`. Packet ordering alone is never used.

## Risk scoring

- Transparent 0-100 penalty score: `sum(rule penalties for proven failures)`; unknown fields add no penalty. Severity weights (policy-configurable): low 3, medium 10, high 20, critical 35.
- Risk bands: 0-19 low, 20-39 low-moderate, 40-59 moderate, 60-79 high, 80-100 critical.
- Evidence completeness = fraction of 9 important fields with authoritative evidence (protocol, encryption, key size, integrity, DH, mode, PFS, replay, rekey).
- Low completeness reduces certainty of the assessment and is reported, never hidden.

## Policy

`security/policy/default_policy.json` is named `project_default_policy`. It is a configurable project policy, **not** an official regulatory-compliance certification (no NIST/PCI DSS/ISO 27001 claim is made).

## Validation

- 12 unit tests cover provenance, conflicts, passive limitations, two-SPI handling, AH confidentiality, PFS, scoring, and unknown handling.
- Scenario validation T01-T15: parsed evidence matches expected protocol/mode/encryption/IKE version with zero mismatches (`security/results/scenario_validation.json`).
- Passive-only input yields many `unknown` fields and no fabricated crypto facts (`security/results/passive_vs_full.json`).
