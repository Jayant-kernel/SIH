# Results Summary

## Phase 1 — Testbed

Four-container site-to-site IPsec VPN (strongSwan 5.9.8, swanctl/vici, privileged XFRM) validated end-to-end: IKEv2 establishment, ESP tunnel with AES-CBC-256/HMAC-SHA256/MODP3072, client-to-client connectivity, and transit-only captures. Baseline verifier: `testbed/scripts/check-testbed.ps1`.

## Phase 2 — Protocol coverage

Five controlled variations validated with per-variant PCAPs and XFRM evidence: AES-GCM (AEAD), IPv6 IKE transport, ESP transport mode, AH tunnel, and lifecycle rekey. Verifier: `testbed/scripts/check-phase2.ps1`. Ground truth in `testbed/scenarios/`.

## Phase 3 — Dataset

Final dataset `dataset_v3_5_v2_full` (version `3.5-v2`): 180 valid runs, 15 scenarios x 4 traffic classes x 3 repetitions, zero empty PCAPs, balanced classes, corrected T15 (12/12 clean ESP-only runs). Independent validator: `testbed/scripts/validate-dataset.ps1`.

## Phase 4 — Traffic ML

Random Forest on 36 passive features, grouped by scenario.

| Evaluation | Result |
|---|---|
| Grouped CV accuracy | 0.9500 +/- 0.0456 |
| Grouped CV macro F1 | 0.9483 +/- 0.0480 |
| Unseen-scenario holdout (T13/T14/T15) | accuracy 0.9167, macro F1 0.9143 |
| Best model selection basis | grouped macro F1 (5 models compared) |

Known weakness: web -> ICMP confusion (9/45 out-of-fold web samples). Details in `ml_v2/results/`.

## Phase 5 — Security engine

Evidence-first assessment with four provenance types, deterministic crypto facts (runtime/config only), PFS from Child-SA DH only, rekey from runtime SPI-set comparison, replay from explicit XFRM windows. T01-T15 scenario validation: zero mismatches. Final rekey correction: T08 artifact removed (no_rekey from runtime), T14 genuine rekey confirmed from runtime (SA #201 -> #202 with new SPIs).

Risk scores (project policy): ESP/GCM and CBC scenarios with PFS 0 (low); PFS-disabled CBC scenarios 0 under default policy (policy-dependent); AH-only scenarios 50 (moderate) driven by the high-severity no-confidentiality findings.

Artifacts: `security/results/` (scenario matrix, validation, passive-vs-full, scoring examples, summary).

## Phase 6 — Integration, dashboard, reports

Unified `phase6-v1` pipeline reusing Phase 4 CLI and Phase 5 engine without duplication. Representative scenarios (T03, T04, T07, T08, T14, T15) processed; passive-only and full-evidence modes validated; local dashboard verified over HTTP; executive and technical reports generated. Artifacts: `integration/results/`, `reports/results/`.

## Final validation

`scripts/final-validation.ps1` re-verifies dataset integrity, Phase 4 artifacts, Phase 5 tests/validation, Phase 6 tests, dashboard startup/HTTP, and report generation. Results recorded in `docs/FINAL_VALIDATION.md`.
