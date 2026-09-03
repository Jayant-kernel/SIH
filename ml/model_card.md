# Encrypted Traffic-Type Classifier

- Task: predict synthetic encrypted-flow traffic behavior class.
- Dataset: version 3.5-v1, 180 rows, four balanced classes.
- Evaluation: StratifiedGroupKFold grouped by `group_scenario_id`; scenarios never cross primary folds.
- Selected model: `hist_gradient_boosting`.
- Grouped macro F1: 0.954 +/- 0.053.
- Holdout scenarios: T13, T14, T15.
- Holdout macro F1: 0.822; holdout accuracy: 0.833.
- Holdout per-class recall: ICMP 1.000, web 0.444, voip-like 0.889, video-like 1.000.
- Behavioral ablation macro F1: 0.954 +/- 0.053 after removing IP-version, IKE, ESP/AH, SPI, and rekey indicators.
- Most influential features by permutation importance: `capture.total_bytes`, `timing.median_iat`, `direction.byte_ratio_a2b_b2a`, and `timing.std_iat`.
- Confidence threshold: configurable; threshold results are in `results/threshold_analysis.csv`.

This model predicts traffic behavior class from encrypted-flow metadata. It does not decrypt payload, infer AES key size, prove application identity, or identify WhatsApp/YouTube. Classes are synthetic traffic categories.

Operational behavior: empty or unparseable PCAP input returns `unknown` with uniform 0.25 confidence. With a threshold of 0.80, cross-validated coverage is 97.2% and accuracy on covered rows is 96.6%.

Known limitations: small dataset, synthetic traffic, scenario generalization uncertainty, materially weaker web recall on the held-out scenarios, and confidence probabilities are model outputs rather than certainty. The persisted feature schema is `feature_schema.json`; the training input excludes group, identifier, IP-address, VPN-ground-truth, and raw-SPI fields.
