# ML Model (Phase 4)

## Task

Predict the synthetic encrypted-flow behavior class of an IPsec-protected capture from passive side-channel features. Classes: `icmp`, `web`, `voip-like`, `video-like`. The model does not decrypt payloads and does not identify real applications.

## Model

- Selected model: **Random Forest** (400 trees) inside a scikit-learn pipeline with a median `SimpleImputer`.
- Artifact: `ml_v2/models/traffic_classifier.joblib` (dataset version `3.5-v2`, schema `phase4-v1`).
- Prediction CLI: `ml_v2/predict_traffic.py` (`--features` or `--pcap`, default threshold 0.60).
- Class handling: the CLI maps model probabilities to schema classes **by label name** (`model.classes_` order may differ across numpy versions and is never assumed positionally); output probability keys always follow the schema order `icmp`, `web`, `voip-like`, `video-like`.

## Evaluation methodology

- Primary: `StratifiedGroupKFold`, 5 folds, grouped by `group_scenario_id` — a scenario never appears in both train and validation within a fold (36 test rows per fold).
- Secondary: unseen-scenario holdout of three complete scenarios (T13, T14, T15): 144 train rows, 36 test rows, all four classes present.

## Final metrics (grouped CV, selected model)

| Metric | Mean | Std |
|---|---:|---:|
| Accuracy | 0.9500 | 0.0456 |
| Macro precision | 0.9621 | 0.0312 |
| Macro recall | 0.9500 | 0.0456 |
| Macro F1 | 0.9483 | 0.0480 |
| Weighted F1 | 0.9483 | 0.0480 |

Model comparison (grouped macro F1): logistic regression 0.8918, random forest 0.9483, hist gradient boosting 0.9279, kNN 0.8189, SVM 0.8140. Random forest was selected on grouped macro F1, not random-split accuracy.

## Holdout (T13, T14, T15)

- Accuracy 0.9167; macro precision 0.9375; macro recall 0.9167; macro F1 0.9143.

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| icmp | 0.7500 | 1.0000 | 0.8571 |
| web | 1.0000 | 0.6667 | 0.8000 |
| voip-like | 1.0000 | 1.0000 | 1.0000 |
| video-like | 1.0000 | 1.0000 | 1.0000 |

## Failure cases

The dominant error is `web -> ICMP` confusion: 9 of 45 web samples were classified as ICMP in grouped out-of-fold prediction. Web holdout recall improved from 0.4444 (previous dataset) to 0.6667 after the corrected T15 dataset, but the confusion is **not** solved. Holdout errors were 3 web-as-ICMP samples.

## Confidence and unknown handling

- Output includes predicted label, confidence, and the full probability distribution (`evidence_type: ml_inferred`).
- Confidence below the threshold returns `unknown`.

| Threshold | Coverage | Accuracy on covered |
|---:|---:|---:|
| 0.50 | 98.89% | 96.07% |
| 0.60 | 94.44% | 98.24% |
| 0.70 | 87.78% | 98.73% |
| 0.80 | 83.33% | 99.33% |

- Empty or unparseable PCAP and insufficient feature JSON return `unknown` with confidence `0.25` and uniform probabilities; the CLI never crashes or fabricates a confident prediction.

## Limitations

- Trained on a small, synthetic, controlled-testbed dataset; real-world generalization is not proven.
- Traffic classes are synthetic behavior categories, not application identities.
- Model confidence is an estimate, not certainty.
- Top features are ordinary passive observables (byte ratio, bps, size stats, pps, burst size, timing); ablation without protocol/environment markers stays within 0.0013 macro F1 (0.9470), which does not prove zero leakage.
