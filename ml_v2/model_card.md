# Encrypted Traffic-Type Classifier

## Task

This model classifies traffic behavior from passive IPsec observables. It predicts four synthetic traffic categories:

- `icmp`
- `web`
- `voip-like`
- `video-like`

## Dataset

- Dataset: `dataset_v3_5_v2_full`
- Version: `3.5-v2`
- Size: 180 rows across 15 scenarios
- Class balance: 45 samples per class
- Replication: 3 samples per scenario/class
- Corrected T15: 12 repaired ESP-only captures, 3 per class

The previous T15 plaintext-capture contamination issue was repaired before v2 training.

## Selected Model

Random Forest.

## Grouped Evaluation

Primary evaluation uses `StratifiedGroupKFold` with 5 folds, grouped by `group_scenario_id`. No scenario appears in both training and validation within a fold.

- Accuracy: `0.9500 +/- 0.0456`
- Macro precision: `0.9621 +/- 0.0312`
- Macro recall: `0.9500 +/- 0.0456`
- Macro F1: `0.9483 +/- 0.0480`
- Weighted F1: `0.9483 +/- 0.0480`

## Unseen-Scenario Holdout

Held-out scenarios: `T13`, `T14`, `T15`.

- Accuracy: `0.9167`
- Macro precision: `0.9375`
- Macro recall: `0.9167`
- Macro F1: `0.9143`

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| ICMP | 0.7500 | 1.0000 | 0.8571 |
| web | 1.0000 | 0.6667 | 0.8000 |
| voip-like | 1.0000 | 1.0000 | 1.0000 |
| video-like | 1.0000 | 1.0000 | 1.0000 |

## Failure Cases

The primary observed failure is `web -> ICMP` confusion. In the overall out-of-fold confusion matrix, 9 web samples were classified as ICMP. This remains an observed error and is not considered solved.

## Confidence Behavior

| threshold | coverage | covered accuracy |
|---|---:|---:|
| 0.50 | 98.89% | 96.07% |
| 0.60 | 94.44% | 98.24% |
| 0.70 | 87.78% | 98.73% |
| 0.80 | 83.33% | 99.33% |

Higher thresholds reduce coverage and increase covered accuracy. Predictions below the configured threshold can return `unknown`. Probabilities are confidence estimates, not certainty.

Empty or unparseable captures return `unknown` with confidence `0.25` and uniform class probabilities. Insufficient feature JSON also returns `unknown` with confidence `0.25`.

## Ablation

| Feature set | Accuracy | Macro F1 |
|---|---:|---:|
| Full passive features | 0.9500 | 0.9483 |
| Reduced behavioral features | 0.9500 | 0.9470 |

Removing explicit IP-version, IKE, ESP/AH, SPI, and rekey indicators did not materially reduce grouped performance. This does not prove zero leakage.

## Scientific Limitations

- The model does not decrypt ESP.
- The model does not identify real applications such as WhatsApp or YouTube.
- `web`, `voip-like`, and `video-like` are synthetic behavioral categories.
- The model does not infer AES key size from ciphertext appearance.
- The model does not prove tunnel or transport mode solely from ciphertext.
- Confidence is not certainty.
- The dataset is small and synthetic.
- Broader real-world validation is still required.
