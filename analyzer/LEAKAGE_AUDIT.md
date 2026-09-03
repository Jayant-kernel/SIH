# Leakage Audit - Phase 3.5

**Date:** 2026-09-02
**Dataset:** dataset/ (21 runs smoke, target 150-300)
**Feature extractor:** analyzer/pcap_features.py v3.5

## ML Feature Vector MUST NOT Contain

| Leakage Source | Severity | Description | Mitigation |
|---|---|---|---|
| `scenario_id` (e.g., T01) | HIGH | Direct label for VPN config, would allow trivial VPN classification | Excluded from CSV, kept as `group_scenario_id` for GroupKFold only |
| `traffic_class` / `traffic_type` | HIGH | Target label itself | Kept as label column `traffic_class`, not as feature |
| `family` name | HIGH | Encodes VPN family, correlates with encryption | Excluded |
| `run_id`, folder name, `pcap` path | MEDIUM | Unique per run, could be memorized | Excluded, kept as `group_run_id` |
| `local_ts` / `remote_ts` (e.g., 10.77.11.0/24) | HIGH | Static IP uniquely identifies scenario (e.g., 10.77.11.0 only used by T04 GCM) | Excluded from features; traffic generator uses those IPs but ML sees only packet counts/sizes, not IPs |
| Ground-truth `encryption_algorithm`, `key_length`, `mode`, `protocol` | HIGH | Would allow VPN crypto prediction without passive evidence | Excluded from traffic CSV; kept in `vpn_observable_features.csv` with warning that AES-128 vs 256 not observable from ESP ciphertext |
| Raw `esp_spis` numeric values (e.g., 0xc151692a) | MEDIUM | Random per SA, not predictive, could be memorized | Excluded; only `esp_spi_count` and `unique_spi_total` kept |
| `pcap_hash` | LOW | Unique per file | Kept as `group_pcap_hash` for duplicate detection, not as feature |
| `seed`, `duration` as feature | MEDIUM | Duration 8-15 varies per run, but if one traffic class always uses same duration, would leak | Duration is randomized 8-15 across all classes (see profiles.json `duration_range`), seed is grouping only (`group_seed`), not feature |

## Indirect Leakage Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Unique packet count per traffic class hard-coded (e.g., web always 15 requests) | MEDIUM | Profiles now use `requests_range [10,20]` with seed-based randomization; actual count logged in `traffic_ground_truth.generator_output` |
| One VPN always paired with one traffic type | HIGH | Smoke dataset ensures each VPN (T01,T04,T06,T08,T10) contains all 4 traffic classes (icmp/web/voip/video) |
| Static IP `10.77.0.10` only used for transport | LOW | Transport's `a_to_b` is host-to-host; but `a_to_b` counts are derived from first packet src, not IP value. IP not in features. |
| `profile_version` could encode time | LOW | Kept as `group_profile_version`, not feature |

## SPI Misuse

- Raw SPI `#c151692a` removed from ML vector. Only `esp_spi_count` (1,2,4) and `unique_spi_total` kept.
- `rekey_observed` now requires `unique_esp_spis >2` (not >1), because normal bidirectional ESP has 2 SPIs. Checked via `pcap_features.py` rekey logic: `unique_esp_spis >2` or `CREATE_CHILD_SA` in pcap.

## Verification

- `analyzer/build_ml_dataset.py` explicitly lists `PASSIVE_FEATURES` and `FLAT_MAP`; `LEAKAGE_COLS` are excluded.
- `group_*` columns are for `GroupKFold` by `scenario_id` to avoid near-duplicate leakage across train/test.
- No `scenario_id` appears in `traffic_features.csv` header except as `group_scenario_id`.
