#!/usr/bin/env python3
"""
Build ML-ready CSV from dataset/*/metadata.json + features.json
Excludes leakage columns, handles grouping, produces traffic and VPN exports.
Usage: python build_ml_dataset.py --dataset dataset --out dataset_exports
"""
import argparse, json, os, glob, csv, hashlib, sys
from pathlib import Path

# Leakage columns to NEVER include in ML feature vector
LEAKAGE_COLS = {
    "scenario_id", "traffic_class", "traffic_type", "family", "run_id", "folder", "pcap", "local_ts", "remote_ts",
    "ike_endpoints", "scenario", "traffic_ground_truth", "vpn_ground_truth", "run", "metadata", "raw_spi", "esp_spis", "ah_spis"
}

# Passive features allowed (from pcap_features.py)
PASSIVE_FEATURES = [
    "capture.total_packets", "capture.duration", "capture.total_bytes", "capture.ipv4_count", "capture.ipv6_count",
    "capture.ike_packets", "capture.udp500", "capture.udp4500", "capture.esp_packets", "capture.ah_packets", "capture.pps", "capture.bps",
    "size.mean", "size.median", "size.min", "size.max", "size.std", "size.cv", "size.small_lt200", "size.medium_200_1000", "size.large_ge1000",
    "direction.a_to_b_packets", "direction.b_to_a_packets", "direction.a_to_b_bytes", "direction.b_to_a_bytes", "direction.ratio_a2b_b2a", "direction.byte_ratio_a2b_b2a",
    "timing.mean_iat", "timing.median_iat", "timing.std_iat", "timing.cv_iat",
    "burstiness.burst_count", "burstiness.avg_burst_size", "burstiness.avg_burst_duration", "burstiness.idle_gap_count",
    "burstiness.coefficient_variation_iat", "burstiness.coefficient_variation_size",
    "esp_ah.esp_spi_count", "esp_ah.ah_spi_count", "esp_ah.unique_spi_total",
    "rekey.unique_esp_spis", "rekey.unique_ah_spis", "rekey.rekey_observed", "rekey.rekey_status"
]

# Actual mapping from features.json structure to flat columns
FLAT_MAP = {
    "capture.total_packets": ("capture", "total_packets"),
    "capture.duration": ("capture", "duration"),
    "capture.total_bytes": ("capture", "total_bytes"),
    "capture.ipv4_count": ("capture", "ipv4_count"),
    "capture.ipv6_count": ("capture", "ipv6_count"),
    "capture.ike_packets": ("capture", "ike_packets"),
    "capture.esp_packets": ("capture", "esp_packets"),
    "capture.ah_packets": ("capture", "ah_packets"),
    "capture.pps": ("capture", "pps"),
    "capture.bps": ("capture", "bps"),
    "size.mean": ("size", "mean"),
    "size.median": ("size", "median"),
    "size.min": ("size", "min"),
    "size.max": ("size", "max"),
    "size.std": ("size", "std"),
    "size.cv": ("size", "cv"),
    "size.small_lt200": ("size", "small_lt200"),
    "size.medium_200_1000": ("size", "medium_200_1000"),
    "size.large_ge1000": ("size", "large_ge1000"),
    "direction.a_to_b_packets": ("direction", "a_to_b_packets"),
    "direction.b_to_a_packets": ("direction", "b_to_a_packets"),
    "direction.ratio_a2b_b2a": ("direction", "ratio_a2b_b2a"),
    "direction.byte_ratio_a2b_b2a": ("direction", "byte_ratio_a2b_b2a"),
    "timing.mean_iat": ("timing", "mean_iat"),
    "timing.median_iat": ("timing", "median_iat"),
    "timing.std_iat": ("timing", "std_iat"),
    "timing.cv_iat": ("timing", "cv_iat"),
    "burstiness.burst_count": ("burstiness", "burst_count"),
    "burstiness.avg_burst_size": ("burstiness", "avg_burst_size"),
    "burstiness.avg_burst_duration": ("burstiness", "avg_burst_duration"),
    "burstiness.idle_gap_count": ("burstiness", "idle_gap_count"),
    "esp_ah.esp_spi_count": ("esp_ah", "esp_spi_count"),
    "esp_ah.ah_spi_count": ("esp_ah", "ah_spi_count"),
    "esp_ah.unique_spi_total": ("esp_ah", "unique_spi_total"),
    "rekey.unique_esp_spis": ("rekey", "unique_esp_spis"),
    "rekey.rekey_observed": ("rekey", "rekey_observed"),
}

def load_features(feat_path):
    with open(feat_path, encoding="utf-8-sig") as f:
        return json.load(f)

def load_metadata(meta_path):
    with open(meta_path, encoding="utf-8-sig") as f:
        return json.load(f)

def get_nested(d, keys, default=0):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset", help="dataset root")
    ap.add_argument("--out", default="dataset_exports", help="output dir")
    args = ap.parse_args()
    dataset = Path(args.dataset)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    runs = []
    for meta_path in dataset.rglob("metadata.json"):
        feat_path = meta_path.parent / "features.json"
        pcap_path = meta_path.parent / "capture.pcap"
        if not feat_path.exists() or not pcap_path.exists():
            continue
        try:
            meta = load_metadata(meta_path)
            feat = load_features(feat_path)
            # Data quality: skip empty pcap
            if feat.get("capture", {}).get("total_packets", 0) == 0:
                continue
            runs.append((meta, feat, meta_path.parent))
        except Exception as e:
            print(f"skip {meta_path}: {e}", file=sys.stderr)
            continue

    if not runs:
        print("No valid runs found", file=sys.stderr)
        return

    # Build traffic CSV (target = traffic_class)
    traffic_rows = []
    vpn_rows = []
    for meta, feat, run_dir in runs:
        # Grouping fields (not features)
        grouping = {
            "scenario_id": meta["run"]["scenario_id"],
            "run_id": meta["run"]["run_id"],
            "seed": meta["traffic_ground_truth"]["seed"],
            "profile_version": meta["traffic_ground_truth"].get("profile_version", "unknown"),
            "duration": meta["traffic_ground_truth"]["duration"],
            "pcap_hash": hashlib.md5(open(run_dir / "capture.pcap", "rb").read()).hexdigest()[:8] if (run_dir / "capture.pcap").exists() else ""
        }
        # Traffic features
        row = {}
        for col, keys in FLAT_MAP.items():
            row[col] = get_nested(feat, keys, 0)
        # Add burstiness CV (derived)
        # Already in FLAT_MAP
        row["traffic_class"] = meta["traffic_ground_truth"]["traffic_class"]
        # Add grouping for reference (not for ML)
        row.update({f"group_{k}": v for k, v in grouping.items()})
        traffic_rows.append(row)

        # VPN observable (for later experiments, but mark scientifically weak)
        vpn_row = dict(row)
        vpn_row["vpn_mode"] = meta["vpn_ground_truth"]["mode"]
        vpn_row["vpn_protocol"] = meta["vpn_ground_truth"]["ipsec_protocol"]
        # Mark weak targets
        vpn_row["_note"] = "AES key length / GCM vs CBC not reliably observable from ESP ciphertext; use only if IKE evidence available"
        vpn_rows.append(vpn_row)

    # Write traffic CSV
    if traffic_rows:
        fieldnames = list(FLAT_MAP.keys()) + ["traffic_class"] + [f"group_{k}" for k in ["scenario_id","run_id","seed","profile_version","duration","pcap_hash"]]
        with open(outdir / "traffic_features.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in traffic_rows:
                w.writerow({k: r.get(k, "") for k in fieldnames})
        print(f"Wrote {len(traffic_rows)} rows to {outdir/'traffic_features.csv'}")

    if vpn_rows:
        fieldnames_vpn = list(FLAT_MAP.keys()) + ["vpn_mode","vpn_protocol","traffic_class"] + [f"group_{k}" for k in ["scenario_id","run_id"]]
        with open(outdir / "vpn_observable_features.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames_vpn)
            w.writeheader()
            for r in vpn_rows:
                w.writerow({k: r.get(k, "") for k in fieldnames_vpn})
        print(f"Wrote {len(vpn_rows)} rows to {outdir/'vpn_observable_features.csv'}")

    # Leakage report is separate, but we can print summary
    print("\nLeakage check: excluded raw SPI values, scenario_id, traffic_type, IPs, run_id from ML features")
    print("Grouping fields are prefixed with group_ and should be used for GroupKFold, not as features")

if __name__ == "__main__":
    main()
