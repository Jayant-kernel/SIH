#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features")
    ap.add_argument("--pcap")
    ap.add_argument("--model", default="ml_v2/models/traffic_classifier.joblib")
    ap.add_argument("--schema", default="ml_v2/feature_schema.json")
    ap.add_argument("--threshold", type=float, default=0.60)
    args = ap.parse_args()
    if bool(args.features) == bool(args.pcap):
        raise SystemExit("provide exactly one of --features or --pcap")

    schema = json.loads(Path(args.schema).read_text(encoding="utf-8"))
    source = args.features
    extraction_failed = False
    if args.pcap:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            source = f.name
        completed = subprocess.run(
            [sys.executable, "analyzer/pcap_features.py", args.pcap, "--out", source],
            capture_output=True,
            text=True,
        )
        extraction_failed = completed.returncode != 0

    data = {}
    if not extraction_failed:
        try:
            data = json.loads(Path(source).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            extraction_failed = True

    def nested(d, keys):
        for key in keys:
            if not isinstance(d, dict) or key not in d:
                return None
            d = d[key]
        return d

    values = []
    insufficient_features = False
    for feature in schema["features"]:
        section, key = feature.split(".", 1)
        value = nested(data, [section, key])
        if value is None:
            insufficient_features = True
            values.append(0.0)
        else:
            values.append(float(value or 0))

    model = joblib.load(args.model)
    labels = list(schema["classes"])
    empty_capture = (nested(data, ["capture", "total_packets"]) or 0) <= 0
    if extraction_failed or empty_capture or insufficient_features:
        prob = np.full(len(labels), 1.0 / len(labels))
        label, confidence = "unknown", float(prob.max())
    else:
        raw_prob = model.predict_proba(np.array([values], dtype=float))[0]
        prob = np.zeros(len(labels))
        for i, model_label in enumerate(model.classes_):
            prob[labels.index(model_label)] = raw_prob[i]
        idx = int(np.argmax(prob))
        confidence = float(prob[idx])
        label = labels[idx] if confidence >= args.threshold else "unknown"

    print(json.dumps({
        "traffic_prediction": {
            "label": label,
            "confidence": confidence,
            "probabilities": {name: float(prob[i]) for i, name in enumerate(labels)},
        },
        "model_version": "phase4-v1",
        "dataset_version": schema.get("dataset"),
        "feature_schema_version": schema.get("schema_version"),
        "evidence_type": "ml_inferred",
    }, indent=2))


if __name__ == "__main__":
    main()
