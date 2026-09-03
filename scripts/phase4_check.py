#!/usr/bin/env python3
"""Final-validation helper: verify the Phase 4 artifact, CLI alignment, and unknown handling."""
import json
import subprocess
import sys

import joblib

schema = json.load(open("ml_v2/feature_schema.json"))
model = joblib.load("ml_v2/models/traffic_classifier.joblib")
print("SCHEMA_CLASSES", list(schema["classes"]))
print("MODEL_CLASSES", [str(c) for c in model.classes_])
print("NFEATURES", len(schema["features"]))
print("DATASET", schema["dataset"])
print("CLASS_SET_MATCH", set(map(str, model.classes_)) == set(schema["classes"]))

completed = subprocess.run(
    [sys.executable, "ml_v2/predict_traffic.py", "--features",
     "dataset_v3_5_v2_full/T04/20260903-143933-601/features.json"],
    capture_output=True, text=True,
)
prediction = json.loads(completed.stdout)["traffic_prediction"]
print("PROBKEYS", list(prediction["probabilities"].keys()))
print("PREDICT_OK", prediction["label"] in schema["classes"]
      and list(prediction["probabilities"].keys()) == list(schema["classes"]))

empty = subprocess.run(
    [sys.executable, "ml_v2/predict_traffic.py", "--pcap", "tmp/empty.pcap"],
    capture_output=True, text=True,
)
empty_prediction = json.loads(empty.stdout)["traffic_prediction"]
print("PHASE4-UNKNOWN-OK", empty_prediction["label"] == "unknown"
      and empty_prediction["confidence"] == 0.25)
