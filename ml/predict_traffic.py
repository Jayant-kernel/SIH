#!/usr/bin/env python3
import argparse, json, subprocess, tempfile, sys
from pathlib import Path
import joblib, numpy as np

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--features"); ap.add_argument("--pcap"); ap.add_argument("--model",default="ml/models/traffic_classifier.joblib"); ap.add_argument("--schema",default="ml/feature_schema.json"); ap.add_argument("--threshold",type=float,default=0.60); a=ap.parse_args()
    if bool(a.features)==bool(a.pcap): raise SystemExit("provide exactly one of --features or --pcap")
    schema=json.loads(Path(a.schema).read_text(encoding="utf-8")); source=a.features
    extraction_failed = False
    if a.pcap:
        with tempfile.NamedTemporaryFile(suffix=".json",delete=False) as f: source=f.name
        completed = subprocess.run([sys.executable,"analyzer/pcap_features.py",a.pcap,"--out",source],capture_output=True,text=True)
        extraction_failed = completed.returncode != 0
    data = {} if extraction_failed and not Path(source).exists() else json.loads(Path(source).read_text(encoding="utf-8-sig"))
    def nested(d, keys):
        for k in keys:
            if not isinstance(d,dict) or k not in d:return 0
            d=d[k]
        return d
    X=[]
    for feature in schema["features"]:
        section,key=feature.split(".",1); X.append(float(nested(data,[section,key]) or 0))
    model=joblib.load(a.model)
    empty_capture = nested(data,["capture","total_packets"]) <= 0
    if extraction_failed or empty_capture:
        labels = schema["classes"]
        prob = np.full(len(labels), 1.0 / len(labels))
        label, confidence = "unknown", float(prob.max())
    else:
        raw_prob=model.predict_proba(np.array([X],dtype=float))[0]
        prob=np.zeros(len(schema["classes"]))
        for i, model_label in enumerate(model.classes_): prob[schema["classes"].index(model_label)] = raw_prob[i]
        idx=int(np.argmax(prob)); confidence=float(prob[idx]); label=schema["classes"][idx] if confidence>=a.threshold else "unknown"
        labels=schema["classes"]
    print(json.dumps({"traffic_prediction":{"label":label,"confidence":confidence,"probabilities":{k:float(prob[i]) for i,k in enumerate(labels)}},"model_version":"phase4-v1","feature_schema_version":schema["schema_version"],"evidence_type":"ml_inferred"},indent=2))
if __name__=="__main__":main()
