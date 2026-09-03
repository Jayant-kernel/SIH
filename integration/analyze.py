#!/usr/bin/env python3
"""Run Phase 4 and Phase 5 once and emit one unified Phase 6 JSON result."""
import argparse, json, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security.assess_ipsec import run as assess_ipsec
from integration.schema import unknown


def _phase4(features=None, pcap=None):
    source = features or pcap
    if not source: return {}
    mode = "--features" if features else "--pcap"
    cli = ROOT / "ml_v2" / "predict_traffic.py"
    if not cli.exists(): return {"error": "Phase 4 prediction CLI is missing"}
    try:
        p = subprocess.run([sys.executable, str(cli), mode, str(source)], cwd=ROOT, capture_output=True, text=True, timeout=90)
        return json.loads(p.stdout) if p.returncode == 0 else {"error": p.stderr.strip() or "Phase 4 prediction failed"}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"error": str(exc)}


def _extract_features(pcap):
    if not pcap: return None, None
    temp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    temp.close()
    try:
        p = subprocess.run([sys.executable, str(ROOT / "analyzer" / "pcap_features.py"), str(pcap), "--out", temp.name], cwd=ROOT, capture_output=True, text=True, timeout=90)
        if p.returncode == 0 and Path(temp.name).exists(): return temp.name, None
        return None, p.stderr.strip() or "feature extraction failed"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)


def _source(run_dir=None, pcap=None, features=None):
    if run_dir: return "run_directory", str(Path(run_dir))
    if pcap and features: return "evidence_bundle", str(Path(pcap))
    if pcap: return "pcap", str(Path(pcap))
    if features: return "features", str(Path(features))
    return "none", None


def analyze(run_dir=None, pcap=None, features=None, metadata=None, evidence_paths=None):
    source_type, source = _source(run_dir, pcap, features)
    temp_features = None
    extraction_error = None
    if run_dir:
        d = Path(run_dir); feature_path = d / "features.json"; pcap_path = d / "capture.pcap"
        features = str(feature_path) if feature_path.exists() else None
        pcap = str(pcap_path) if pcap_path.exists() else None
    elif pcap and not features:
        temp_features, extraction_error = _extract_features(pcap); features = temp_features
    traffic = _phase4(features, pcap if not features else None)
    paths = dict(evidence_paths or {})
    if metadata: paths["metadata"] = metadata
    if features: paths["features"] = features
    if pcap: paths["pcap"] = pcap
    security = assess_ipsec(run_dir if run_dir else None, paths=paths, traffic_prediction=traffic)
    values = dict(security.get("vpn_characteristics", {}).get("fields", {}))
    for field in ("ike_proposal", "child_dh_group", "lifetime", "spi_count", "protected_ip_version", "ike_transport_ip_version", "aead", "local_ts", "remote_ts"):
        values.setdefault(field, unknown())
    return {
        "analysis_version": "phase6-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {"type": source_type, "source": source, "extraction_error": extraction_error},
        "components": {"model_version": traffic.get("model_version", "unknown"), "dataset_version": traffic.get("dataset_version", "unknown"), "security_version": security.get("assessment_version", "unknown"), "report_version": "phase6-v1"},
        "protocol_analysis": {"fields": values, "values": security.get("vpn_characteristics", {}).get("values", {})},
        "traffic_analysis": traffic,
        "security_assessment": security,
        "risk": security.get("risk", {}),
        "threat_matrix": security.get("threat_matrix", []),
        "evidence_summary": {"sources": security.get("input", {}).get("sources", []), "field_count": len(values), "unknown_fields": [k for k,v in values.items() if v.get("value") is None]},
        "limitations": security.get("limitations", []) + (["Some VPN properties cannot be determined from passive encrypted traffic alone."] if source_type == "pcap" else []),
    }
    if temp_features:
        try: Path(temp_features).unlink()
        except OSError: pass


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--run"); ap.add_argument("--pcap"); ap.add_argument("--features"); ap.add_argument("--metadata"); ap.add_argument("--output")
    a = ap.parse_args()
    if not any((a.run, a.pcap, a.features)): ap.error("provide --run, --pcap, or --features")
    result = analyze(a.run, a.pcap, a.features, a.metadata)
    text = json.dumps(result, indent=2)
    if a.output: Path(a.output).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__": main()
