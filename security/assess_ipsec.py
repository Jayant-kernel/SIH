#!/usr/bin/env python3
"""Evidence-first IPsec assessment. No scenario IDs are used as inference shortcuts."""
import argparse, json, re, subprocess, sys
from pathlib import Path
try:
    from .evidence import choose, load, parse_features, parse_text
    from .rules import assess
    from .schema import Evidence
    from .scoring import calculate
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from security.evidence import choose, load, parse_features, parse_text
    from security.rules import assess
    from security.schema import Evidence
    from security.scoring import calculate

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "security" / "policy" / "default_policy.json"


def metadata_events(data):
    """Controlled-testbed declarations are provenance, not passive observations."""
    if not isinstance(data, dict):
        return []
    source = "metadata.json (controlled testbed declaration)"
    scenario = data.get("scenario", {})
    mapping = {
        "ipsec_protocol": "protocol", "ike_version": "ike_version",
        "mode": "mode", "encryption_algorithm": "encryption_algorithm",
        "encryption_key_length": "encryption_key_length", "integrity_algorithm": "integrity_algorithm",
        "dh_group_name": "dh_group", "pfs": "pfs", "protected_ip_version": "protected_ip_version",
        "local_ts": "local_ts", "remote_ts": "remote_ts", "rekey_enabled": "rekey_configured",
    }
    out = []
    for src in (scenario, data.get("vpn_ground_truth", {})):
        for key, field in mapping.items():
            if key in src:
                value = src[key]
                if field == "dh_group" and isinstance(value, str):
                    value = value.upper().replace("MODP", "MODP")
                out.append(Evidence(field, value, "deterministically_derived", 1.0, source, "controlled configuration provenance"))
    return out


def _read_run(run_dir):
    d = Path(run_dir)
    names = {"metadata": "metadata.json", "swanctl_before": "swanctl-before.txt", "swanctl_after": "swanctl-after.txt", "xfrm": "xfrm-state.txt", "xfrm_before": "xfrm-state-before.txt", "xfrm_after": "xfrm-state-after.txt", "xfrm_policy": "xfrm-policy.txt", "features": "features.json", "pcap": "capture.pcap"}
    result = {}
    for key, name in names.items():
        path = d / name
        if path.exists(): result[key] = load(path)
    return result


def _rekey_events(inputs):
    """Compare authoritative runtime snapshots; passive heuristics never prove rekey."""
    pairs = (
        ("xfrm_before", "xfrm_after", r"\bspi\s+(?:0x)?([0-9a-f]+)"),
        ("swanctl_before", "swanctl_after", r"\b(?:in|out)\s+([0-9a-f]{6,16}),"),
    )
    events = []
    for before_key, after_key, pattern in pairs:
        before, after = inputs.get(before_key), inputs.get(after_key)
        if not before or not after: continue
        a = set(re.findall(pattern, str(before), re.I))
        b = set(re.findall(pattern, str(after), re.I))
        if not a or not b: continue
        if a != b:
            events.append(Evidence("rekey_status", "rekey_observed", "deterministically_derived", 1.0, before_key + "/" + after_key, "SPI set changed across runtime snapshots"))
        else:
            events.append(Evidence("rekey_status", "no_rekey", "deterministically_derived", 1.0, before_key + "/" + after_key, "identical SPI set across runtime snapshots"))
        break
    return events


def _traffic_prediction(path):
    if not path: return {}
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError): return {}


def _run_ml(features=None, pcap=None):
    source = features or pcap
    if not source or not (ROOT / "ml_v2" / "predict_traffic.py").exists(): return {}
    mode = "--features" if features else "--pcap"
    try:
        completed = subprocess.run([sys.executable, str(ROOT / "ml_v2" / "predict_traffic.py"), mode, str(source)], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        return json.loads(completed.stdout) if completed.returncode == 0 else {}
    except (OSError, ValueError, subprocess.TimeoutExpired): return {}


def run(run_dir=None, paths=None, policy=None, traffic_prediction=None):
    paths = paths or {}
    inputs = _read_run(run_dir) if run_dir else {}
    for key, path in paths.items():
        if key != "use_ml" and path: inputs[key] = load(path)
    if "tcpdump" not in inputs and run_dir:
        inputs["tcpdump"] = load(Path(run_dir) / "tcpdump-summary.txt")
    events = []
    if isinstance(inputs.get("metadata"), dict): events += metadata_events(inputs["metadata"])
    for key, data in inputs.items():
        if key in {"swanctl_before", "swanctl_after", "xfrm", "xfrm_before", "xfrm_after", "xfrm_policy", "tcpdump"} and data:
            events += parse_text(data, key + ".txt")
    if isinstance(inputs.get("features"), dict): events += parse_features(inputs["features"])
    events += _rekey_events(inputs)
    if not events:
        events.append(Evidence("ipsec_present", None, "unknown", 0.0, "no evidence", "No evidence bundle supplied"))
    important = ["protocol", "ike_version", "encryption_algorithm", "encryption_key_length", "integrity_algorithm", "dh_group", "mode", "pfs", "replay", "rekey_status"]
    present = {e.field for e in events}
    for field in important:
        if field not in present:
            events.append(Evidence(field, None, "unknown", 0.0, "not available", "No authoritative evidence available"))
    selected, conflicts = choose(events)
    facts = {k: v.value for k, v in selected.items() if v.value is not None}
    # Normalize explicit rekey configuration without confusing it with observed rekey.
    if "rekey_status" not in facts and facts.get("rekey_configured") is False:
        selected["rekey_status"] = Evidence("rekey_status", "no_rekey", "deterministically_derived", 1.0, "controlled configuration/runtime", "rekey disabled; two SPIs are directional")
        facts["rekey_status"] = "no_rekey"
    policy = policy or {}
    findings = assess(facts, selected, policy)
    ml = traffic_prediction or {}
    if not ml and paths.get("use_ml"):
        feature_source = paths.get("features") or (str(Path(run_dir) / "features.json") if run_dir and (Path(run_dir) / "features.json").exists() else None)
        pcap_source = paths.get("pcap") or (str(Path(run_dir) / "capture.pcap") if run_dir and (Path(run_dir) / "capture.pcap").exists() else None)
        ml = _run_ml(feature_source, pcap_source)
    if ml:
        tp = ml.get("traffic_prediction", {})
        events.append(Evidence("traffic_type", tp.get("label"), "ml_inferred", float(tp.get("confidence", 0.0)), "Phase 4 prediction", "traffic behavior only"))
    result = {
        "assessment_version": "phase5-v1",
        "input": {"run": str(run_dir) if run_dir else None, "sources": sorted(inputs)},
        "vpn_characteristics": {"fields": {k: {"value": v.value, "evidence_type": v.evidence_type, "confidence": v.confidence, "source": v.source} for k, v in selected.items()}, "values": facts},
        "traffic_prediction": ml,
        "security_findings": [f.json() for f in findings],
        "threat_matrix": _threats(facts),
        "risk": calculate(findings, selected, policy),
        "evidence": [e.json() for e in events],
        "conflicts": conflicts,
        "limitations": ["Passive ciphertext does not reveal AES key size, AES-GCM versus AES-CBC, mode, PFS, or DH group.", "Traffic type is probabilistic synthetic behavior classification."],
    }
    return result


def _threats(facts):
    threats = [{"threat": "passive traffic analysis", "condition": "outer metadata visible", "evidence": "packet sizes, timing, directionality", "risk": "moderate", "recommendation": "Consider traffic shaping or padding only if metadata resistance is required.", "evidence_type": "directly_observed"}]
    if facts.get("pfs") is False:
        threats.append({"threat": "historical decryption impact", "condition": "PFS disabled", "evidence": "Child-SA/configuration evidence", "risk": "elevated", "recommendation": "Enable a Child-SA DH group.", "evidence_type": "deterministically_derived"})
    if facts.get("protocol") == "AH":
        threats.append({"threat": "confidentiality loss", "condition": "AH-only protection", "evidence": "AH protocol evidence", "risk": "high", "recommendation": "Use ESP encryption where confidentiality is required.", "evidence_type": "deterministically_derived"})
    if facts.get("dh_strength_bits", 999999) < 2048 and facts.get("dh_strength_bits") != 256:
        threats.append({"threat": "weak key exchange", "condition": "weak DH group", "evidence": "negotiated DH evidence", "risk": "elevated", "recommendation": "Upgrade to MODP3072 or an appropriate elliptic-curve group.", "evidence_type": "deterministically_derived"})
    if facts.get("replay") == "disabled":
        threats.append({"threat": "replay attacks", "condition": "replay protection disabled", "evidence": "explicit XFRM replay window", "risk": "elevated", "recommendation": "Enable replay protection.", "evidence_type": "deterministically_derived"})
    return threats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run"); ap.add_argument("--metadata"); ap.add_argument("--swanctl"); ap.add_argument("--swanctl-before"); ap.add_argument("--swanctl-after"); ap.add_argument("--xfrm-state", "--xfrm", dest="xfrm"); ap.add_argument("--xfrm-policy"); ap.add_argument("--xfrm-before"); ap.add_argument("--xfrm-after"); ap.add_argument("--pcap"); ap.add_argument("--features"); ap.add_argument("--traffic-prediction"); ap.add_argument("--ml", action="store_true"); ap.add_argument("--policy", default=str(POLICY)); ap.add_argument("--output"); ap.add_argument("--summary", action="store_true")
    a = ap.parse_args(); policy = json.loads(Path(a.policy).read_text(encoding="utf-8"))
    paths = {k: v for k, v in {"metadata": a.metadata, "swanctl_before": a.swanctl_before, "swanctl_after": a.swanctl_after or a.swanctl, "xfrm": a.xfrm, "xfrm_policy": a.xfrm_policy, "xfrm_before": a.xfrm_before, "xfrm_after": a.xfrm_after, "features": a.features, "pcap": a.pcap}.items() if v}
    if a.ml: paths["use_ml"] = True
    result = run(a.run, paths, policy, _traffic_prediction(a.traffic_prediction))
    output = result["risk"] if a.summary else result
    text = json.dumps(output, indent=2)
    if a.output: Path(a.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(text)


if __name__ == "__main__": main()
