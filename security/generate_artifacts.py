import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security.assess_ipsec import run

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset_v3_5_v2_full"
OUT = ROOT / "security" / "results"
POLICY = json.loads((ROOT / "security/policy/default_policy.json").read_text())


def first_run(sid):
    for p in sorted((DATASET / sid).glob("*/metadata.json")):
        try:
            if json.loads(p.read_text(encoding="utf-8-sig"))["run"]["status"] == "PASS": return p.parent
        except (OSError, ValueError, KeyError): pass
    return None


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows, validation = [], {}
    for n in range(1, 16):
        sid = f"T{n:02d}"; run_dir = first_run(sid); result = run(run_dir, policy=POLICY)
        expected = json.loads((ROOT / "testbed/scenarios" / f"{sid}.json").read_text())
        checks = {}
        for field, expected_key in (("protocol", "ipsec_protocol"), ("mode", "mode"), ("encryption_algorithm", "encryption_algorithm"), ("ike_version", "ike_version")):
            if expected.get(expected_key) is not None: checks[field] = result["vpn_characteristics"]["values"].get(field) == expected[expected_key]
        mismatch = [k for k, ok in checks.items() if not ok]
        validation[sid] = {"run": str(run_dir), "checks": checks, "mismatches": mismatch}
        rows.append([sid, result["risk"]["score"], result["risk"]["level"], result["risk"]["evidence_completeness"], len(mismatch)])
    (OUT / "scenario_validation.json").write_text(json.dumps(validation, indent=2))
    with (OUT / "scenario_matrix.csv").open("w", newline="") as f:
        w = csv.writer(f); w.writerow(["scenario","protocol","mode","encryption","integrity","dh","pfs","rekey","ip_version","risk_score","result"])
        for sid in validation:
            r = run(first_run(sid), policy=POLICY); v = r["vpn_characteristics"]["values"]
            w.writerow([sid, v.get("protocol","unknown"), v.get("mode","unknown"), v.get("encryption_algorithm","unknown"), v.get("integrity_algorithm","unknown"), v.get("dh_group","unknown"), v.get("pfs","unknown"), v.get("rekey_status","unknown"), v.get("outer_ip_version","unknown"), r["risk"]["score"], "PASS" if not validation[sid]["mismatches"] else "REVIEW"])
    all_results = {sid: run(first_run(sid), policy=POLICY) for sid in validation}
    (OUT / "scoring_examples.json").write_text(json.dumps({k: v["risk"] for k,v in all_results.items()}, indent=2))
    passive = run(paths={"features": str(first_run("T01") / "features.json"), "pcap": str(first_run("T01") / "capture.pcap")}, policy=POLICY)
    (OUT / "passive_vs_full.json").write_text(json.dumps({"passive": passive, "full": all_results["T01"]}, indent=2))
    (OUT / "phase5_summary.json").write_text(json.dumps({"assessment_version":"phase5-v1", "scenarios":15, "mismatches": {k:v["mismatches"] for k,v in validation.items() if v["mismatches"]}, "verdict":"PASS" if all(not v["mismatches"] for v in validation.values()) else "REVIEW"}, indent=2))


if __name__ == "__main__": main()
