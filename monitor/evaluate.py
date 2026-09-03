#!/usr/bin/env python3
"""Passive-vs-ground-truth evaluation (VALIDATION ONLY).

Reads a monitor snapshot plus the scenario JSON. The pipeline itself
never sees ground truth; this script runs AFTERWARD and a scientifically
correct UNKNOWN counts as a successful abstention.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.dashboard import live_contract  # noqa: E402

ABSTAIN_FIELDS = ("child_encryption", "encryption_key_length", "integrity",
                  "child_dh", "pfs", "mode", "replay")


def norm(x):
    return str(x).strip().upper() if x is not None else "UNKNOWN"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    snap = json.load(open(a.profiles, encoding="utf-8"))
    truth = json.load(open(a.truth, encoding="utf-8"))
    profiles = snap.get("profiles", {})
    profs = list(profiles.values()) if isinstance(profiles, dict) else list(profiles)
    if not profs:
        print("no profiles observed: FAIL (nothing to evaluate)")
        return 2
    p = profs[0]
    # Leakage surface = what the dashboard contract would display.
    contract = live_contract(snap)
    cprof = (contract.get("profiles") or [{}])[0]
    cfields = cprof.get("fields", {})
    raw_vals = {
        "protocol": (p.get("protocols") or [None])[0],
        "outer": (p.get("ip_versions") or [None])[0],
        "ike_version": (p.get("ike") or {}).get("version"),
        "ke": (p.get("ike") or {}).get("ke_groups", []),
        "gateways": (p.get("gateway_a"), p.get("gateway_b")),
    }
    rows = []
    ok = True

    def row(passive, truth_v, result):
        rows.append((passive, truth_v, result))
        return result != "Mismatch"

    ok &= row("proto=%s" % norm(raw_vals["protocol"]), "proto=%s" % norm(truth.get("ipsec_protocol")),
              "Correct" if norm(raw_vals["protocol"]) == norm(truth.get("ipsec_protocol")) else "Mismatch")
    ok &= row("outer=IPv%s" % raw_vals["outer"], "ike_transport=%s" % truth.get("ike_transport_ip_version"),
              "Correct" if ("IPv%s" % raw_vals["outer"]) == truth.get("ike_transport_ip_version") else "Mismatch")
    ok &= row("ike=v%s" % raw_vals["ike_version"], "ike=v%s" % truth.get("ike_version"),
              "Correct" if raw_vals["ike_version"] == truth.get("ike_version") else "Mismatch")
    ke_names = [norm(g) for g in (raw_vals["ke"] or [])]
    want = norm(truth.get("dh_group_name"))
    ke_hit = (want in ke_names or
              any(str(truth.get("dh_group", "")) in str(g) for g in (raw_vals["ke"] or [])))
    ok &= row("ike_ke=%s" % (",".join(raw_vals["ke"]) or "UNKNOWN"),
              "dh=%s" % truth.get("dh_group_name"),
              "Correct" if ke_hit else ("Correct abstention" if not raw_vals["ke"] else "Mismatch"))
    gtruth_eps = (truth.get("ike_endpoints") or "").replace(" ", "").split("<->")
    ok &= row("eps=%s" % p.get("profile_id"), "eps=%s" % truth.get("ike_endpoints"),
              "Correct" if set(raw_vals["gateways"]) == set(gtruth_eps) else "Mismatch")
    abstain_map = {
        "child_encryption": truth.get("encryption_algorithm"),
        "encryption_key_length": truth.get("encryption_key_length"),
        "integrity": truth.get("integrity_algorithm"),
        "child_dh": truth.get("dh_group_name"),
        "pfs": truth.get("pfs"),
        "mode": truth.get("mode"),
        "replay": "endpoint property",
    }
    for field, tval in abstain_map.items():
        shown = (cfields.get(field) or {}).get("value")
        leaked = shown not in (None, "Unknown", "", [])
        ok &= row("%s=%s" % (field, shown), "%s=%s" % (field, tval),
                  "Mismatch (LEAKAGE!)" if leaked else "Correct abstention")
    tp = (p.get("traffic") or {})
    rows.append(("traffic=%s (%.2f)" % (tp.get("label"), tp.get("confidence", 0.0)),
                 "behavioral classes %s" % truth.get("traffic_profiles"), "Informational"))
    print("%-42s %-28s %s" % ("PASSIVE OBSERVATION", "GROUND TRUTH", "RESULT"))
    for a1, b1, c1 in rows:
        print("%-42s %-28s %s" % (a1, b1, c1))
    if a.out:
        Path(a.out).write_text(json.dumps(
            {"rows": [{"passive": a1, "truth": b1, "result": c1} for a1, b1, c1 in rows],
             "pass": bool(ok)}, indent=2), encoding="utf-8")
    print("EVALUATION:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
