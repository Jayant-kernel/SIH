#!/usr/bin/env python3
"""Continuous security bridge. Builds Phase 5 Evidence objects ONLY from
passive observations, then reuses security.rules.assess and
security.scoring.calculate WITHOUT changing their semantics.

Output separates VERIFIED CONFIGURATION RISK (rule-based, relabeled so a
0 is never mistaken for 'proven secure') from RESIDUAL/PASSIVE THREATS.
Unknown never becomes failure (the reused scorer already guarantees it).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security.schema import Evidence  # noqa: E402
from security.rules import assess  # noqa: E402
from security.scoring import calculate  # noqa: E402

LOW_EVIDENCE_CUTOFF = 0.5
LOW_EVIDENCE_TEXT = ("Insufficient evidence for a complete VPN security "
                     "assessment.")


def profile_evidence(profile):
    """Passive-only evidence. Anything not observable here stays absent
    (the rules layer reports it as unknown)."""
    ev = []
    protos = profile.get("protocols", [])
    if protos:
        proto = sorted(protos)[0]
        ev.append(Evidence("protocol", proto, "directly_observed", 1.0,
                           "%s packet" % proto,
                           "passively observed on the wire"))
    ivs = profile.get("ip_versions", [])
    if ivs:
        ev.append(Evidence("outer_ip_version", "IPv%d" % sorted(ivs)[0],
                           "directly_observed", 1.0, "IP header",
                           "outer envelope only; inner addresses in tunnel "
                           "mode are NOT observable"))
    ver = (profile.get("ike") or {}).get("version")
    if ver:
        ev.append(Evidence("ike_version", ver, "directly_observed", 1.0,
                           "IKE packet", "negotiation was captured"))
    rs = profile.get("rekey_status", "unknown")
    if rs in ("no_rekey", "possible_rekey", "rekey_observed"):
        ev.append(Evidence("rekey_status", rs, "deterministically_derived", 1.0,
                           "SPI timeline",
                           "; ".join(profile.get("rekey_evidence", []))))
    return ev


def assess_profile(profile, policy):
    events = profile_evidence(profile)
    selected = {e.field: e for e in events}
    facts = {k: v.value for k, v in selected.items() if v.value is not None}
    findings = assess(facts, selected, policy)
    risk = calculate(findings, selected, policy)
    completeness = risk.get("evidence_completeness", 0.0)
    residual = []
    if facts.get("protocol") in ("ESP", "AH"):
        residual.append({
            "threat": "passive traffic analysis",
            "condition": "outer metadata visible (endpoints, sizes, timing, direction)",
            "risk": "moderate",
            "recommendation": "Consider traffic shaping or padding only if metadata "
                              "resistance is a requirement.",
            "evidence_type": "directly_observed"})
    return {
        "findings": [f.json() for f in findings],
        # Relabeled: this score covers VERIFIED configuration findings only.
        "verified_configuration_risk": {
            "score": risk.get("score"), "level": risk.get("level"),
            "penalty_points": risk.get("penalty_points"),
            "formula": risk.get("formula"), "transparent": True},
        "risk": risk,
        "residual_threats": residual,
        "evidence_completeness": completeness,
        "low_evidence_warning": (LOW_EVIDENCE_TEXT if completeness < LOW_EVIDENCE_CUTOFF
                                 else ""),
        "unknown_fields": [f.id for f in findings if f.status == "unknown"],
    }
