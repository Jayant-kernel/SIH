from .schema import Finding


def _finding(rule_id, title, category, severity, status, desc, evidence, recommendation="", confidence=0.0):
    return Finding(rule_id, title, category, severity, status, desc, evidence, recommendation, confidence)


def assess(facts, selected, policy):
    findings = []
    def check(i, title, category, value, good, severity, description, recommendation=""):
        ev = [selected[value].json()] if value in selected else []
        if value not in facts:
            findings.append(_finding(i, title, category, severity, "unknown", "Insufficient evidence", ev, recommendation))
        else:
            confidence = selected[value].confidence if value in selected else 1.0
            findings.append(_finding(i, title, category, "info" if good else severity, "pass" if good else "fail", description, ev, recommendation, confidence))
    protocol = facts.get("protocol")
    check("IPSEC-PROTO-001", "IPsec protocol present", "protocol", "protocol", protocol in {"ESP", "AH"}, "high", str(protocol or "unknown"))
    check("IPSEC-IKE-001", "IKEv2 negotiated", "key_management", "ike_version", facts.get("ike_version") == 2, "medium", str(facts.get("ike_version", "unknown")))
    alg = facts.get("encryption_algorithm")
    check("IPSEC-ENC-001", "Encryption present", "confidentiality", "encryption_algorithm", alg in {"AES-GCM", "AES-CBC"}, "high", str(alg or "unknown"), "Use ESP with an approved encryption algorithm.")
    if protocol == "AH":
        ev = [selected["protocol"].json()] if "protocol" in selected else []
        confidence = selected["protocol"].confidence if "protocol" in selected else 1.0
        findings.append(_finding("IPSEC-ENC-002", "AH provides no confidentiality", "confidentiality", "high", "fail", "AH authenticates packets but does not encrypt payloads.", ev, "Use ESP with encryption where confidentiality is required.", confidence))
    key = facts.get("encryption_key_length")
    check("IPSEC-KEY-001", "Encryption key size", "confidentiality", "encryption_key_length", key in policy.get("allowed_key_sizes", [128, 192, 256]), "medium", str(key or "unknown"))
    integrity = facts.get("integrity_algorithm")
    check("IPSEC-AUTH-001", "Integrity/authentication", "integrity", "integrity_algorithm", integrity in {"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "AEAD-GCM"}, "high", str(integrity or "unknown"))
    dh = facts.get("dh_strength_bits")
    check("IPSEC-DH-001", "DH group strength", "key_management", "dh_strength_bits", dh is not None and (dh >= policy.get("minimum_dh_bits", 2048) or dh == 256), "high", str(dh or "unknown"), "Upgrade the Diffie-Hellman group to MODP3072 or an approved elliptic-curve group.")
    pfs = facts.get("pfs")
    check("IPSEC-PFS-001", "Perfect Forward Secrecy", "key_management", "pfs", pfs is True or not policy.get("require_pfs", False), "medium", str(pfs if pfs is not None else "unknown"), "Enable a Child-SA DH group to provide Perfect Forward Secrecy.")
    mode = facts.get("mode")
    check("IPSEC-MODE-001", "Tunnel or transport mode", "protocol", "mode", mode in {"tunnel", "transport"}, "medium", str(mode or "unknown"))
    replay = facts.get("replay")
    check("IPSEC-REPLAY-001", "Replay protection", "lifecycle", "replay", replay == "enabled" or not policy.get("require_replay_protection", False), "medium", str(replay or "unknown"))
    rekey = facts.get("rekey_status")
    check("IPSEC-REKEY-001", "SA lifecycle", "lifecycle", "rekey_status", rekey in {"rekey_observed", "no_rekey"}, "medium", str(rekey or "unknown"))
    if rekey == "no_rekey":
        findings[-1].status = "pass"
        findings[-1].severity = "info"
        findings[-1].description = "No lifecycle rekey observed; two directional SPIs are normal."
    elif rekey == "possible_rekey":
        findings[-1].status = "warning"
        findings[-1].severity = "low"
        findings[-1].description = "Passive rekey heuristic without runtime lifecycle corroboration."
        findings[-1].recommendation = "Collect runtime XFRM/swanctl before/after evidence to confirm or refute rekey."
    findings.append(_finding("IPSEC-META-001", "Traffic metadata exposure", "metadata_exposure", "low", "warning", "Outer endpoints, ESP/AH, sizes, timing, directionality, and rate may remain visible.", [], "Consider traffic shaping or padding where metadata resistance is required.", 1.0))
    return findings
