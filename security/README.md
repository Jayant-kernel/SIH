# Phase 5 IPsec Security Assessment

`assess_ipsec.py` produces stable JSON from an evidence bundle or run directory. Runtime XFRM and strongSwan evidence has highest priority, followed by negotiated/runtime text, controlled-testbed metadata, passive packet observations, and finally ML traffic inference. Conflicts are retained rather than silently discarded.

Evidence types are strictly `directly_observed`, `deterministically_derived`, `ml_inferred`, and `unknown`. Missing evidence remains unknown and receives confidence `0.0`. The engine never infers cipher, key size, mode, PFS, or DH group from ciphertext appearance. Two directional SPIs do not mean rekey; lifecycle evidence is required.

The project policy is `security/policy/default_policy.json` and is named `project_default_policy`; it is not a regulatory compliance profile. Rule findings use pass/fail/warning/unknown status and a transparent 0-100 rule penalty score. Unknown fields do not incur worst-case penalties. Evidence completeness is the proportion of the nine important fields with selected evidence.

Usage:

```text
python security/assess_ipsec.py --run dataset_v3_5_v2_full/T01/<run-id>
python security/assess_ipsec.py --run dataset_v3_5_v2_full/T01/<run-id> --summary
python security/generate_artifacts.py
```

Phase 4 is integrated only for synthetic traffic-type behavior and is labeled `ml_inferred`; it cannot affect crypto, mode, PFS, DH, replay, or lifecycle findings. Passive-only input therefore reports many unknown fields, while full controlled-run evidence can report deterministic configuration/runtime properties.
