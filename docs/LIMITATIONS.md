# Limitations

## Cryptography from passive captures

- Encrypted payloads are never decrypted; no payload content is visible.
- AES-128 vs AES-192 vs AES-256 cannot be recovered from arbitrary ESP ciphertext appearance; key sizes are reported only from runtime/config evidence.
- AES-GCM vs AES-CBC is never guessed from ciphertext randomness or entropy.
- Child-SA algorithms may be hidden inside encrypted IKE exchanges; passive captures alone often cannot reveal them.
- Tunnel vs transport mode may be unknown from passive capture alone; mode is claimed only with runtime/XFRM evidence.
- PFS requires negotiated/runtime evidence; it is not inferred from the IKE SA's DH group.
- Replay protection requires runtime evidence; missing evidence yields `unknown`.
- SA lifetimes are reported only when present in runtime evidence.

## ML model

- Traffic classes (`icmp`, `web`, `voip-like`, `video-like`) are synthetic behavior categories generated in a controlled testbed; they are not application identities (the model cannot and does not identify WhatsApp, YouTube, or any real app).
- The dataset is small (180 runs) and fully synthetic; real-world generalization is not proven.
- Model confidence is an estimate, not certainty; below-threshold predictions return `unknown`.
- The known web -> ICMP confusion is documented and not solved.

## Security assessment

- The default policy is `project_default_policy`, a project-specific configuration — not an official NIST/PCI DSS/ISO 27001 compliance certification.
- Risk scores are rule-based penalties for proven failures; `unknown` fields add no penalty, so a low score with low evidence completeness means "no proven risk found", not "secure".
- Metadata side channels (outer IPs, packet sizes, timing, directionality, rate, duration, SPI values, IKE endpoints) remain observable even with strong encryption.

## Environment

- Results come from a controlled Docker/WSL2 testbed with fixed seeds and synthetic traffic profiles.
- The 3 reported web samples and ML probabilities may vary slightly across runs due to model/serialization nondeterminism; predictions are stable in all validated runs.
