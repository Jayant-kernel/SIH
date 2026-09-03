# Scenarios

## Phase 1
- `baseline-s01.json` — IKEv2 ESP tunnel CBC `aes256-sha256-modp3072` / `aes256-sha256-modp2048` (GCM preferred but now available as S02)

## Phase 2 (representative, not full 15)
- `phase2/gcm.json` — AES-128-GCM tunnel `aes128gcm16-prfsha256-modp3072` (requires extra plugins)
- `phase2/ipv6-ike.json` — IKE over `fd77:77:0::10` (same TS as baseline, different outer)
- `phase2/transport.json` — ESP transport `10.77.0.10/32 === 10.77.0.20/32` (mode transport)
- `phase2/ah.json` — AH tunnel `10.77.8.0/24 === 10.77.9.0/24` (`proto ah`)
- `phase2/rekey.json` — manual `swanctl --rekey` of baseline (new SPIs)

Configs: `testbed/config/gateway-a/{gcm,ipv6-ike,transport,ah}.conf` (mirrored in gateway-b).

Future 15-scenario matrix will expand from these, producing `dataset/<scenario>/<run-id>/{capture.pcap,metadata.json}` with evidence categories `directly_observed / deterministically_derived / ml_inferred / unknown`.
