# Testbed

## Design

Four Docker containers form a site-to-site IPsec VPN. Gateways run Debian bookworm with strongSwan 5.9.8 (swanctl/vici) and extra plugin packages enabling AES-GCM and AH. Gateways are privileged so strongSwan can install XFRM kernel states. Clients are minimal Debian hosts with static routes.

```text
client-a (10.77.1.10, fd77:77:1::10)
    |
gateway-a (protected 10.77.1.1 / transit 10.77.0.10)
    |
transit 10.77.0.0/24, fd77:77:0::/64   <- captures taken here
    |
gateway-b (transit 10.77.0.20 / protected 10.77.2.1)
    |
client-b (10.77.2.10, fd77:77:2::10)
```

- IPv4: transit `10.77.0.0/24`; protected LANs `10.77.1.0/24` and `10.77.2.0/24` (per-scenario dummy subnets for some scenarios).
- IPv6: ULA prefixes `fd77:77:0::/64`, `fd77:77:1::/64`, `fd77:77:2::/64`; T15 protects `fd77:77:23::/64 <-> fd77:77:24::/64` over IPv4 IKE transport.
- Evidence captured per run: `capture.pcap`, `metadata.json`, `features.json`, `swanctl-before.txt`, `swanctl-after.txt`, `xfrm-state.txt`, `xfrm-policy.txt`, `tcpdump-summary.txt`, `run.log`.

## Scenario matrix (T01-T15)

| Scenario | Protocol | Mode | Encryption | Integrity | DH | PFS | IP version |
|---|---|---|---|---|---|---|---|
| T01 | ESP | tunnel | AES-CBC-256 | HMAC-SHA256 | MODP3072 | yes | IPv4+IPv6 |
| T02 | ESP | tunnel | AES-CBC | HMAC-SHA256 | MODP2048 | yes | IPv4 |
| T03 | ESP | tunnel | AES-CBC | HMAC-SHA256 | MODP2048 | no | IPv4 |
| T04 | ESP | tunnel | AES-GCM | AEAD | MODP3072 | yes | IPv4 |
| T05 | ESP | tunnel | AES-GCM | AEAD | MODP3072 | yes | IPv4 |
| T06 | ESP | transport | AES-CBC | HMAC-SHA256 | MODP2048 | yes | IPv4 |
| T07 | ESP | transport | AES-GCM | AEAD | MODP3072 | yes | IPv4 |
| T08 | AH | tunnel | none | HMAC-SHA256 | MODP2048 | no | IPv4 |
| T09 | AH | transport | none | HMAC-SHA256 | MODP2048 | no | IPv4 |
| T10 | ESP | tunnel | AES-CBC | HMAC-SHA384 | MODP2048 | yes | IPv6 |
| T11 | ESP | tunnel | AES-GCM | AEAD | MODP3072 | yes | IPv6 |
| T12 | ESP | tunnel | AES-CBC | HMAC-SHA256 | ECP256 | yes | IPv4 |
| T13 | ESP | tunnel | AES-CBC | HMAC-SHA384 | MODP3072 | yes | IPv4 |
| T14 | ESP | tunnel | AES-CBC | HMAC-SHA256 | MODP3072 | yes | IPv4 (rekey 60s) |
| T15 | ESP | tunnel | AES-CBC-192 | HMAC-SHA256 | MODP3072 | no | IPv6 protected |

T14 is the dedicated lifecycle scenario: `rekey_time=60s` so the capture window observes a real CREATE_CHILD_SA rekey. T15 is the corrected mixed-edge scenario: IKEv2 over IPv4 transport, IPv6-protected traffic selectors, AES-CBC-192, PFS disabled, no rekey.

## Operations

```bash
# Start (add -f testbed/compose/t15.yml when exercising T15)
docker compose -f testbed/compose/testbed.yml up -d --build

# Verify Phase 1 baseline / Phase 2 protocol coverage
powershell -File testbed/scripts/check-testbed.ps1
powershell -File testbed/scripts/check-phase2.ps1

# Generate dataset runs (captures + runtime evidence per run)
powershell -File testbed/scripts/run-scenario.ps1 -Scenario T04 -Traffic "icmp,web,voip-like,video-like" -Runs 3 -DatasetRoot dataset_v3_5_v2_final

# Tear down
docker compose -f testbed/compose/testbed.yml down -v
```

Ground-truth declarations live in `testbed/scenarios/T01.json` ... `T15.json`. They are used **only** for validation/testing; the security engine never reads scenario IDs during inference.
