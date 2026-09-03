# StrongSwan configs

- `gateway-a/swanctl.conf`: IKEv2 / ESP / tunnel / aes128gcm16 / modp3072 (IKE) + modp2048 (ESP PFS)
- `gateway-b/swanctl.conf`: mirror

Version: strongSwan 5.9.8 (Debian bookworm, swanctl/vici).
PSK is baseline only — no secrets committed beyond this testbed PSK.
