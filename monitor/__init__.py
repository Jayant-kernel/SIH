"""Continuous passive IPsec monitoring.

Live/async counterpart to the offline run-based pipeline. Parses packets
(IKE + ESP/AH) into timestamped events, correlates them into persistent
VPN profiles, and reuses the Phase 4 classifier and Phase 5 security
engine. Never decrypts payloads; unknown stays unknown.
"""
__version__ = "monitor-v1"
