import unittest
from security.evidence import choose, parse_features, parse_text
from security.schema import Evidence
from security.assess_ipsec import _rekey_events


class EvidenceTests(unittest.TestCase):
    def test_runtime_beats_metadata_and_conflict_is_retained(self):
        events = parse_text("site-to-site IKEv2 net: #1, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072", "swanctl")
        selected, conflicts = choose(events)
        self.assertEqual(selected["protocol"].value, "ESP")
        self.assertEqual(selected["encryption_algorithm"].value, "AES-CBC")

    def test_passive_text_does_not_create_crypto_fact(self):
        fields = {x.field for x in parse_text("IP 10.0.0.1 > 10.0.0.2: ESP(spi=0x1)", "pcap")}
        self.assertNotIn("encryption_algorithm", fields)
        self.assertIn("protocol", fields)

    def test_two_spis_are_not_rekey(self):
        fields = {x.field for x in parse_text("ESP(spi=0x1) ESP(spi=0x2)", "pcap")}
        self.assertNotIn("rekey_status", fields)

    def test_explicit_rekey_and_replay(self):
        events = parse_text("replay-window 32 CREATE_CHILD_SA", "xfrm")
        self.assertIn(("rekey_status", "rekey_observed"), {(x.field, x.value) for x in events})
        self.assertIn(("replay", "enabled"), {(x.field, x.value) for x in events})

    def test_equal_authority_conflict_becomes_unknown(self):
        selected, conflicts = choose([Evidence("replay", "disabled", "deterministically_derived", 1.0, "xfrm"), Evidence("replay", "enabled", "deterministically_derived", 1.0, "xfrm")])
        self.assertEqual(selected["replay"].evidence_type, "unknown")
        self.assertTrue(conflicts)

    def test_passive_rekey_claim_is_downgraded(self):
        events = parse_features({"rekey": {"rekey_observed": True, "rekey_status": "rekey_observed", "rekey_evidence": ["total_unique 3 >2"]}})
        self.assertIn(("rekey_status", "possible_rekey"), {(x.field, x.value) for x in events})

    def test_runtime_spi_comparison_is_authoritative(self):
        same = _rekey_events({"swanctl_before": "in cf63a732, out c35d0fc6,", "swanctl_after": "in cf63a732, out c35d0fc6,"})
        changed = _rekey_events({"swanctl_before": "in cf63a732, out c35d0fc6,", "swanctl_after": "in 11111111, out c35d0fc6,"})
        self.assertEqual(same[0].value, "no_rekey")
        self.assertEqual(changed[0].value, "rekey_observed")


if __name__ == "__main__": unittest.main()
