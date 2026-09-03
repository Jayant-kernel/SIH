import unittest
from security.rules import assess


class RuleTests(unittest.TestCase):
    def test_strong_and_pfs(self):
        facts = {"protocol":"ESP", "ike_version":2, "encryption_algorithm":"AES-GCM", "encryption_key_length":256, "integrity_algorithm":"AEAD-GCM", "dh_strength_bits":3072, "pfs":True, "mode":"tunnel", "replay":"enabled", "rekey_status":"no_rekey"}
        findings = assess(facts, {}, {})
        self.assertTrue(all(x.status != "fail" for x in findings if x.id != "IPSEC-META-001"))

    def test_ah_confidentiality(self):
        findings = assess({"protocol":"AH"}, {}, {})
        self.assertTrue(any(x.id == "IPSEC-ENC-002" and x.status == "fail" for x in findings))

    def test_unknown_is_not_failure(self):
        findings = assess({}, {}, {})
        self.assertTrue(any(x.status == "unknown" for x in findings))


if __name__ == "__main__": unittest.main()
