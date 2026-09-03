import unittest
from security.rules import assess
from security.scoring import calculate


class ScoringTests(unittest.TestCase):
    def test_unknown_does_not_add_penalty(self):
        empty = calculate(assess({}, {}, {}), {}, {})
        self.assertEqual(empty["penalty_points"], 0)

    def test_score_is_transparent_and_bounded(self):
        facts = {"protocol":"ESP", "encryption_algorithm":"AES-CBC", "pfs":False}
        result = calculate(assess(facts, {}, {}), {}, {})
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        self.assertTrue(result["transparent"])


if __name__ == "__main__": unittest.main()
