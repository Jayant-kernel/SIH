import json, unittest
from pathlib import Path
from integration.analyze import analyze

ROOT=Path(__file__).resolve().parents[2]
RUN=next((ROOT/"dataset_v3_5_v2_full"/"T15").glob("*/metadata.json")).parent

class PipelineTests(unittest.TestCase):
    def test_full_run(self):
        r=analyze(run_dir=RUN)
        self.assertEqual(r["analysis_version"],"phase6-v1")
        self.assertEqual(r["security_assessment"]["assessment_version"],"phase5-v1")
        self.assertIn("risk",r)
    def test_passive_only(self):
        r=analyze(pcap=RUN/"capture.pcap")
        self.assertEqual(r["input"]["type"],"pcap")
        self.assertTrue(any(v.get("evidence_type")=="unknown" for v in r["protocol_analysis"]["fields"].values()))

if __name__=="__main__": unittest.main()
