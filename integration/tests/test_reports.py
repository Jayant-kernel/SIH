import json, tempfile, unittest
from pathlib import Path
from integration.analyze import analyze
from reports.generate_report import executive, technical

ROOT=Path(__file__).resolve().parents[2]
RUN=next((ROOT/"dataset_v3_5_v2_full"/"T04").glob("*/metadata.json")).parent

class ReportTests(unittest.TestCase):
    def test_reports_contain_integrated_values(self):
        r=analyze(run_dir=RUN); e=executive(r); t=technical(r)
        self.assertIn(str(r["risk"]["score"]),e); self.assertIn("evidence",t.lower()); self.assertIn("phase6-v1",t)

if __name__=="__main__": unittest.main()
