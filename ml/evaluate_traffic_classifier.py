#!/usr/bin/env python3
"""Print saved Phase 4 evaluation results."""
import argparse, json
from pathlib import Path
ap=argparse.ArgumentParser(); ap.add_argument("--results", default="ml/results"); a=ap.parse_args()
for name in ("cross_validation.json", "holdout_results.json", "ablation.json", "training_summary.json"):
    p=Path(a.results)/name
    print(f"\n## {name}\n{p.read_text(encoding='utf-8')}")
