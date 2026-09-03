import json, shutil, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integration.analyze import analyze
from reports.generate_report import generate

ROOT=Path(__file__).resolve().parents[1]
IR=ROOT/"integration"/"results"; RR=ROOT/"reports"/"results"

def first(sid): return next((ROOT/"dataset_v3_5_v2_full"/sid).glob("*/metadata.json")).parent

def main():
    IR.mkdir(parents=True,exist_ok=True); RR.mkdir(parents=True,exist_ok=True)
    cases={sid: analyze(run_dir=first(sid)) for sid in ("T03","T04","T07","T08","T14","T15")}
    for sid,result in cases.items(): (IR/f"{sid.lower()}_result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    t15=first("T15"); passive=analyze(pcap=t15/"capture.pcap"); full=cases["T04"]
    (IR/"passive_only_result.json").write_text(json.dumps(passive,indent=2),encoding="utf-8")
    (IR/"full_evidence_result.json").write_text(json.dumps(full,indent=2),encoding="utf-8")
    generate(passive,RR,"passive"); generate(full,RR,"full")
    shutil.copyfile(RR/"executive_full.html",RR/"sample_executive.html"); shutil.copyfile(RR/"technical_full.html",RR/"sample_technical.html")
    validation={"analysis_version":"phase6-v1","scenarios":{},"passive_only":{},"full_evidence":{},"reports":{}}
    for sid,result in cases.items(): validation["scenarios"][sid]={"security_version":result["components"]["security_version"],"risk":result["risk"],"traffic":result["traffic_analysis"].get("traffic_prediction",{})}
    validation["passive_only"]={"unknown_fields":passive["evidence_summary"]["unknown_fields"],"completeness":passive["risk"].get("evidence_completeness")}
    validation["full_evidence"]={"unknown_fields":full["evidence_summary"]["unknown_fields"],"completeness":full["risk"].get("evidence_completeness")}
    validation["reports"]={"executive":(RR/"sample_executive.html").exists(),"technical":(RR/"sample_technical.html").exists()}
    (IR/"phase6_validation.json").write_text(json.dumps(validation,indent=2),encoding="utf-8")

if __name__=="__main__": main()
