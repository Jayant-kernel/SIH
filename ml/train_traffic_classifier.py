#!/usr/bin/env python3
"""Train and evaluate the Phase 4 encrypted traffic-type classifier."""
import argparse, csv, json, math, os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, precision_score,
                             recall_score, make_scorer)
from sklearn.inspection import permutation_importance
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

CLASSES = ["icmp", "web", "voip-like", "video-like"]
ENV_MARKERS = ("ipv4_count", "ipv6_count", "esp_packets", "ah_packets",
               "ike_packets", "unique_esp_spis", "rekey", "spi_count")

def number(value):
    if value in (None, "", "NA", "nan"): return np.nan
    if str(value).lower() in ("true", "false"): return float(str(value).lower() == "true")
    return float(value)

def load_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    target = "traffic_class"
    groups = "group_scenario_id"
    features = [k for k in rows[0] if k != target and not k.startswith("group_")]
    X = np.array([[number(r.get(k)) for k in features] for r in rows], dtype=float)
    y = np.array([r[target] for r in rows])
    g = np.array([r[groups] for r in rows])
    return rows, features, X, y, g

def pipe(model, scale=False):
    steps = [("imputer", SimpleImputer(strategy="median"))]
    if scale: steps.append(("scaler", StandardScaler()))
    steps.append(("model", model))
    return Pipeline(steps)

def models(seed):
    return {
        "logistic_regression": pipe(LogisticRegression(max_iter=3000, random_state=seed), True),
        "random_forest": pipe(RandomForestClassifier(n_estimators=400, random_state=seed, n_jobs=-1, class_weight=None)),
        "hist_gradient_boosting": pipe(HistGradientBoostingClassifier(max_iter=250, random_state=seed)),
        "knn": pipe(KNeighborsClassifier(n_neighbors=7), True),
        "svm": pipe(SVC(probability=True, random_state=seed), True),
    }

def scores(y, pred):
    p, r, f, _ = precision_recall_fscore_support(y, pred, labels=CLASSES, zero_division=0)
    return {"accuracy": float(accuracy_score(y, pred)),
            "macro_precision": float(precision_score(y, pred, labels=CLASSES, average="macro", zero_division=0)),
            "macro_recall": float(recall_score(y, pred, labels=CLASSES, average="macro", zero_division=0)),
            "macro_f1": float(f1_score(y, pred, labels=CLASSES, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y, pred, labels=CLASSES, average="weighted", zero_division=0)),
            "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i])} for i, c in enumerate(CLASSES)},
            "confusion_matrix": confusion_matrix(y, pred, labels=CLASSES).tolist()}

def grouped_cv(X, y, groups, seed, n_splits=5, only=None):
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    result = {}
    for name, model in models(seed).items():
        if only and name != only: continue
        folds = []
        oof_pred = np.empty(len(y), dtype=object)
        oof_prob = np.zeros((len(y), len(CLASSES)))
        for fold, (tr, te) in enumerate(splitter.split(X, y, groups)):
            model.fit(X[tr], y[tr])
            pred = model.predict(X[te])
            prob = model.predict_proba(X[te]) if hasattr(model, "predict_proba") else None
            oof_pred[te] = pred
            if prob is not None:
                for j, label in enumerate(model.classes_):
                    oof_prob[te, CLASSES.index(label)] = prob[:, j]
            s = scores(y[te], pred)
            s["fold"] = fold + 1
            s["train_scenarios"] = sorted(set(groups[tr]))
            s["test_scenarios"] = sorted(set(groups[te]))
            folds.append(s)
        summary = {}
        for metric in ("accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"):
            vals = [f[metric] for f in folds]
            summary[metric] = {"mean": float(np.mean(vals)), "std": float(np.std(vals, ddof=1))}
        result[name] = {"folds": folds, "summary": summary, "oof_pred": oof_pred.tolist(), "oof_prob": oof_prob.tolist()}
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="dataset_exports/traffic_features.csv")
    ap.add_argument("--out", default="ml")
    ap.add_argument("--seed", type=int, default=20260903)
    ap.add_argument("--dataset-version", default="3.5-v1")
    args = ap.parse_args()
    out = Path(args.out); results = out / "results"; models_dir = out / "models"
    results.mkdir(parents=True, exist_ok=True); models_dir.mkdir(parents=True, exist_ok=True)
    rows, features, X, y, groups = load_csv(args.csv)
    counts = {c: int(sum(y == c)) for c in CLASSES}
    if len(rows) != 180 or counts != {c: 45 for c in CLASSES}:
        raise SystemExit(f"unexpected frozen export: rows={len(rows)} counts={counts}")
    print("X columns:")
    for f in features: print(f"  {f}")
    print(f"rows={len(rows)} classes={counts} groups={len(set(groups))}")
    cv = grouped_cv(X, y, groups, args.seed)
    serial = {k: {kk: vv for kk, vv in v.items() if kk not in ("oof_pred", "oof_prob")} for k, v in cv.items()}
    (results / "cross_validation.json").write_text(json.dumps(serial, indent=2), encoding="utf-8")
    best = max(cv, key=lambda n: (cv[n]["summary"]["macro_f1"]["mean"], -cv[n]["summary"]["macro_f1"]["std"]))
    best_model = models(args.seed)[best]
    best_model.fit(X, y)
    joblib.dump(best_model, models_dir / "traffic_classifier.joblib")
    schema = {"schema_version": "phase4-v1", "target": "traffic_class", "classes": CLASSES, "features": features,
              "group_columns": [k for k in rows[0] if k.startswith("group_")], "dataset": args.dataset_version}
    (out / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
    # Hold out three complete unseen scenarios, preserving all four classes.
    holdout = sorted(set(groups))[-3:]
    tr = ~np.isin(groups, holdout); te = ~tr
    best_holdout = models(args.seed)[best]; best_holdout.fit(X[tr], y[tr]); hp = best_holdout.predict(X[te])
    holdout_result = {"model": best, "held_out_scenarios": holdout, "train_rows": int(tr.sum()), "test_rows": int(te.sum()), "metrics": scores(y[te], hp)}
    (results / "holdout_results.json").write_text(json.dumps(holdout_result, indent=2), encoding="utf-8")
    # Per-class and confusion artifacts for the selected model's out-of-fold predictions.
    pred = np.array(cv[best]["oof_pred"]); ss = scores(y, pred)
    with open(results / "per_class_metrics.csv", "w", newline="") as f:
        w=csv.writer(f); w.writerow(["class","precision","recall","f1"])
        for c in CLASSES: w.writerow([c, ss["per_class"][c]["precision"], ss["per_class"][c]["recall"], ss["per_class"][c]["f1"]])
    with open(results / "confusion_matrix.csv", "w", newline="") as f:
        w=csv.writer(f); w.writerow(["actual\\predicted"]+CLASSES); w.writerows([[CLASSES[i]]+row for i,row in enumerate(ss["confusion_matrix"])])
    # Feature importance from the final selected model when available.
    est = best_model.named_steps["model"]
    importance = np.zeros(len(features))
    if hasattr(est, "feature_importances_"): importance = est.feature_importances_
    elif hasattr(est, "coef_"): importance = np.mean(np.abs(est.coef_), axis=0)
    else:
        perm = permutation_importance(best_model, X, y, scoring="f1_macro", n_repeats=8, random_state=args.seed, n_jobs=-1)
        importance = perm.importances_mean
    with open(results / "feature_importance.csv", "w", newline="") as f:
        w=csv.writer(f); w.writerow(["feature","importance"])
        w.writerows(sorted(zip(features, importance), key=lambda x: x[1], reverse=True))
    # Behavioral ablation removes obvious environment/protocol/rekey markers.
    keep = [i for i,f in enumerate(features) if not any(marker in f for marker in ENV_MARKERS)]
    abl = grouped_cv(X[:, keep], y, groups, args.seed, only=best)
    ablation = {"excluded_features": [features[i] for i in range(len(features)) if i not in keep], "model": best,
                "summary": abl[best]["summary"]}
    (results / "ablation.json").write_text(json.dumps(ablation, indent=2), encoding="utf-8")
    # Threshold coverage/accuracy from grouped out-of-fold probabilities.
    probs=np.array(cv[best]["oof_prob"]); threshold_rows=[]
    for threshold in (0.50,0.60,0.70,0.80):
        conf=probs.max(axis=1); covered=conf>=threshold; labels=np.array(CLASSES)[probs.argmax(axis=1)]
        threshold_rows.append({"threshold":threshold,"coverage":float(covered.mean()),"covered_rows":int(covered.sum()),"accuracy_on_covered":float(accuracy_score(y[covered],labels[covered])) if covered.any() else None,"unknown_rows":int((~covered).sum())})
    (results / "threshold_analysis.csv").write_text("threshold,coverage,covered_rows,accuracy_on_covered,unknown_rows\n"+"\n".join(",".join(str(r[k]) for k in ("threshold","coverage","covered_rows","accuracy_on_covered","unknown_rows")) for r in threshold_rows)+"\n", encoding="utf-8")
    summary={"dataset_rows":len(rows),"class_counts":counts,"features":features,"group_column":"group_scenario_id","models_tested":list(cv),"selected_model":best,"cv_summary":cv[best]["summary"],"seed":args.seed,"model_path":"ml/models/traffic_classifier.joblib"}
    (results / "training_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    card=f"""# Encrypted Traffic-Type Classifier\n\n- Task: predict synthetic encrypted-flow traffic behavior class.\n- Dataset: version {args.dataset_version}, 180 rows, four balanced classes.\n- Evaluation: StratifiedGroupKFold grouped by `group_scenario_id`; scenarios never cross primary folds.\n- Selected model: `{best}`.\n- Grouped macro F1: {cv[best]['summary']['macro_f1']['mean']:.3f} +/- {cv[best]['summary']['macro_f1']['std']:.3f}.\n- Holdout scenarios: {', '.join(holdout)}.\n- Confidence threshold: configurable; threshold results are in `results/threshold_analysis.csv`.\n\nThis model predicts traffic behavior class from encrypted-flow metadata. It does not decrypt payload, infer AES key size, prove application identity, or identify WhatsApp/YouTube. Classes are synthetic traffic categories.\n\nKnown limitations: small dataset, synthetic traffic, scenario generalization uncertainty, and confidence probabilities are model outputs rather than certainty.\n"""
    (out / "model_card.md").write_text(card, encoding="utf-8")
    print(f"selected={best} grouped_macro_f1={cv[best]['summary']['macro_f1']}")

if __name__ == "__main__": main()
