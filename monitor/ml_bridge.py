#!/usr/bin/env python3
"""Rolling-window ML bridge. Reuses the trained Phase 4 model with zero
drift: window raw packets -> temp pcap -> analyzer/pcap_features.py ->
ml_v2/predict_traffic.py. Never retrains. Every abstention carries a
machine-readable reason AND a human explanation.
"""
import json
import os
import subprocess
import sys
import tempfile

from .pcapio import PcapWriter

WINDOW_MIN_PACKETS = 10
DEFAULT_THRESHOLD = 0.60

REASON_TEXT = {
    "ok": "Model produced a prediction above the confidence threshold.",
    "insufficient_packets": "Too few packets in the rolling window for a valid prediction.",
    "extraction_failed": "Feature extraction failed for this window.",
    "schema_mismatch": "Window features do not match the model feature schema.",
    "model_unavailable": "Prediction CLI or model artifact is unavailable.",
    "below_threshold": "Model confidence is below the acceptance threshold.",
    "prediction_error": "Prediction subprocess failed.",
}


def _get_nested(d, dotted):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def window_to_features(packets, linktype, analyzer_path, schema):
    """packets: [(ts, raw)]. Returns (features|None, reason, detail)."""
    if len(packets) < WINDOW_MIN_PACKETS:
        return (None, "insufficient_packets",
                "window has %d packets, need >= %d" % (len(packets), WINDOW_MIN_PACKETS))
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    out = tmp.name + ".features.json"
    try:
        with PcapWriter(tmp.name, linktype) as w:
            for ts, raw in packets:
                w.write(ts, raw)
        p = subprocess.run([sys.executable, str(analyzer_path), tmp.name,
                            "--out", out], capture_output=True, text=True, timeout=120)
        if p.returncode != 0 or not os.path.exists(out):
            return (None, "extraction_failed", (p.stderr or "")[-300:])
        with open(out, encoding="utf-8") as fh:
            features = json.load(fh)
        missing = [k for k in schema.get("features", [])
                   if not _get_nested(features, k)[1]]
        if missing:
            return (None, "schema_mismatch", "missing keys: %s" % missing[:5])
        return (features, "ok", "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return (None, "extraction_failed", str(exc)[:300])
    finally:
        for f in (tmp.name, out):
            try:
                os.unlink(f)
            except OSError:
                pass


def predict_traffic(features, workdir, cli_path, threshold=DEFAULT_THRESHOLD):
    """features: dict. Returns (result|None, reason, detail)."""
    if not os.path.exists(str(cli_path)):
        return (None, "model_unavailable", "missing %s" % cli_path)
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w",
                                      encoding="utf-8")
    try:
        json.dump(features, tmp)
        tmp.close()
        p = subprocess.run([sys.executable, str(cli_path), "--features", tmp.name,
                            "--threshold", str(threshold)],
                           capture_output=True, text=True, timeout=120, cwd=str(workdir))
        if p.returncode != 0:
            return (None, "prediction_error", (p.stderr or p.stdout or "")[-300:])
        try:
            doc = json.loads(p.stdout)
        except ValueError as exc:
            return (None, "prediction_error", "bad CLI JSON: %s" % exc)
        tp = doc.get("traffic_prediction", {})
        if tp.get("label") == "Unknown" or tp.get("label") == "unknown":
            return (doc, "below_threshold",
                    "confidence %.3f below threshold %.2f"
                    % (tp.get("confidence", 0.0), threshold))
        return (doc, "ok", "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (None, "model_unavailable", str(exc)[:300])
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def analyze_window(packets, linktype, analyzer_path, cli_path, schema, workdir,
                   threshold=DEFAULT_THRESHOLD):
    """Full window pipeline. Always returns a displayable dict."""
    window_seconds = (max(t for t, _ in packets) - min(t for t, _ in packets)) \
        if len(packets) > 1 else 0.0
    base = {"window_packets": len(packets), "window_seconds": round(window_seconds, 3),
            "label": "Unknown", "confidence": 0.0, "probabilities": {},
            "reason": "insufficient_packets",
            "explanation": REASON_TEXT["insufficient_packets"]}
    features, reason, detail = window_to_features(packets, linktype, analyzer_path, schema)
    if features is None:
        base.update(reason=reason, explanation="%s %s" % (REASON_TEXT[reason], detail))
        return base
    doc, reason, detail = predict_traffic(features, workdir, cli_path, threshold)
    if doc is None:
        base.update(reason=reason, explanation="%s %s" % (REASON_TEXT[reason], detail))
        return base
    tp = doc.get("traffic_prediction", {})
    out = {"window_packets": len(packets), "window_seconds": round(window_seconds, 3),
           "label": tp.get("label", "Unknown"),
           "confidence": float(tp.get("confidence", 0.0)),
           "probabilities": tp.get("probabilities", {}),
           "model_version": doc.get("model_version", "unknown"),
           "reason": reason,
           "explanation": "%s %s" % (REASON_TEXT.get(reason, reason), detail)}
    return out
