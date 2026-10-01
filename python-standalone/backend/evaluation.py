"""Self-evaluation over the labelled sample set.

IMPORTANT (academic honesty): the six built-in samples form a tiny sanity
check, not a benchmark. Accuracy/precision/recall/F1 here mean "does the DFA
prototype separate these labelled examples correctly". Real-world performance
cannot be claimed from six files.
"""

from __future__ import annotations

from typing import List

from .detector import analyze_log_text
from .main import SAMPLES, SAMPLE_DIRS  # circular-safe: imported lazily


def _iter_labelled_samples():
    for sid, (kind, fname, _, _) in SAMPLES.items():
        path = SAMPLE_DIRS[kind] / fname
        if path.exists():
            yield sid, fname, kind, path


def run_evaluation() -> dict:
    samples: List[dict] = []
    tp = fp = tn = fn = 0

    for sid, fname, kind, path in _iter_labelled_samples():
        text = path.read_text(encoding="utf-8")
        result = analyze_log_text(text, fname, source="sample")
        predicted = "anomalous" if result["summary"]["anomalies"] > 0 else "normal"
        correct = predicted == kind
        if kind == "anomalous" and predicted == "anomalous":
            tp += 1
        elif kind == "normal" and predicted == "anomalous":
            fp += 1
        elif kind == "normal" and predicted == "normal":
            tn += 1
        else:
            fn += 1
        samples.append({
            "filename": fname,
            "label": kind,
            "predicted": predicted,
            "correct": correct,
            "events": result["summary"]["total_events"],
            "anomalies": result["summary"]["anomalies"],
            "critical": result["summary"]["critical_anomalies"],
            "detection_ms": result["summary"]["detection_ms"],
        })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    total = len(samples) or 1
    return {
        "samples": samples,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "total_events": sum(s["events"] for s in samples),
        "total_anomalies": sum(s["anomalies"] for s in samples),
        "total_critical": sum(s["critical"] for s in samples),
        "avg_detection_ms": round(
            sum(s["detection_ms"] for s in samples) / total, 2),
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "disclaimer": (
            "Computed on 6 labelled sample files (2 normal, 4 anomalous). This "
            "is a sanity check of a rule/DFA-based academic prototype — not a "
            "real-world benchmark, and no general detection accuracy is claimed."
        ),
    }
