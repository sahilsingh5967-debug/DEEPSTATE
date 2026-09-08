"""
Evaluator Module for ML Traffic Classifier.
Phase 5.3 — AI-Powered IPsec VPN Protocol Analyzer.

Provides standardized evaluation metrics calculation (Accuracy, Macro/Weighted Precision,
Recall, F1, Per-Class Breakdown, 8x8 Confusion Matrix) for multi-class classifiers.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Union
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)

TARGET_CLASSES = [
    "ICMP",
    "Web Browsing",
    "Email",
    "Chat",
    "Streaming",
    "File Transfer",
    "VoIP",
    "P2P"
]


def evaluate_classifier(
    model: Any,
    X: Union[np.ndarray, List[List[float]]],
    y_true: Union[np.ndarray, List[str]],
    class_names: List[str] = TARGET_CLASSES
) -> Dict[str, Any]:
    """
    Evaluates a trained classifier against ground-truth labels.
    Calculates accuracy, macro/weighted precision, recall, F1, per-class breakdown,
    and normalized confusion matrix.
    """
    y_true_arr = np.array(y_true)
    y_pred_arr = model.predict(X)

    acc = float(accuracy_score(y_true_arr, y_pred_arr))

    # Macro & Weighted metrics
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, labels=class_names, average="macro", zero_division=0
    )
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, labels=class_names, average="weighted", zero_division=0
    )

    # Per-class metrics
    per_class_p, per_class_r, per_class_f1, per_class_support = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, labels=class_names, average=None, zero_division=0
    )

    per_class_metrics: Dict[str, Dict[str, float]] = {}
    for idx, cname in enumerate(class_names):
        per_class_metrics[cname] = {
            "precision": round(float(per_class_p[idx]), 4),
            "recall": round(float(per_class_r[idx]), 4),
            "f1_score": round(float(per_class_f1[idx]), 4),
            "support": int(per_class_support[idx])
        }

    # Confusion matrix (8x8)
    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=class_names)
    cm_list = cm.tolist()

    return {
        "accuracy": round(acc, 4),
        "macro_precision": round(float(macro_p), 4),
        "macro_recall": round(float(macro_r), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_precision": round(float(weighted_p), 4),
        "weighted_recall": round(float(weighted_r), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm_list,
        "target_classes": class_names
    }


def save_evaluation_artifacts(
    eval_results: Dict[str, Any],
    output_dir: Union[str, Path]
) -> Dict[str, str]:
    """
    Saves evaluation_results.json and confusion_matrix.json into output_dir.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    eval_json_path = out_path / "evaluation_results.json"
    cm_json_path = out_path / "confusion_matrix.json"

    # Separate confusion matrix for explicit file
    cm_data = {
        "target_classes": eval_results.get("target_classes", TARGET_CLASSES),
        "confusion_matrix": eval_results.get("confusion_matrix", [])
    }

    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(eval_results, f, indent=2)

    with open(cm_json_path, "w", encoding="utf-8") as f:
        json.dump(cm_data, f, indent=2)

    return {
        "evaluation_results": str(eval_json_path),
        "confusion_matrix": str(cm_json_path)
    }


if __name__ == "__main__":
    print("Evaluator module initialized successfully.")
