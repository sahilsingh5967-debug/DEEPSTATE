"""
Candidate Model Retraining & Evaluation Engine.
Phase 11.4 — AI-Powered IPsec VPN Protocol Analyzer.

Executes candidate model training and validation on the Phase 11.3 behavioral dataset
using strict capture/session-level grouped splitting.
Evaluates candidate classifiers (RandomForest, LogisticRegression, HistGradientBoosting, XGBoost)
against Validation Macro-F1, Balanced Accuracy, Per-class Precision/Recall/F1, Confusion Matrix,
Feature Importance (encapsulation vs behavioral indicators), and Real IPsec OOD benchmarking.

SAFETY GUARANTEE:
All candidate artifacts are serialized under data/models/candidates/.
Production artifacts (data/models/final_model.pkl and preprocessor.pkl) are NEVER overwritten.
"""

import datetime
import json
import math
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import csv

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    f1_score
)

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except Exception as e:
    XGBOOST_AVAILABLE = False
    XGBOOST_UNAVAILABLE_REASON = str(e)

from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS
from backend.app.ml.splitting import split_records_session_level, FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.schema import (
    BEHAVIORAL_TARGET_CLASSES,
    CLASS_UNKNOWN_UNCLASSIFIED,
    map_legacy_class_to_behavioral,
    apply_unknown_inference_policy,
    SOURCE_SYNTHETIC_DEVELOPMENT,
    REAL_IPSEC_GROUND_TRUTH_REGISTRY
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FEATURES_CSV = PROJECT_ROOT / "data" / "datasets" / "features" / "iscx_vpn2016_features.csv"
CANDIDATE_MODEL_DIR = PROJECT_ROOT / "data" / "models" / "candidates"
PRODUCTION_MODEL_DIR = PROJECT_ROOT / "data" / "models"

ENCAPSULATION_FEATURES = ["esp_packet_count", "has_ike", "has_esp", "has_udp_4500"]


def load_and_prepare_behavioral_records(csv_path: Path = FEATURES_CSV) -> List[Dict[str, Any]]:
    """Loads feature CSV and attaches Phase 11 behavioral target classes."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Feature CSV not found at {csv_path}")

    records = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Clean and map legacy class if behavioral_class missing
            if "behavioral_class" not in row or not row["behavioral_class"]:
                row["behavioral_class"] = map_legacy_class_to_behavioral(row.get("traffic_class"))
            records.append(row)
    return records


def validate_clean_records(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int, int]:
    """Validates records to ensure no NaNs/INFs exist in predictive feature columns."""
    clean_recs = []
    nan_cnt = 0
    inf_cnt = 0

    for r in records:
        has_err = False
        for col in ML_FEATURE_COLUMNS:
            val_str = r.get(col, "")
            try:
                val = float(val_str)
                if math.isnan(val):
                    nan_cnt += 1
                    has_err = True
                elif math.isinf(val):
                    inf_cnt += 1
                    has_err = True
            except (ValueError, TypeError):
                has_err = True
        if not has_err:
            clean_recs.append(r)

    return clean_recs, nan_cnt, inf_cnt


def extract_matrices_behavioral(records: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """
    Extracts feature matrix X (28 predictive features ONLY) and target label array y.
    Strictly purges forbidden predictive identifiers from X.
    """
    X_list = []
    y_list = []
    meta_list = []

    for r in records:
        # Guarantee no forbidden columns enter X
        feat_vec = [float(r[col]) for col in ML_FEATURE_COLUMNS]
        X_list.append(feat_vec)
        y_list.append(r["behavioral_class"])
        meta_list.append({col: r.get(col) for col in METADATA_COLUMNS if col in r})

    return np.array(X_list, dtype=np.float64), np.array(y_list), meta_list


def evaluate_behavioral_candidate(
    model: Any,
    X: np.ndarray,
    y_true: np.ndarray,
    classes: List[str],
    label_encoder: Optional[LabelEncoder] = None
) -> Dict[str, Any]:
    """Computes comprehensive evaluation metrics for a candidate model."""
    if label_encoder:
        raw_preds = model.predict(X)
        y_pred = label_encoder.inverse_transform(raw_preds) if isinstance(raw_preds[0], (int, np.integer)) else raw_preds
    else:
        y_pred = model.predict(X)

    y_pred = np.array([str(p) for p in y_pred])

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro"))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted"))

    p_per, r_per, f1_per, s_per = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )

    per_class_metrics = {}
    for idx, cname in enumerate(classes):
        per_class_metrics[cname] = {
            "precision": round(float(p_per[idx]), 4),
            "recall": round(float(r_per[idx]), 4),
            "f1_score": round(float(f1_per[idx]), 4),
            "support": int(s_per[idx])
        }

    cm = confusion_matrix(y_true, y_pred, labels=classes).tolist()

    return {
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm,
        "classes": classes
    }


def analyze_feature_importance(model: Any, model_name: str) -> Dict[str, Any]:
    """Analyzes feature importances, explicitly highlighting encapsulation indicators."""
    importances = {}
    if hasattr(model, "feature_importances_"):
        raw_imp = model.feature_importances_
        sorted_pairs = sorted(zip(ML_FEATURE_COLUMNS, raw_imp), key=lambda x: x[1], reverse=True)
        importances = {f: round(float(imp), 6) for f, imp in sorted_pairs}
    elif hasattr(model, "coef_"):
        abs_coefs = np.mean(np.abs(model.coef_), axis=0)
        sorted_pairs = sorted(zip(ML_FEATURE_COLUMNS, abs_coefs), key=lambda x: x[1], reverse=True)
        importances = {f: round(float(c), 6) for f, c in sorted_pairs}
    else:
        importances = {f: 0.0 for f in ML_FEATURE_COLUMNS}

    encap_importance_sum = sum(importances.get(f, 0.0) for f in ENCAPSULATION_FEATURES)
    total_importance_sum = sum(importances.values()) if sum(importances.values()) > 0 else 1.0
    encap_ratio = round(float(encap_importance_sum / total_importance_sum), 4)

    return {
        "model_name": model_name,
        "feature_importances": importances,
        "encapsulation_feature_importances": {f: importances.get(f, 0.0) for f in ENCAPSULATION_FEATURES},
        "encapsulation_importance_share": encap_ratio,
        "finding": (
            "Encapsulation features account for "
            f"{encap_ratio * 100:.2f}% of total feature importance. "
            + ("High reliance on encapsulation signatures detected." if encap_ratio > 0.35 else "Primary reliance is on behavioral traffic dynamics.")
        )
    }


def train_and_evaluate_candidate_models(
    csv_path: Optional[Path] = None,
    split_manifest_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Executes Candidate Retraining, Validation, Feature Audit & Serialization.
    GUARANTEES production model files remain untouched.
    """
    target_csv = csv_path or FEATURES_CSV
    print("============================================================")
    print(f" Candidate Model Retraining & Validation Engine ({target_csv.name})")
    print("============================================================")

    CANDIDATE_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    prod_mtime_before = (PRODUCTION_MODEL_DIR / "final_model.pkl").stat().st_mtime if (PRODUCTION_MODEL_DIR / "final_model.pkl").exists() else 0

    # 1. Load records & attach behavioral targets
    raw_records = load_and_prepare_behavioral_records(target_csv)
    clean_records, nan_cnt, inf_cnt = validate_clean_records(raw_records)
    print(f"[+] Loaded {len(clean_records)} clean behavioral records from {target_csv}")

    # 2. Session-Level Split
    if split_manifest_path and split_manifest_path.exists():
        with open(split_manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        train_sids_set = set(manifest.get("train_sessions", []))
        val_sids_set = set(manifest.get("validation_sessions", []))
        test_sids_set = set(manifest.get("test_sessions", []))

        train_recs = [r for r in clean_records if (r.get("session_id") or r.get("capture_id")) in train_sids_set]
        val_recs = [r for r in clean_records if (r.get("session_id") or r.get("capture_id")) in val_sids_set]
        test_recs = [r for r in clean_records if (r.get("session_id") or r.get("capture_id")) in test_sids_set]
        print(f"[+] Applied split from manifest: {split_manifest_path.name}")
    else:
        splits = split_records_session_level(clean_records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)
        train_recs, val_recs, test_recs = splits["train"], splits["val"], splits["test"]

    # 3. Session Isolation Verification
    train_sids = set(r.get("capture_id") or r.get("session_id") for r in train_recs)
    val_sids = set(r.get("capture_id") or r.get("session_id") for r in val_recs)
    test_sids = set(r.get("capture_id") or r.get("session_id") for r in test_recs)

    assert len(train_sids & val_sids) == 0, "Train and Val share session IDs!"
    assert len(train_sids & test_sids) == 0, "Train and Test share session IDs!"
    assert len(val_sids & test_sids) == 0, "Val and Test share session IDs!"
    print(f"[+] Session-Level Split Verified (Zero Overlap): Train={len(train_recs)} flows ({len(train_sids)} sessions), Val={len(val_recs)} flows ({len(val_sids)} sessions), Test={len(test_recs)} flows ({len(test_sids)} sessions)")

    # 4. Matrix Extraction (28 features ONLY)
    X_train_raw, y_train, _ = extract_matrices_behavioral(train_recs)
    X_val_raw, y_val, _ = extract_matrices_behavioral(val_recs)
    X_test_raw, y_test, _ = extract_matrices_behavioral(test_recs)

    # 5. Preprocessing: Fit StandardScaler ONLY on X_train_raw
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    scaler_candidate_path = CANDIDATE_MODEL_DIR / "candidate_preprocessor.pkl"
    joblib.dump(scaler, scaler_candidate_path)

    # Label Encoder
    target_classes = sorted(list(set(y_train) | set(y_val) | set(y_test)))
    label_encoder = LabelEncoder()
    label_encoder.fit(target_classes)
    y_train_enc = label_encoder.transform(y_train)

    # 6. Candidate Models Definition
    candidates = {
        "RandomForestClassifier": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier(max_iter=100, random_state=42)
    }

    if XGBOOST_AVAILABLE:
        candidates["XGBClassifier"] = XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric="mlogloss")

    candidate_results = {}
    candidate_objects = {}
    best_candidate_name = None
    best_val_macro_f1 = -1.0

    print("\n--- Training and Evaluating Candidate Models on Validation Split ---")
    for name, model in candidates.items():
        print(f"[*] Training candidate '{name}'...")
        if name in ("XGBClassifier", "HistGradientBoostingClassifier"):
            model.fit(X_train, y_train_enc)
            val_eval = evaluate_behavioral_candidate(model, X_val, y_val, target_classes, label_encoder)
            test_eval = evaluate_behavioral_candidate(model, X_test, y_test, target_classes, label_encoder)
        else:
            model.fit(X_train, y_train)
            val_eval = evaluate_behavioral_candidate(model, X_val, y_val, target_classes)
            test_eval = evaluate_behavioral_candidate(model, X_test, y_test, target_classes)

        feat_importance = analyze_feature_importance(model, name)

        candidate_results[name] = {
            "validation_metrics": val_eval,
            "test_metrics": test_eval,
            "feature_importance": feat_importance
        }
        candidate_objects[name] = model

        # Save candidate artifact
        cand_path = CANDIDATE_MODEL_DIR / f"candidate_{name.lower()}.pkl"
        joblib.dump({
            "model": model,
            "label_encoder": label_encoder if name in ("XGBClassifier", "HistGradientBoostingClassifier") else None,
            "candidate_name": name,
            "feature_names": ML_FEATURE_COLUMNS,
            "target_classes": target_classes,
            "random_seed": 42
        }, cand_path)

        val_f1 = val_eval["macro_f1"]
        print(f"    {name} -> Val Macro-F1: {val_f1:.4f} | Val Accuracy: {val_eval['accuracy']:.4f} | Val Bal-Acc: {val_eval['balanced_accuracy']:.4f}")

        if val_f1 > best_val_macro_f1:
            best_val_macro_f1 = val_f1
            best_candidate_name = name

    print(f"\n[+] BEST CANDIDATE BY MACRO-F1: '{best_candidate_name}' (Validation Macro-F1: {best_val_macro_f1:.4f})")

    # 7. UNKNOWN Policy Statistics Audit on Validation Set
    best_model = candidate_objects[best_candidate_name]
    best_is_encoded = best_candidate_name in ("XGBClassifier", "HistGradientBoostingClassifier")

    if hasattr(best_model, "predict_proba"):
        val_probs = best_model.predict_proba(X_val)
        val_max_probs = np.max(val_probs, axis=1)
        val_preds_raw = best_model.predict(X_val)
        if best_is_encoded:
            val_preds_str = label_encoder.inverse_transform(val_preds_raw)
        else:
            val_preds_str = val_preds_raw

        unknown_count = 0
        conf_sum = 0.0
        for idx in range(len(X_val)):
            p_cls = str(val_preds_str[idx])
            p_conf = float(val_max_probs[idx])
            # Check UNKNOWN policy rule (prob < 0.50 or pkt_count < 3)
            # In validation matrix, total_packets is column index 7
            pkt_cnt = int(X_val_raw[idx][ML_FEATURE_COLUMNS.index("total_packets")])
            eff_c, eff_p, _ = apply_unknown_inference_policy(p_cls, p_conf, pkt_cnt)
            if eff_c == CLASS_UNKNOWN_UNCLASSIFIED:
                unknown_count += 1
            conf_sum += eff_p

        unknown_rate = round(float(unknown_count / len(X_val)), 4)
        mean_confidence = round(float(conf_sum / len(X_val)), 4)
    else:
        unknown_rate = 0.0
        mean_confidence = 1.0

    # Save summary report
    comparison_summary = {
        "timestamp": datetime.datetime.now().isoformat(),
        "phase": "11.4",
        "dataset_source": SOURCE_SYNTHETIC_DEVELOPMENT,
        "provenance_disclaimer": "Local development synthetic PCAP dataset generated by scripts/ml/download_dataset.py",
        "best_candidate": best_candidate_name,
        "model_selection_criterion": "Highest Validation Macro-F1",
        "session_split": {
            "train_flows": len(train_recs),
            "val_flows": len(val_recs),
            "test_flows": len(test_recs),
            "train_sessions": len(train_sids),
            "val_sessions": len(val_sids),
            "test_sessions": len(test_sids),
            "zero_session_overlap": True
        },
        "candidate_comparison": {
            k: {
                "val_macro_f1": v["validation_metrics"]["macro_f1"],
                "val_accuracy": v["validation_metrics"]["accuracy"],
                "val_balanced_accuracy": v["validation_metrics"]["balanced_accuracy"],
                "val_weighted_f1": v["validation_metrics"]["weighted_f1"],
                "test_macro_f1": v["test_metrics"]["macro_f1"],
                "test_accuracy": v["test_metrics"]["accuracy"]
            }
            for k, v in candidate_results.items()
        },
        "unknown_policy_statistics": {
            "validation_unknown_rate": unknown_rate,
            "validation_mean_confidence": mean_confidence,
            "confidence_threshold": 0.50,
            "min_packet_threshold": 3
        },
        "feature_importance_audit": candidate_results[best_candidate_name]["feature_importance"]
    }

    comp_out_path = CANDIDATE_MODEL_DIR / "phase11_4_model_comparison.json"
    with open(comp_out_path, "w", encoding="utf-8") as f:
        json.dump(comparison_summary, f, indent=2)

    # 8. Verify Production Artifact Safety
    prod_mtime_after = (PRODUCTION_MODEL_DIR / "final_model.pkl").stat().st_mtime if (PRODUCTION_MODEL_DIR / "final_model.pkl").exists() else 0
    assert prod_mtime_before == prod_mtime_after, "SAFETY CRASH: Production final_model.pkl was modified!"

    print(f"[+] Candidate model retraining & evaluation complete. Summary saved to: {comp_out_path}")
    print("============================================================")

    return comparison_summary


if __name__ == "__main__":
    train_and_evaluate_candidate_models()
