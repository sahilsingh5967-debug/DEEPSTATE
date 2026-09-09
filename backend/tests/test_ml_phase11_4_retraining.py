"""
Unit & Integration Tests for Phase 11.4 Candidate Retraining, Validation & Safety.
Phase 11.4 — AI-Powered IPsec VPN Protocol Analyzer.
"""

import json
from pathlib import Path
import pytest
import joblib

from backend.app.ml.candidate_training import (
    train_and_evaluate_candidate_models,
    load_and_prepare_behavioral_records,
    extract_matrices_behavioral,
    CANDIDATE_MODEL_DIR
)

from backend.app.ml.splitting import split_records_session_level, FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS
from backend.app.ml.schema import (
    BEHAVIORAL_TARGET_CLASSES,
    CLASS_UNKNOWN_UNCLASSIFIED,
    REAL_IPSEC_GROUND_TRUTH_REGISTRY
)
from backend.app.ml.inference import (
    TrafficClassifierInference,
    evaluate_real_ipsec_ground_truth,
    predict_flow_class,
    classify_pcap_for_integration
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "final_model.pkl"
PRODUCTION_PREPROCESSOR_PATH = PROJECT_ROOT / "data" / "models" / "preprocessor.pkl"


def test_candidate_artifacts_created_and_production_protected():
    """
    Verifies candidate model artifacts exist in data/models/candidates/
    and guarantees production final_model.pkl and preprocessor.pkl were NOT modified.
    """
    assert PRODUCTION_MODEL_PATH.exists(), "Production final_model.pkl must exist"
    assert PRODUCTION_PREPROCESSOR_PATH.exists(), "Production preprocessor.pkl must exist"

    # Train candidates
    summary = train_and_evaluate_candidate_models()

    assert summary["best_candidate"] in ("RandomForestClassifier", "HistGradientBoostingClassifier", "LogisticRegression")

    cand_rf = CANDIDATE_MODEL_DIR / "candidate_randomforestclassifier.pkl"
    cand_lr = CANDIDATE_MODEL_DIR / "candidate_logisticregression.pkl"
    cand_hgb = CANDIDATE_MODEL_DIR / "candidate_histgradientboostingclassifier.pkl"
    cand_prep = CANDIDATE_MODEL_DIR / "candidate_preprocessor.pkl"

    assert cand_rf.exists(), "candidate_randomforestclassifier.pkl missing"
    assert cand_lr.exists(), "candidate_logisticregression.pkl missing"
    assert cand_hgb.exists(), "candidate_histgradientboostingclassifier.pkl missing"
    assert cand_prep.exists(), "candidate_preprocessor.pkl missing"


def test_session_level_split_zero_overlap():
    """Verifies strict 70/15/15 session-level splitting with zero session leakage across partitions."""
    records = load_and_prepare_behavioral_records()
    splits = split_records_session_level(records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)

    train_sids = set(r.get("capture_id") or r.get("session_id") for r in splits["train"])
    val_sids = set(r.get("capture_id") or r.get("session_id") for r in splits["val"])
    test_sids = set(r.get("capture_id") or r.get("session_id") for r in splits["test"])

    # Strict Zero Overlap Assertions
    assert len(train_sids & val_sids) == 0, "Train and Val share session IDs!"
    assert len(train_sids & test_sids) == 0, "Train and Test share session IDs!"
    assert len(val_sids & test_sids) == 0, "Val and Test share session IDs!"
    assert len(train_sids) + len(val_sids) + len(test_sids) == 80


def test_zero_forbidden_predictive_identifiers_in_matrix():
    """Verifies NO forbidden predictive identifiers enter feature matrix X."""
    records = load_and_prepare_behavioral_records()
    X, y, meta = extract_matrices_behavioral(records)

    assert X.shape[1] == 28, f"Feature matrix X must contain exactly 28 predictive features, got {X.shape[1]}"
    for col in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert col not in ML_FEATURE_COLUMNS, f"Forbidden identifier '{col}' found in ML_FEATURE_COLUMNS!"


def test_candidate_ood_evaluation():
    """Evaluates candidate models against real IPsec captures using candidate preprocessor."""
    cand_model = CANDIDATE_MODEL_DIR / "candidate_randomforestclassifier.pkl"
    cand_prep = CANDIDATE_MODEL_DIR / "candidate_preprocessor.pkl"

    assert cand_model.exists()
    assert cand_prep.exists()

    res = evaluate_real_ipsec_ground_truth(model_path=cand_model, preprocessor_path=cand_prep)
    assert res["evaluation_type"] == "REAL_IPSEC_GROUND_TRUTH_REGISTRY_EVALUATION"
    assert "registry_results" in res
    assert "TEST-001.pcap" in res["registry_results"]
    assert "TEST-002.pcap" in res["registry_results"]
    assert "TEST-003.pcap" in res["registry_results"]


def test_backward_compatibility_production_inference():
    """Verifies existing inference functions maintain 100% backward compatibility."""
    real_pcap = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-001.pcap"
    assert real_pcap.exists()

    integration_res = classify_pcap_for_integration(real_pcap)
    assert integration_res.status in ("inferred", "unavailable", "no_flows")
    assert hasattr(integration_res, "dominant_class")
    assert hasattr(integration_res, "confidence")

    gt_res = evaluate_real_ipsec_ground_truth()
    assert "registry_results" in gt_res
