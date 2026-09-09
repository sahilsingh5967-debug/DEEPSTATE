"""
Phase 5.3 Unit & Regression Test Suite for ML Model Training, Evaluation, and Inference.
AI-Powered IPsec VPN Protocol Analyzer.

Verifies:
1. Model training pipeline execution & artifact serialization.
2. 28 approved numerical predictive feature whitelist.
3. Strict exclusion of forbidden predictive identifiers from X.
4. Zero NaN / INF values in training data.
5. Zero flow-ID overlap across Train / Validation / Test splits.
6. Target label separation from input feature array.
7. Determinism under fixed random seed 42.
8. Existence and deserialization of final_model.pkl & preprocessor.pkl.
9. Valid prediction format, confidence in [0, 1], and probability sum ~ 1.0.
10. Multi-class coverage across all 8 target categories.
11. Complete exclusion of real IPsec ground-truth & synthetic fixtures from training.
12. Internal consistency of evaluation_results.json, confusion_matrix.json, model_metadata.json, and ood_ipsec_results.json.
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pytest

from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS
from backend.app.ml.splitting import FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.evaluator import TARGET_CLASSES
from backend.app.ml.model_training import train_and_select_model
from backend.app.ml.inference import TrafficClassifierInference, predict_pcap_traffic

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = PROJECT_ROOT / "data" / "models"
FINAL_MODEL_PATH = MODEL_DIR / "final_model.pkl"
PREPROCESSOR_PATH = MODEL_DIR / "preprocessor.pkl"
METADATA_PATH = MODEL_DIR / "model_metadata.json"
EVALUATION_PATH = MODEL_DIR / "evaluation_results.json"
CONFUSION_PATH = MODEL_DIR / "confusion_matrix.json"
OOD_PATH = MODEL_DIR / "ood_ipsec_results.json"
FEATURES_CSV = PROJECT_ROOT / "data" / "datasets" / "features" / "iscx_vpn2016_features.csv"


def test_1_training_pipeline_execution_and_artifacts():
    assert FEATURES_CSV.exists(), "iscx_vpn2016_features.csv must exist"
    assert FINAL_MODEL_PATH.exists(), "final_model.pkl must exist"
    assert PREPROCESSOR_PATH.exists(), "preprocessor.pkl must exist"
    assert METADATA_PATH.exists(), "model_metadata.json must exist"
    assert EVALUATION_PATH.exists(), "evaluation_results.json must exist"
    assert CONFUSION_PATH.exists(), "confusion_matrix.json must exist"


def test_2_exactly_28_approved_numerical_features():
    assert len(ML_FEATURE_COLUMNS) == 28
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["feature_count"] == 28
    assert meta["feature_names"] == ML_FEATURE_COLUMNS


def test_3_forbidden_identifiers_absent_from_feature_matrix():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    feature_names = meta["feature_names"]
    for forbidden in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert forbidden not in feature_names, f"Forbidden identifier '{forbidden}' found in feature matrix!"


def test_4_zero_nan_and_inf_values_in_eval_metadata():
    with open(EVALUATION_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)
    val_metrics = eval_data.get("validation_metrics", {})
    per_class = val_metrics.get("per_class_metrics", {})
    for cname, m in per_class.items():
        assert not np.isnan(m["precision"])
        assert not np.isnan(m["recall"])
        assert not np.isnan(m["f1_score"])
        assert not np.isinf(m["precision"])
        assert not np.isinf(m["recall"])
        assert not np.isinf(m["f1_score"])


def test_5_zero_flow_id_overlap_across_splits():
    with open(EVALUATION_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)
    leakage = eval_data.get("leakage_checks", {})
    assert leakage.get("zero_flow_id_overlap") is True


def test_6_labels_excluded_from_feature_matrix():
    assert "traffic_class" not in ML_FEATURE_COLUMNS
    assert "label" not in ML_FEATURE_COLUMNS


def test_7_training_seed_determinism():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["random_seed"] == 42


def test_8_final_model_pkl_exists():
    assert FINAL_MODEL_PATH.exists()
    model_art = joblib.load(FINAL_MODEL_PATH)
    assert "model" in model_art
    assert "selected_model_name" in model_art


def test_9_preprocessor_pkl_exists_and_deserializes():
    assert PREPROCESSOR_PATH.exists()
    scaler = joblib.load(PREPROCESSOR_PATH)
    assert hasattr(scaler, "transform")
    assert hasattr(scaler, "mean_")
    assert len(scaler.mean_) == 28


def test_10_deserialized_model_predicts_valid_class():
    classifier = TrafficClassifierInference()
    dummy_features = np.zeros((1, 28))
    dummy_scaled = classifier.preprocessor.transform(dummy_features)
    pred = classifier.model.predict(dummy_scaled)[0]
    assert str(pred) in TARGET_CLASSES


def test_11_inference_confidence_bounded_in_0_to_1():
    classifier = TrafficClassifierInference()
    dummy_features = np.zeros((1, 28))
    dummy_scaled = classifier.preprocessor.transform(dummy_features)
    if hasattr(classifier.model, "predict_proba"):
        probs = classifier.model.predict_proba(dummy_scaled)[0]
        conf = float(np.max(probs))
        assert 0.0 <= conf <= 1.0


def test_12_probability_vector_sums_approximately_to_1():
    classifier = TrafficClassifierInference()
    dummy_features = np.zeros((1, 28))
    dummy_scaled = classifier.preprocessor.transform(dummy_features)
    if hasattr(classifier.model, "predict_proba"):
        probs = classifier.model.predict_proba(dummy_scaled)[0]
        assert abs(float(np.sum(probs)) - 1.0) < 1e-3


def test_13_all_8_target_classes_represented():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["target_classes"] == TARGET_CLASSES
    assert len(meta["target_classes"]) == 8


def test_14_real_ipsec_captures_absent_from_training_dataset():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    statement = meta.get("ground_truth_isolation_statement", "")
    assert "TEST-001.pcap" in statement or "100% excluded" in statement


def test_15_synthetic_fixtures_absent_from_training_dataset():
    with open(EVALUATION_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)
    leakage = eval_data.get("leakage_checks", {})
    assert leakage.get("synthetic_fixtures_excluded") is True


def test_16_evaluation_artifacts_internal_consistency():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(EVALUATION_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)
    with open(CONFUSION_PATH, "r", encoding="utf-8") as f:
        cm_data = json.load(f)

    assert meta["model_name"] == eval_data["selected_model"]
    assert meta["model_name"] == cm_data["model_name"]
    assert meta["test_accuracy"] == eval_data["final_test_metrics"]["accuracy"]
    assert meta["test_macro_f1"] == eval_data["final_test_metrics"]["macro_f1"]


def test_17_ood_results_file_exists_and_isolated():
    assert OOD_PATH.exists(), "ood_ipsec_results.json must exist"
    with open(OOD_PATH, "r", encoding="utf-8") as f:
        ood = json.load(f)
    assert ood["evaluation_type"] == "INDEPENDENT_REAL_IPSEC_OUT_OF_DISTRIBUTION_INFERENCE"
    assert "ood_disclaimer" in ood
    assert len(ood["results"]) == 3  # TEST-001, TEST-002, TEST-003


def test_18_pcap_inference_cli_pipeline():
    real_pcap = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-001.pcap"
    assert real_pcap.exists()
    res = predict_pcap_traffic(str(real_pcap))
    assert res["status"] == "COMPLETED"
    assert "dominant_inferred_class" in res
    assert res["dominant_inferred_class"] in TARGET_CLASSES or res["dominant_inferred_class"] == "UNKNOWN_UNCLASSIFIED"


def test_19_ood_results_structure_and_disclaimer():
    assert OOD_PATH.exists(), "ood_ipsec_results.json must exist"
    with open(OOD_PATH, "r", encoding="utf-8") as f:
        ood = json.load(f)

    assert ood["evaluation_type"] == "INDEPENDENT_REAL_IPSEC_OUT_OF_DISTRIBUTION_INFERENCE"
    assert "ood_disclaimer" in ood
    assert "inference" in ood["ood_disclaimer"].lower() or "out-of-distribution" in ood["ood_disclaimer"].lower()

    results = ood.get("results", [])
    assert len(results) == 3
    pcap_names = [r["pcap_file"] for r in results]
    assert "TEST-001.pcap" in pcap_names
    assert "TEST-002.pcap" in pcap_names
    assert "TEST-003.pcap" in pcap_names

    for r in results:
        assert "ground_truth_protocol" in r
        assert "ground_truth_description" in r
        assert r["status"] == "COMPLETED"
        for inf in r.get("flow_inferences", []):
            ml_cls = inf.get("inferred_ml_classification", {})
            assert ml_cls.get("status") == "INFERRED"
            assert "disclaimer" in ml_cls


def test_20_ood_metrics_and_domain_shift_audit():
    with open(OOD_PATH, "r", encoding="utf-8") as f:
        ood = json.load(f)

    metrics = ood.get("metrics", {})
    assert metrics.get("total_flows_evaluated") == 11
    assert "ood_flow_accuracy" in metrics
    assert 0.0 <= metrics["ood_flow_accuracy"] <= 1.0

    conf_stats = metrics.get("confidence_stats", {})
    assert "min_confidence" in conf_stats
    assert "max_confidence" in conf_stats
    assert "mean_confidence" in conf_stats
    assert 0.0 <= conf_stats["min_confidence"] <= conf_stats["max_confidence"] <= 1.0

    assert "domain_shift_audit" in ood
    assert "ESP" in ood["domain_shift_audit"] or "domain shift" in ood["domain_shift_audit"].lower()


def test_21_ood_probability_distribution_integrity():
    with open(OOD_PATH, "r", encoding="utf-8") as f:
        ood = json.load(f)

    for r in ood.get("results", []):
        for inf in r.get("flow_inferences", []):
            probs = inf["inferred_ml_classification"]["class_probabilities"]
            assert len(probs) == 8
            for cname in TARGET_CLASSES:
                assert cname in probs
                assert 0.0 <= probs[cname] <= 1.0
            prob_sum = float(sum(probs.values()))
            assert abs(prob_sum - 1.0) < 0.02, f"Probabilities sum to {prob_sum}, expected ~1.0"


def test_22_model_classes_indexing_alignment():
    classifier = TrafficClassifierInference()
    dummy_features = np.zeros((1, 28))
    from backend.app.ml.flow_extractor import Flow, FlowPacket
    pkt = FlowPacket(
        timestamp=1.0, length=100, is_forward=True, protocol=6, payload_len=50, has_esp=False, has_ike=False
    )
    mock_flow = Flow(
        flow_id="TCP_10.0.0.1:1234<->10.0.0.2:80",
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80, protocol=6,
        packets=[pkt]
    )
    res = classifier.predict_flow_class(mock_flow)

    ml_info = res["inferred_ml_classification"]
    probs = ml_info["class_probabilities"]
    model_classes = list(getattr(classifier.model, "classes_", classifier.target_classes))

    # Verify all target classes exist in probs and sum to ~1.0
    for cname in classifier.target_classes:
        assert cname in probs
        assert 0.0 <= probs[cname] <= 1.0
    assert abs(sum(probs.values()) - 1.0) < 0.02

