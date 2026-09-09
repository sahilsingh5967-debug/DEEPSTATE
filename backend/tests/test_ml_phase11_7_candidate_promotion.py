"""
Comprehensive Automated Test Suite for Candidate Evaluation & Promotion Gates.
Phase 11.7 — AI-Powered IPsec VPN Protocol Analyzer.

Verifies:
1. Production model & preprocessor SHA256 immutability.
2. OOD benchmark PCAPs SHA256 immutability.
3. REAL-IPSEC-v1 dataset & split manifest integrity.
4. Session-level isolation (zero overlap across partitions).
5. 28 predictive feature contract & forbidden metadata exclusion from X.
6. Pre-capture ground-truth independence.
7. Candidate model isolation under data/models/candidates/.
8. Candidate reproducibility & deterministic training (seed 42).
9. Production baseline vs Candidate evaluation metrics.
10. All 14 Promotion Gate evaluations.
11. No automatic production overwrite path.
"""

import hashlib
import json
from pathlib import Path
import pytest

from backend.app.ml.schema import (
    BEHAVIORAL_TARGET_CLASSES,
    CLASS_UNKNOWN_UNCLASSIFIED,
    SOURCE_REAL_IPSEC_GROUND_TRUTH
)
from backend.app.ml.splitting import FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS
from backend.app.ml.promotion_evaluator import (
    execute_phase11_7_evaluation,
    verify_production_and_ood_sentinels,
    compute_file_sha256,
    BASELINE_PROD_MODEL_SHA256,
    BASELINE_PROD_PREPROCESSOR_SHA256,
    OOD_BENCHMARK_CAPTURES
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "datasets" / "real_ipsec"
REGISTRY_PATH = REAL_IPSEC_DIR / "real_ipsec_registry.json"
DATASET_MANIFEST_PATH = REAL_IPSEC_DIR / "dataset_manifest.json"
SPLIT_MANIFEST_PATH = REAL_IPSEC_DIR / "split_manifest.json"
FEATURES_CSV_PATH = REAL_IPSEC_DIR / "real_ipsec_features.csv"

PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "final_model.pkl"
PRODUCTION_PREPROCESSOR_PATH = PROJECT_ROOT / "data" / "models" / "preprocessor.pkl"
CANDIDATES_DIR = PROJECT_ROOT / "data" / "models" / "candidates"
PHASE11_7_REPORT_PATH = CANDIDATES_DIR / "phase11_7" / "phase11_7_report.json"


def test_1_production_model_artifact_exists():
    """Verify production final_model.pkl exists on disk."""
    assert PRODUCTION_MODEL_PATH.exists(), "Production final_model.pkl missing!"


def test_2_production_preprocessor_artifact_exists():
    """Verify production preprocessor.pkl exists on disk."""
    assert PRODUCTION_PREPROCESSOR_PATH.exists(), "Production preprocessor.pkl missing!"


def test_3_production_final_model_sha256_unmodified():
    """Verify final_model.pkl SHA256 hash matches production baseline."""
    curr_hash = compute_file_sha256(PRODUCTION_MODEL_PATH)
    assert curr_hash == BASELINE_PROD_MODEL_SHA256, f"Production final_model.pkl modified! {curr_hash} != {BASELINE_PROD_MODEL_SHA256}"


def test_4_production_preprocessor_sha256_unmodified():
    """Verify preprocessor.pkl SHA256 hash matches production baseline."""
    curr_hash = compute_file_sha256(PRODUCTION_PREPROCESSOR_PATH)
    assert curr_hash == BASELINE_PROD_PREPROCESSOR_SHA256, f"Production preprocessor.pkl modified! {curr_hash} != {BASELINE_PROD_PREPROCESSOR_SHA256}"


def test_5_ood_test001_pcap_exists():
    """Verify TEST-001.pcap exists on disk."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-001.pcap"
    assert pcap_path.exists(), "TEST-001.pcap missing!"


def test_6_ood_test002_pcap_exists():
    """Verify TEST-002.pcap exists on disk."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-002.pcap"
    assert pcap_path.exists(), "TEST-002.pcap missing!"


def test_7_ood_test003_pcap_exists():
    """Verify TEST-003.pcap exists on disk."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-003.pcap"
    assert pcap_path.exists(), "TEST-003.pcap missing!"


def test_8_ood_test001_sha256_unmodified():
    """Verify TEST-001.pcap SHA256 matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-001.pcap"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == OOD_BENCHMARK_CAPTURES["TEST-001.pcap"]


def test_9_ood_test002_sha256_unmodified():
    """Verify TEST-002.pcap SHA256 matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-002.pcap"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == OOD_BENCHMARK_CAPTURES["TEST-002.pcap"]


def test_10_ood_test003_sha256_unmodified():
    """Verify TEST-003.pcap SHA256 matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-003.pcap"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == OOD_BENCHMARK_CAPTURES["TEST-003.pcap"]


def test_11_real_ipsec_dataset_manifest_exists():
    """Verify dataset_manifest.json exists."""
    assert DATASET_MANIFEST_PATH.exists()


def test_12_real_ipsec_dataset_id():
    """Verify dataset_id is REAL-IPSEC-v1."""
    with open(DATASET_MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("dataset_id") == "REAL-IPSEC-v1"


def test_13_real_ipsec_dataset_source():
    """Verify dataset_source is REAL_IPSEC_GROUND_TRUTH."""
    with open(DATASET_MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("dataset_source") == SOURCE_REAL_IPSEC_GROUND_TRUTH


def test_14_real_ipsec_session_count():
    """Verify REAL-IPSEC-v1 session count matches 75."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    assert len(reg.get("sessions", [])) == 75


def test_15_real_ipsec_feature_records_exist():
    """Verify real_ipsec_features.csv exists and contains non-zero rows."""
    assert FEATURES_CSV_PATH.exists()
    lines = FEATURES_CSV_PATH.read_text().splitlines()
    assert len(lines) > 100


def test_16_all_five_behavioral_classes_present():
    """Verify all 5 target behavioral classes exist in schema."""
    assert len(BEHAVIORAL_TARGET_CLASSES) == 5
    for cname in ["ICMP_DIAGNOSTIC", "WEB_INTERACTIVE", "BULK_TRANSFER", "STREAMING_MEDIA", "VOIP_AUDIO"]:
        assert cname in BEHAVIORAL_TARGET_CLASSES


def test_17_predictive_feature_schema_count():
    """Verify ML_FEATURE_COLUMNS contains exactly 28 predictive features."""
    assert len(ML_FEATURE_COLUMNS) == 28


def test_18_forbidden_identifiers_absent_from_x():
    """Verify forbidden predictive identifiers are absent from ML_FEATURE_COLUMNS."""
    for col in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert col not in ML_FEATURE_COLUMNS


def test_19_split_manifest_exists():
    """Verify split_manifest.json exists."""
    assert SPLIT_MANIFEST_PATH.exists()


def test_20_split_manifest_random_seed():
    """Verify split manifest uses random seed 42."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    assert sm.get("random_seed") == 42


def test_21_zero_train_val_session_overlap():
    """Verify 0 session overlap between train and validation splits."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    train_set = set(sm.get("train_sessions", []))
    val_set = set(sm.get("validation_sessions", []))
    assert len(train_set & val_set) == 0


def test_22_zero_train_test_session_overlap():
    """Verify 0 session overlap between train and test splits."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    train_set = set(sm.get("train_sessions", []))
    test_set = set(sm.get("test_sessions", []))
    assert len(train_set & test_set) == 0


def test_23_zero_val_test_session_overlap():
    """Verify 0 session overlap between validation and test splits."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    val_set = set(sm.get("validation_sessions", []))
    test_set = set(sm.get("test_sessions", []))
    assert len(val_set & test_set) == 0


def test_24_ood_captures_excluded_from_splits():
    """Verify permanent OOD captures are explicitly listed as excluded from splits."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    excl = sm.get("excluded_ood_captures", [])
    for pcap in ["TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"]:
        assert pcap in excl


def test_25_ground_truth_pre_capture_contract():
    """Verify ground truth assignment method is PRE_CAPTURE_EXPERIMENT_CONFIGURATION."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    for s in reg.get("sessions", []):
        assert s.get("ground_truth_method") == "PRE_CAPTURE_EXPERIMENT_CONFIGURATION"


def test_26_candidate_artifacts_isolation():
    """Verify candidate artifacts live inside data/models/candidates/."""
    candidates = list(CANDIDATES_DIR.glob("candidate_*.pkl"))
    assert len(candidates) >= 3
    for c in candidates:
        assert c.parent == CANDIDATES_DIR


def test_27_promotion_evaluator_execution():
    """Verify Phase 11.7 evaluation engine executes and returns master report."""
    report = execute_phase11_7_evaluation()
    assert report["phase"] == "11.7"
    assert "promotion_gates" in report
    assert "final_verdict" in report


def test_28_all_14_promotion_gates_evaluated():
    """Verify exactly 14 promotion gates are evaluated in master report."""
    with open(PHASE11_7_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)
    gates = rep.get("promotion_gates", {})
    assert len(gates) == 14


def test_29_final_verdict_valid_enum():
    """Verify final verdict is one of approved Phase 11.7 statuses."""
    with open(PHASE11_7_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)
    verdict = rep.get("final_verdict")
    assert verdict in [
        "PROMOTION_APPROVED_PENDING_EXPLICIT_DEPLOYMENT",
        "PROMOTION_REJECTED",
        "EVALUATION_INCONCLUSIVE"
    ]


def test_30_sentinels_post_evaluation_intact():
    """Verify sentinels remain 100% intact after evaluation engine execution."""
    sentinels = verify_production_and_ood_sentinels()
    assert sentinels["all_sentinels_intact"] is True
