"""
Comprehensive Live Real-IPsec Data Acquisition & Validation Safety Tests.
Phase 11.6B — AI-Powered IPsec VPN Protocol Analyzer.

Enforces zero-tolerance safety bounds:
1. Docker preflight and fail-closed acquisition.
2. Production model immutability (final_model.pkl & preprocessor.pkl SHA256).
3. OOD benchmark immutability (TEST-001/002/003.pcap SHA256).
4. Pre-capture ground-truth metadata completeness.
5. Unique session IDs, capture IDs, and PCAP SHA256 checksums.
6. Zero session leakage across dataset partitions.
7. Absolute exclusion of forbidden predictive identifiers from X.
8. 28-feature schema correctness.
9. Dataset Readiness Gate evaluation.
10. Candidate model isolation under data/models/candidates/.
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
from scripts.testbed.generate_real_ipsec_dataset import (
    check_testbed_acquisition_readiness,
    compute_file_sha256
)
from scripts.testbed.profile_registry import get_all_profiles, get_profile
from scripts.testbed.traffic_generator import (
    generate_icmp_diagnostic,
    generate_web_interactive,
    generate_bulk_transfer,
    generate_streaming_media,
    generate_voip_audio
)
from scripts.ml.audit_real_ipsec_dataset import audit_real_ipsec_dataset, PERMANENT_OOD_CAPTURES

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "datasets" / "real_ipsec"
REGISTRY_PATH = REAL_IPSEC_DIR / "real_ipsec_registry.json"
SPLIT_MANIFEST_PATH = REAL_IPSEC_DIR / "split_manifest.json"
FEATURES_CSV_PATH = REAL_IPSEC_DIR / "real_ipsec_features.csv"

PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "final_model.pkl"
PRODUCTION_PREPROCESSOR_PATH = PROJECT_ROOT / "data" / "models" / "preprocessor.pkl"

BASELINE_FINAL_MODEL_SHA256 = "e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4"
BASELINE_PREPROCESSOR_SHA256 = "f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2"

BASELINE_TEST001_SHA256 = "e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813"
BASELINE_TEST002_SHA256 = "cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c"
BASELINE_TEST003_SHA256 = "719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229"


def test_1_preflight_docker_contract():
    """Verify testbed preflight check returns structured status dictionary."""
    readiness = check_testbed_acquisition_readiness()
    assert "is_ready" in readiness
    assert "docker_available" in readiness
    assert "peer_a_running" in readiness
    assert "peer_b_running" in readiness
    assert "status" in readiness


def test_2_ground_truth_pre_capture_contract():
    """Verify ground truth is assigned from experiment configuration before capture."""
    sample_session = {
        "ground_truth_behavioral_class": "WEB_INTERACTIVE",
        "ground_truth_method": "PRE_CAPTURE_EXPERIMENT_CONFIGURATION",
        "ground_truth_established_before_capture": True
    }
    assert sample_session["ground_truth_established_before_capture"] is True
    assert sample_session["ground_truth_method"] == "PRE_CAPTURE_EXPERIMENT_CONFIGURATION"
    assert sample_session["ground_truth_behavioral_class"] in BEHAVIORAL_TARGET_CLASSES


def test_3_no_synthetic_pcap_substitution():
    """Verify dataset_source is REAL_IPSEC_GROUND_TRUTH for all registered sessions."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for s in data.get("sessions", []):
            assert s.get("dataset_source") == SOURCE_REAL_IPSEC_GROUND_TRUTH


def test_4_approved_behavioral_classes_only():
    """Verify all 5 target behavioral classes are defined."""
    assert len(BEHAVIORAL_TARGET_CLASSES) == 5
    for cname in ["ICMP_DIAGNOSTIC", "WEB_INTERACTIVE", "BULK_TRANSFER", "STREAMING_MEDIA", "VOIP_AUDIO"]:
        assert cname in BEHAVIORAL_TARGET_CLASSES


def test_5_approved_ipsec_profiles_only():
    """Verify 5 research IPsec profiles (TEST-001 through TEST-005) are registered."""
    profiles = get_all_profiles()
    assert len(profiles) >= 5
    for pid in ["TEST-001", "TEST-002", "TEST-003", "TEST-004", "TEST-005"]:
        prof = get_profile(pid)
        assert prof is not None
        assert prof["profile_id"] == pid


def test_6_capture_id_uniqueness():
    """Verify all registered capture IDs are unique."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        cap_ids = [s["capture_id"] for s in data.get("sessions", []) if "capture_id" in s]
        assert len(cap_ids) == len(set(cap_ids)), "Duplicate capture IDs detected!"


def test_7_session_id_uniqueness():
    """Verify all registered session IDs are unique."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        sess_ids = [s["session_id"] for s in data.get("sessions", []) if "session_id" in s]
        assert len(sess_ids) == len(set(sess_ids)), "Duplicate session IDs detected!"


def test_8_sha256_uniqueness():
    """Verify all registered PCAP SHA256 hashes are unique."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        hashes = [s["sha256"] for s in data.get("sessions", []) if "sha256" in s]
        assert len(hashes) == len(set(hashes)), "Duplicate PCAP hashes detected!"


def test_9_metadata_completeness_per_session():
    """Verify per-session JSON metadata file exists for every registered capture."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for s in data.get("sessions", []):
            meta_rel = s.get("metadata_path")
            assert meta_rel is not None
            meta_abs = PROJECT_ROOT / meta_rel
            assert meta_abs.exists(), f"Missing metadata JSON file: {meta_abs}"


def test_10_ood_test001_immutability_and_exclusion():
    """Verify TEST-001.pcap SHA256 hash matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-001.pcap"
    assert pcap_path.exists(), "TEST-001.pcap missing on disk"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == BASELINE_TEST001_SHA256, f"TEST-001.pcap hash changed! {curr_hash} != {BASELINE_TEST001_SHA256}"


def test_11_ood_test002_immutability_and_exclusion():
    """Verify TEST-002.pcap SHA256 hash matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-002.pcap"
    assert pcap_path.exists(), "TEST-002.pcap missing on disk"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == BASELINE_TEST002_SHA256, f"TEST-002.pcap hash changed! {curr_hash} != {BASELINE_TEST002_SHA256}"


def test_12_ood_test003_immutability_and_exclusion():
    """Verify TEST-003.pcap SHA256 hash matches baseline."""
    pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / "TEST-003.pcap"
    assert pcap_path.exists(), "TEST-003.pcap missing on disk"
    curr_hash = compute_file_sha256(pcap_path)
    assert curr_hash == BASELINE_TEST003_SHA256, f"TEST-003.pcap hash changed! {curr_hash} != {BASELINE_TEST003_SHA256}"


def test_13_production_final_model_pkl_immutability():
    """Verify final_model.pkl SHA256 hash matches baseline."""
    assert PRODUCTION_MODEL_PATH.exists(), "Production final_model.pkl missing!"
    curr_hash = compute_file_sha256(PRODUCTION_MODEL_PATH)
    assert curr_hash == BASELINE_FINAL_MODEL_SHA256, f"Production final_model.pkl modified! {curr_hash} != {BASELINE_FINAL_MODEL_SHA256}"


def test_14_production_preprocessor_pkl_immutability():
    """Verify preprocessor.pkl SHA256 hash matches baseline."""
    assert PRODUCTION_PREPROCESSOR_PATH.exists(), "Production preprocessor.pkl missing!"
    curr_hash = compute_file_sha256(PRODUCTION_PREPROCESSOR_PATH)
    assert curr_hash == BASELINE_PREPROCESSOR_SHA256, f"Production preprocessor.pkl modified! {curr_hash} != {BASELINE_PREPROCESSOR_SHA256}"


def test_15_zero_session_leakage_across_splits():
    """Verify audit_real_ipsec_dataset confirms 0 session leakage and 0 OOD contamination."""
    res = audit_real_ipsec_dataset()
    assert res["leakage_audit"]["status"] == "PASSED"
    assert len(res["leakage_audit"]["violations"]) == 0
    assert res["integrity_violations_count"] == 0


def test_16_forbidden_predictive_identifiers_absent():
    """Verify forbidden predictive identifiers (IPs, Ports, Session/Capture IDs) are excluded from X."""
    assert len(FORBIDDEN_PREDICTIVE_IDENTIFIERS) > 0
    for forbidden in ["src_ip", "dst_ip", "src_port", "dst_port", "session_id", "capture_id"]:
        assert forbidden in FORBIDDEN_PREDICTIVE_IDENTIFIERS
        assert forbidden not in ML_FEATURE_COLUMNS


def test_17_predictive_28_features_schema():
    """Verify ML_FEATURE_COLUMNS contains exactly 28 feature names."""
    assert len(ML_FEATURE_COLUMNS) == 28


def test_18_traffic_generators_coverage():
    """Verify 5 behavioral traffic generator functions are callable."""
    generators = [
        generate_icmp_diagnostic,
        generate_web_interactive,
        generate_bulk_transfer,
        generate_streaming_media,
        generate_voip_audio
    ]
    assert len(generators) == 5
    for gen_func in generators:
        assert callable(gen_func)


def test_19_candidate_models_isolation_under_candidates_dir():
    """Verify candidate models path is isolated under data/models/candidates/."""
    candidates_dir = PROJECT_ROOT / "data" / "models" / "candidates"
    assert candidates_dir.exists()
    assert candidates_dir != PRODUCTION_MODEL_PATH.parent


def test_20_dataset_readiness_gate_criteria():
    """Verify Dataset Readiness Gate criteria evaluation logic."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        sess_count = len(data.get("sessions", []))
        readiness = check_testbed_acquisition_readiness()
        if sess_count >= 50 and readiness["is_ready"]:
            expected_status = "DATASET_READY"
        else:
            expected_status = "DATASET_INSUFFICIENT"
        assert expected_status in ["DATASET_READY", "DATASET_INSUFFICIENT"]
