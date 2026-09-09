"""
Automated Diagnostic & Safety Test Suite for Phase 11.8 ICMP_DIAGNOSTIC Failure Forensics.
Phase 11.8 — AI-Powered IPsec VPN Protocol Analyzer.

Verifies:
1. Production Model & Preprocessor SHA256 immutability.
2. Permanent OOD Benchmark PCAPs SHA256 immutability.
3. REAL-IPSEC-v1 dataset integrity and ICMP session distribution across splits.
4. Ground-truth pre-capture configuration provenance.
5. 28 predictive feature schema contract and forbidden identifier exclusion.
6. Execution of ICMP forensic analysis and generation of phase11_8_diagnostic_report.json.
7. Confirmation of root-cause diagnostic findings.
"""

import json
from pathlib import Path
import pytest

from backend.app.ml.features import ML_FEATURE_COLUMNS
from backend.app.ml.splitting import FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.schema import BEHAVIORAL_TARGET_CLASSES, SOURCE_REAL_IPSEC_GROUND_TRUTH
from backend.app.ml.promotion_evaluator import (
    verify_production_and_ood_sentinels,
    compute_file_sha256,
    BASELINE_PROD_MODEL_SHA256,
    BASELINE_PROD_PREPROCESSOR_SHA256,
    OOD_BENCHMARK_CAPTURES
)
from scripts.ml.phase11_8.icmp_forensics_runner import run_icmp_forensics

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "datasets" / "real_ipsec"
REGISTRY_PATH = REAL_IPSEC_DIR / "real_ipsec_registry.json"
SPLIT_MANIFEST_PATH = REAL_IPSEC_DIR / "split_manifest.json"
FEATURES_CSV_PATH = REAL_IPSEC_DIR / "real_ipsec_features.csv"

PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "final_model.pkl"
PRODUCTION_PREPROCESSOR_PATH = PROJECT_ROOT / "data" / "models" / "preprocessor.pkl"
DIAGNOSTICS_REPORT_PATH = PROJECT_ROOT / "data" / "models" / "candidates" / "phase11_8_diagnostics" / "phase11_8_diagnostic_report.json"


def test_1_production_model_sha256_unmodified():
    """Verify final_model.pkl SHA256 matches baseline."""
    assert PRODUCTION_MODEL_PATH.exists()
    assert compute_file_sha256(PRODUCTION_MODEL_PATH) == BASELINE_PROD_MODEL_SHA256


def test_2_production_preprocessor_sha256_unmodified():
    """Verify preprocessor.pkl SHA256 matches baseline."""
    assert PRODUCTION_PREPROCESSOR_PATH.exists()
    assert compute_file_sha256(PRODUCTION_PREPROCESSOR_PATH) == BASELINE_PROD_PREPROCESSOR_SHA256


def test_3_ood_benchmarks_sha256_unmodified():
    """Verify all 3 permanent OOD PCAP SHA256 hashes match baseline."""
    for pcap_name, expected_sha in OOD_BENCHMARK_CAPTURES.items():
        pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / pcap_name
        assert pcap_path.exists()
        assert compute_file_sha256(pcap_path) == expected_sha


def test_4_real_ipsec_icmp_session_counts():
    """Verify 15 ICMP_DIAGNOSTIC sessions are registered in REAL-IPSEC-v1."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    icmp_sessions = [s for s in reg.get("sessions", []) if s.get("ground_truth_behavioral_class") == "ICMP_DIAGNOSTIC"]
    assert len(icmp_sessions) == 15


def test_5_icmp_session_split_distribution():
    """Verify ICMP_DIAGNOSTIC sessions exist in Train (11), Val (1), and Test (3)."""
    with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
        sm = json.load(f)
    train_sids = set(sm.get("train_sessions", []))
    val_sids = set(sm.get("validation_sessions", []))
    test_sids = set(sm.get("test_sessions", []))

    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    icmp_sessions = [s for s in reg.get("sessions", []) if s.get("ground_truth_behavioral_class") == "ICMP_DIAGNOSTIC"]
    train_count = sum(1 for s in icmp_sessions if s["session_id"] in train_sids)
    val_count = sum(1 for s in icmp_sessions if s["session_id"] in val_sids)
    test_count = sum(1 for s in icmp_sessions if s["session_id"] in test_sids)

    assert train_count == 11
    assert val_count == 1
    assert test_count == 3


def test_6_ground_truth_pre_capture_configuration_provenance():
    """Verify ground truth is assigned via PRE_CAPTURE_EXPERIMENT_CONFIGURATION."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    for s in reg.get("sessions", []):
        assert s.get("ground_truth_method") == "PRE_CAPTURE_EXPERIMENT_CONFIGURATION"


def test_7_predictive_28_feature_schema_intact():
    """Verify ML_FEATURE_COLUMNS contains exactly 28 predictive features."""
    assert len(ML_FEATURE_COLUMNS) == 28


def test_8_forbidden_predictive_identifiers_excluded():
    """Verify forbidden predictive identifiers are absent from ML_FEATURE_COLUMNS."""
    for forbidden in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert forbidden not in ML_FEATURE_COLUMNS


def test_9_icmp_forensics_runner_execution():
    """Verify run_icmp_forensics executes and writes phase11_8_diagnostic_report.json."""
    report = run_icmp_forensics()
    assert report["phase"] == "11.8"
    assert "root_cause_analysis" in report
    assert DIAGNOSTICS_REPORT_PATH.exists()


def test_10_root_cause_findings_verification():
    """Verify confirmed root causes exist in diagnostic report."""
    with open(DIAGNOSTICS_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)
    rca = rep.get("root_cause_analysis", {})

    assert rca.get("control_flow_disambiguation", {}).get("status") == "CONFIRMED"
    assert rca.get("feature_overlap_icmp_vs_voip", {}).get("status") == "CONFIRMED"
    assert rca.get("sentinel_mutation", {}).get("status") == "RULED_OUT"
