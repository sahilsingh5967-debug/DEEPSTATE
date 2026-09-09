"""
Unit & Integration Tests for Phase 11.3 ML Data & Feature Pipeline Correctness.
Phase 11.3 — AI-Powered IPsec VPN Protocol Analyzer.
"""

import json
from pathlib import Path
import pytest

from backend.app.ml.schema import (
    CLASS_ICMP_DIAGNOSTIC,
    CLASS_WEB_INTERACTIVE,
    CLASS_BULK_TRANSFER,
    CLASS_STREAMING_MEDIA,
    CLASS_VOIP_AUDIO,
    CLASS_UNKNOWN_UNCLASSIFIED,
    BEHAVIORAL_TARGET_CLASSES,
    REAL_IPSEC_GROUND_TRUTH_REGISTRY,
    map_legacy_class_to_behavioral,
    map_lab_scenario_to_behavioral,
    apply_unknown_inference_policy
)

from backend.app.ml.splitting import split_records_session_level, FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS, extract_features_from_flow
from backend.app.ml.flow_extractor import Flow, FlowPacket
from backend.app.ml.model_training import prepare_phase11_dataset_manifest
from backend.app.ml.inference import evaluate_real_ipsec_ground_truth

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FINAL_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "final_model.pkl"
PREPROCESSOR_PATH = PROJECT_ROOT / "data" / "models" / "preprocessor.pkl"


def test_phase11_schema_constants():
    """Verify target classes, constants, and schema definitions."""
    assert len(BEHAVIORAL_TARGET_CLASSES) == 5
    assert CLASS_ICMP_DIAGNOSTIC in BEHAVIORAL_TARGET_CLASSES
    assert CLASS_WEB_INTERACTIVE in BEHAVIORAL_TARGET_CLASSES
    assert CLASS_BULK_TRANSFER in BEHAVIORAL_TARGET_CLASSES
    assert CLASS_STREAMING_MEDIA in BEHAVIORAL_TARGET_CLASSES
    assert CLASS_VOIP_AUDIO in BEHAVIORAL_TARGET_CLASSES
    assert CLASS_UNKNOWN_UNCLASSIFIED not in BEHAVIORAL_TARGET_CLASSES


def test_legacy_class_mapping():
    """Verify mapping of legacy 8-class labels to Phase 11 behavioral target classes."""
    assert map_legacy_class_to_behavioral("ICMP") == CLASS_ICMP_DIAGNOSTIC
    assert map_legacy_class_to_behavioral("Web Browsing") == CLASS_WEB_INTERACTIVE
    assert map_legacy_class_to_behavioral("File Transfer") == CLASS_BULK_TRANSFER
    assert map_legacy_class_to_behavioral("Streaming") == CLASS_STREAMING_MEDIA
    assert map_legacy_class_to_behavioral("VoIP") == CLASS_VOIP_AUDIO
    assert map_legacy_class_to_behavioral("Chat") == CLASS_UNKNOWN_UNCLASSIFIED
    assert map_legacy_class_to_behavioral("Email") == CLASS_UNKNOWN_UNCLASSIFIED
    assert map_legacy_class_to_behavioral("P2P") == CLASS_UNKNOWN_UNCLASSIFIED
    assert map_legacy_class_to_behavioral(None) == CLASS_UNKNOWN_UNCLASSIFIED


def test_lab_scenario_mapping():
    """Verify mapping of Demonstration Lab scenario IDs to behavioral target classes."""
    cls, supp = map_lab_scenario_to_behavioral("ICMP")
    assert cls == CLASS_ICMP_DIAGNOSTIC and supp is True

    cls, supp = map_lab_scenario_to_behavioral("WEB_LIKE")
    assert cls == CLASS_WEB_INTERACTIVE and supp is True

    cls, supp = map_lab_scenario_to_behavioral("FILE_TRANSFER_LIKE")
    assert cls == CLASS_BULK_TRANSFER and supp is True

    cls, supp = map_lab_scenario_to_behavioral("VOIP_LIKE")
    assert cls == CLASS_VOIP_AUDIO and supp is True

    cls, supp = map_lab_scenario_to_behavioral("GENERIC_UDP")
    assert cls == CLASS_UNKNOWN_UNCLASSIFIED and supp is False


def test_unknown_inference_policy():
    """Verify centralized UNKNOWN_UNCLASSIFIED policy rules."""
    # Packet count < 3 -> UNKNOWN_UNCLASSIFIED
    cls, conf, reason = apply_unknown_inference_policy("ICMP", 0.95, packet_count=2)
    assert cls == CLASS_UNKNOWN_UNCLASSIFIED
    assert "Insufficient packet count" in reason

    # Confidence < 0.50 -> UNKNOWN_UNCLASSIFIED
    cls, conf, reason = apply_unknown_inference_policy("Web Browsing", 0.42, packet_count=10)
    assert cls == CLASS_UNKNOWN_UNCLASSIFIED
    assert "below 50% threshold" in reason

    # High confidence & sufficient packets -> Original Class preserved
    cls, conf, reason = apply_unknown_inference_policy("ICMP", 0.88, packet_count=15)
    assert cls == "ICMP"
    assert conf == 0.88


def test_real_ipsec_ground_truth_registry():
    """Verify real IPsec ground truth registry entries for TEST-001, TEST-002, TEST-003."""
    assert "TEST-001.pcap" in REAL_IPSEC_GROUND_TRUTH_REGISTRY
    assert "TEST-002.pcap" in REAL_IPSEC_GROUND_TRUTH_REGISTRY
    assert "TEST-003.pcap" in REAL_IPSEC_GROUND_TRUTH_REGISTRY

    t1 = REAL_IPSEC_GROUND_TRUTH_REGISTRY["TEST-001.pcap"]
    assert t1["ground_truth_behavioral_class"] == CLASS_ICMP_DIAGNOSTIC

    t2 = REAL_IPSEC_GROUND_TRUTH_REGISTRY["TEST-002.pcap"]
    assert t2["ground_truth_behavioral_class"] == CLASS_BULK_TRANSFER

    t3 = REAL_IPSEC_GROUND_TRUTH_REGISTRY["TEST-003.pcap"]
    assert t3["ground_truth_behavioral_class"] == CLASS_WEB_INTERACTIVE


def test_session_level_splitting_zero_leakage():
    """Verify capture/session-level grouped splitting enforces zero session leakage across splits."""
    records = []
    # Create 10 sessions with 5 flows each
    for s_idx in range(10):
        sid = f"SESSION_{s_idx:02d}"
        for f_idx in range(5):
            records.append({
                "flow_id": f"FLOW_{s_idx}_{f_idx}",
                "capture_id": sid,
                "session_id": sid,
                "traffic_class": "Web Browsing",
                "behavioral_class": CLASS_WEB_INTERACTIVE
            })

    splits = split_records_session_level(records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)

    train_sids = set(r["session_id"] for r in splits["train"])
    val_sids = set(r["session_id"] for r in splits["val"])
    test_sids = set(r["session_id"] for r in splits["test"])

    # Strict Zero Overlap Assertion
    assert len(train_sids & val_sids) == 0
    assert len(train_sids & test_sids) == 0
    assert len(val_sids & test_sids) == 0
    assert len(train_sids) + len(val_sids) + len(test_sids) == 10


def test_features_metadata_enhancement():
    """Verify extract_features_from_flow populates Phase 11 metadata fields."""
    pkt1 = FlowPacket(timestamp=100.0, length=100, is_forward=True, protocol=6, payload_len=60)
    pkt2 = FlowPacket(timestamp=100.1, length=200, is_forward=False, protocol=6, payload_len=160)
    flow = Flow(
        flow_id="TEST_FLOW_1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol=6,
        packets=[pkt1, pkt2],
        traffic_class="Web Browsing",
        pcap_source="TEST_CAP_1"
    )

    feat = extract_features_from_flow(
        flow,
        dataset_id="TEST_DATASET",
        dataset_source="SYNTHETIC_DEVELOPMENT",
        session_id="SESS_123",
        behavioral_class=CLASS_WEB_INTERACTIVE
    )

    assert feat["dataset_id"] == "TEST_DATASET"
    assert feat["dataset_source"] == "SYNTHETIC_DEVELOPMENT"
    assert feat["capture_id"] == "TEST_CAP_1"
    assert feat["session_id"] == "SESS_123"
    assert feat["traffic_class"] == "Web Browsing"
    assert feat["behavioral_class"] == CLASS_WEB_INTERACTIVE

    for col in METADATA_COLUMNS:
        assert col in feat


def test_prepare_phase11_manifest_dry_run():
    """Verify prepare_phase11_dataset_manifest executes dry-run without altering model files."""
    m_time_before = FINAL_MODEL_PATH.stat().st_mtime if FINAL_MODEL_PATH.exists() else 0

    manifest = prepare_phase11_dataset_manifest()
    assert manifest["status"] == "prepared"
    assert "session_split" in manifest
    assert manifest["session_split"]["zero_session_overlap_verified"] is True

    m_time_after = FINAL_MODEL_PATH.stat().st_mtime if FINAL_MODEL_PATH.exists() else 0
    assert m_time_before == m_time_after, "Production final_model.pkl must NOT be altered!"


def test_evaluate_real_ipsec_ground_truth():
    """Verify evaluate_real_ipsec_ground_truth entry point."""
    res = evaluate_real_ipsec_ground_truth()
    assert res["evaluation_type"] == "REAL_IPSEC_GROUND_TRUTH_REGISTRY_EVALUATION"
    assert "registry_results" in res
    assert len(res["registry_results"]) >= 3
