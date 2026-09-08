"""
Unit & Integration Tests for Phase 5.2.1 Dataset Expansion & Quality Validation.
"""

import csv
import json
import math
from pathlib import Path
import pytest

from backend.app.ml.flow_extractor import extract_flows_from_pcap
from backend.app.ml.features import (
    extract_features_from_flow,
    extract_features_from_flows,
    ML_FEATURE_COLUMNS,
    METADATA_COLUMNS
)
from backend.app.ml.splitting import (
    split_records_flow_level,
    prepare_ml_matrices,
    FORBIDDEN_PREDICTIVE_IDENTIFIERS
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_PCAP_DIR = PROJECT_ROOT / "data" / "pcaps" / "real"
PUBLIC_DATASET_DIR = PROJECT_ROOT / "data" / "datasets" / "public" / "iscx_vpn2016"
INVENTORY_FILE = PROJECT_ROOT / "data" / "datasets" / "dataset_inventory.json"
QUALITY_REPORT_FILE = PROJECT_ROOT / "data" / "datasets" / "dataset_quality_report.json"
FEATURES_CSV = PROJECT_ROOT / "data" / "datasets" / "features" / "iscx_vpn2016_features.csv"

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


def test_1_expanded_dataset_flow_count():
    assert FEATURES_CSV.exists(), "iscx_vpn2016_features.csv must exist"
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    flow_count = len(records)
    assert flow_count > 93, f"Expanded dataset must contain substantially more than 93 flows (found {flow_count})"


def test_2_acquisition_size_limit():
    assert INVENTORY_FILE.exists(), "dataset_inventory.json must exist"
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        inv = json.load(f)

    pub_bytes = inv.get("public_dataset_metrics", {}).get("total_size_bytes", 0)
    max_allowed_bytes = 2 * 1024 * 1024 * 1024  # 2 GB limit
    assert pub_bytes <= max_allowed_bytes, f"Acquired dataset ({pub_bytes} B) exceeds max storage cap of 2 GB"


def test_3_target_classes_represented():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    classes_found = set(r.get("traffic_class") for r in records)
    for tc in TARGET_CLASSES:
        assert tc in classes_found, f"Target traffic class '{tc}' missing from dataset"


def test_4_zero_nan_values():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    for r in records:
        for col in ML_FEATURE_COLUMNS:
            val = float(r[col])
            assert not math.isnan(val), f"NaN value found in column {col}"


def test_5_zero_infinity_values():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    for r in records:
        for col in ML_FEATURE_COLUMNS:
            val = float(r[col])
            assert not math.isinf(val), f"Infinity value found in column {col}"


def test_6_forbidden_predictive_identifiers():
    for forbidden in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert forbidden not in ML_FEATURE_COLUMNS, f"Forbidden identifier '{forbidden}' found in predictive ML columns"


def test_7_zero_flow_id_overlap_across_splits():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    splits = split_records_flow_level(records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)

    train_ids = set(r["flow_id"] for r in splits["train"])
    val_ids = set(r["flow_id"] for r in splits["val"])
    test_ids = set(r["flow_id"] for r in splits["test"])

    assert len(train_ids & val_ids) == 0, "Train and Val share flow IDs!"
    assert len(train_ids & test_ids) == 0, "Train and Test share flow IDs!"
    assert len(val_ids & test_ids) == 0, "Val and Test share flow IDs!"


def test_8_split_determinism():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    run1 = split_records_flow_level(records, random_seed=42)
    run2 = split_records_flow_level(records, random_seed=42)

    assert [r["flow_id"] for r in run1["train"]] == [r["flow_id"] for r in run2["train"]]
    assert [r["flow_id"] for r in run1["val"]] == [r["flow_id"] for r in run2["val"]]
    assert [r["flow_id"] for r in run1["test"]] == [r["flow_id"] for r in run2["test"]]


def test_9_real_ipsec_isolation():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    for r in records:
        cid = str(r.get("capture_id", "")).upper()
        assert "TEST-001" not in cid
        assert "TEST-002" not in cid
        assert "TEST-003" not in cid


def test_10_synthetic_fixture_isolation():
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    for r in records:
        cid = str(r.get("capture_id", "")).upper()
        assert "SYNTH" not in cid


def test_11_inventory_internal_consistency():
    assert INVENTORY_FILE.exists()
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        inv = json.load(f)

    metrics = inv.get("public_dataset_metrics", {})
    files_detail = inv.get("public_files_detail", [])

    assert metrics.get("total_pcap_files") == len(files_detail)
    assert metrics.get("total_size_bytes") == sum(r["file_size_bytes"] for r in files_detail)


def test_12_quality_report_internal_consistency():
    assert QUALITY_REPORT_FILE.exists()
    with open(QUALITY_REPORT_FILE, "r", encoding="utf-8") as f:
        qr = json.load(f)

    assert qr.get("quality_status") == "PASSED"
    assert qr.get("feature_quality", {}).get("nan_count") == 0
    assert qr.get("feature_quality", {}).get("infinity_count") == 0
    assert qr.get("split_quality", {}).get("flow_isolation_passed") is True
    assert qr.get("leakage_audit", {}).get("leakage_audit_passed") is True
    assert qr.get("real_ipsec_isolation", {}).get("real_ipsec_isolation_passed") is True


def test_13_duplicate_pcap_detection():
    assert INVENTORY_FILE.exists()
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        inv = json.load(f)

    dups = inv.get("quality_flags", {}).get("duplicate_files_count", 0)
    assert dups == 0, f"Duplicate PCAPs detected in inventory: {inv.get('quality_flags', {}).get('duplicate_files')}"


def test_14_corrupt_and_empty_pcap_handling():
    assert INVENTORY_FILE.exists()
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        inv = json.load(f)

    corrupts = inv.get("quality_flags", {}).get("corrupt_files_count", 0)
    empties = inv.get("quality_flags", {}).get("empty_files_count", 0)
    assert corrupts == 0, f"Corrupt files detected: {inv.get('quality_flags', {}).get('corrupt_files')}"
    assert empties == 0, f"Empty files detected: {inv.get('quality_flags', {}).get('empty_files')}"
