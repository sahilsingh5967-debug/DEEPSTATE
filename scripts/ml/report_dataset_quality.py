#!/usr/bin/env python3
"""
Dataset Quality Validation & Audit Script.
Phase 5.2.1 — AI-Powered IPsec VPN Protocol Analyzer.

Analyzes the extracted feature dataset (data/datasets/features/iscx_vpn2016_features.csv)
and dataset inventory, performing comprehensive quality checks for NaNs/infs,
class balance, VPN vs Non-VPN distribution, flow-level leakage-safe splitting,
forbidden identifier leakage, and IPsec ground-truth isolation.

Generates data/datasets/dataset_quality_report.json.
"""

import csv
import datetime
import json
import math
import sys
from pathlib import Path
from typing import Dict, Any, List, Set

from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS
from backend.app.ml.splitting import split_records_flow_level, FORBIDDEN_PREDICTIVE_IDENTIFIERS

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FEATURES_CSV = PROJECT_ROOT / "data" / "datasets" / "features" / "iscx_vpn2016_features.csv"
INVENTORY_JSON = PROJECT_ROOT / "data" / "datasets" / "dataset_inventory.json"
QUALITY_REPORT_OUTPUT = PROJECT_ROOT / "data" / "datasets" / "dataset_quality_report.json"

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


def generate_quality_report() -> Dict[str, Any]:
    print("============================================================")
    print(" Generating Dataset Quality & Leakage Audit Report (Phase 5.2.1)...")
    print("============================================================")

    if not FEATURES_CSV.exists():
        raise FileNotFoundError(f"Feature CSV not found at {FEATURES_CSV}")

    # Load inventory if available
    inv_data = {}
    if INVENTORY_JSON.exists():
        with open(INVENTORY_JSON, "r", encoding="utf-8") as f:
            inv_data = json.load(f)

    pub_metrics = inv_data.get("public_dataset_metrics", {})

    records: List[Dict[str, Any]] = []
    with open(FEATURES_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)

    total_rows = len(records)
    print(f"[+] Loaded {total_rows} feature records from {FEATURES_CSV}")

    # A. DATASET SIZE
    total_bytes = pub_metrics.get("total_size_bytes", FEATURES_CSV.stat().st_size)
    total_mb = round(total_bytes / (1024 * 1024), 2)
    pcap_count = pub_metrics.get("total_pcap_files", 0)
    packet_count = pub_metrics.get("total_packet_count", 0)
    flow_count = total_rows

    size_summary = {
        "total_bytes": total_bytes,
        "total_mb": total_mb,
        "total_gb": round(total_bytes / (1024 * 1024 * 1024), 4),
        "total_pcap_count": pcap_count,
        "total_packet_count": packet_count,
        "total_flow_count": flow_count
    }

    # B. CLASS BALANCE
    class_counts: Dict[str, int] = {c: 0 for c in TARGET_CLASSES}
    for r in records:
        tc = r.get("traffic_class", "UNKNOWN")
        class_counts[tc] = class_counts.get(tc, 0) + 1

    class_percentages = {
        c: round((count / total_rows) * 100, 2) if total_rows > 0 else 0.0
        for c, count in class_counts.items()
    }
    missing_classes = [c for c, count in class_counts.items() if count == 0]

    # C. VPN DISTRIBUTION
    vpn_count = 0
    nonvpn_count = 0
    for r in records:
        cid = r.get("capture_id", "").lower()
        if "nonvpn" in cid:
            nonvpn_count += 1
        else:
            vpn_count += 1

    vpn_pct = round((vpn_count / total_rows) * 100, 2) if total_rows > 0 else 0.0
    nonvpn_pct = round((nonvpn_count / total_rows) * 100, 2) if total_rows > 0 else 0.0

    # D. FEATURE QUALITY (NaN / Inf / Constant / Duplicate checks)
    nan_count = 0
    inf_count = 0
    missing_count = 0

    col_values: Dict[str, List[float]] = {col: [] for col in ML_FEATURE_COLUMNS}

    for r in records:
        for col in ML_FEATURE_COLUMNS:
            val_str = r.get(col, "")
            if val_str == "" or val_str is None:
                missing_count += 1
                continue
            try:
                val = float(val_str)
                if math.isnan(val):
                    nan_count += 1
                elif math.isinf(val):
                    inf_count += 1
                else:
                    col_values[col].append(val)
            except ValueError:
                missing_count += 1

    constant_features = [
        col for col, vals in col_values.items()
        if vals and max(vals) == min(vals)
    ]

    # E. FLOW QUALITY
    flow_ids = [r.get("flow_id") for r in records if r.get("flow_id")]
    unique_flow_ids = set(flow_ids)
    duplicate_flow_ids_count = len(flow_ids) - len(unique_flow_ids)

    zero_duration_count = 0
    for r in records:
        try:
            dur = float(r.get("flow_duration_seconds", 0.0))
            if dur == 0.0:
                zero_duration_count += 1
        except ValueError:
            pass

    # F. SPLIT QUALITY (Train 70% / Val 15% / Test 15% Flow-Level Isolation)
    splits = split_records_flow_level(records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)

    train_recs = splits["train"]
    val_recs = splits["val"]
    test_recs = splits["test"]

    train_fids = set(r["flow_id"] for r in train_recs)
    val_fids = set(r["flow_id"] for r in val_recs)
    test_fids = set(r["flow_id"] for r in test_recs)

    overlap_train_val = len(train_fids & val_fids)
    overlap_train_test = len(train_fids & test_fids)
    overlap_val_test = len(val_fids & test_fids)

    splits_quality = {
        "train_rows": len(train_recs),
        "val_rows": len(val_recs),
        "test_rows": len(test_recs),
        "train_unique_flows": len(train_fids),
        "val_unique_flows": len(val_fids),
        "test_unique_flows": len(test_fids),
        "train_val_flow_overlap": overlap_train_val,
        "train_test_flow_overlap": overlap_train_test,
        "val_test_flow_overlap": overlap_val_test,
        "flow_isolation_passed": (overlap_train_val == 0 and overlap_train_test == 0 and overlap_val_test == 0)
    }

    # G. LEAKAGE AUDIT
    forbidden_in_predictive = [col for col in ML_FEATURE_COLUMNS if col in FORBIDDEN_PREDICTIVE_IDENTIFIERS]
    leakage_passed = len(forbidden_in_predictive) == 0

    # H. REAL IPSEC GROUND-TRUTH ISOLATION
    real_ipsec_in_public = [
        r for r in records
        if any(term in str(r.get("capture_id", "")).upper() for term in ("TEST-001", "TEST-002", "TEST-003"))
    ]
    ipsec_isolation_passed = len(real_ipsec_in_public) == 0

    # I. LIMITATIONS
    limitations = []
    if missing_classes:
        limitations.append(f"Missing target traffic classes: {missing_classes}")
    if abs(vpn_pct - 50.0) > 30:
        limitations.append(f"VPN vs Non-VPN ratio is imbalanced ({vpn_pct}% VPN / {nonvpn_pct}% Non-VPN)")
    limitations.append("Public training dataset uses OpenVPN/SSL VPN captures; raw byte length distributions require ESP padding normalization when inferring on IPsec tunnels.")

    quality_report = {
        "report_timestamp": datetime.datetime.now().isoformat(),
        "quality_status": "PASSED" if (nan_count == 0 and inf_count == 0 and leakage_passed and ipsec_isolation_passed and splits_quality["flow_isolation_passed"]) else "FAILED",
        "dataset_size_summary": size_summary,
        "class_balance": {
            "class_counts": class_counts,
            "class_percentages": class_percentages,
            "missing_classes_count": len(missing_classes),
            "missing_classes": missing_classes
        },
        "vpn_distribution": {
            "vpn_flow_count": vpn_count,
            "nonvpn_flow_count": nonvpn_count,
            "vpn_percentage": vpn_pct,
            "nonvpn_percentage": nonvpn_pct
        },
        "feature_quality": {
            "total_feature_rows": total_rows,
            "predictive_feature_count": len(ML_FEATURE_COLUMNS),
            "nan_count": nan_count,
            "infinity_count": inf_count,
            "missing_value_count": missing_count,
            "constant_features": constant_features
        },
        "flow_quality": {
            "duplicate_flow_ids_count": duplicate_flow_ids_count,
            "zero_duration_flows_count": zero_duration_count
        },
        "split_quality": splits_quality,
        "leakage_audit": {
            "forbidden_predictive_columns_found": forbidden_in_predictive,
            "leakage_audit_passed": leakage_passed
        },
        "real_ipsec_isolation": {
            "real_ipsec_records_found_in_public": len(real_ipsec_in_public),
            "real_ipsec_isolation_passed": ipsec_isolation_passed
        },
        "dataset_limitations": limitations
    }

    QUALITY_REPORT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(QUALITY_REPORT_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(quality_report, f, indent=2)

    print(f"[+] Quality Report complete. Saved to: {QUALITY_REPORT_OUTPUT}")
    print(f" Status: {quality_report['quality_status']}")
    print(f" Extracted Flows: {total_rows}")
    print(f" Target Classes Covered: {8 - len(missing_classes)} / 8")
    print(f" Zero NaN/Inf Check: {'PASSED' if nan_count == 0 and inf_count == 0 else 'FAILED'}")
    print(f" Flow Isolation Check: {'PASSED' if splits_quality['flow_isolation_passed'] else 'FAILED'}")
    print(f" Leakage Audit Check: {'PASSED' if leakage_passed else 'FAILED'}")
    print(f" Real IPsec Isolation Check: {'PASSED' if ipsec_isolation_passed else 'FAILED'}")
    print("============================================================")

    return quality_report


if __name__ == "__main__":
    generate_quality_report()
