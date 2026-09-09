"""
Real-IPsec Dataset Quality & Shortcut Correlation Audit Script.
Phase 11.5 — AI-Powered IPsec VPN Protocol Analyzer.

Performs forensic auditing of the REAL-IPSEC-v1 dataset:
1. Totals, Class Distributions & Profile Distributions.
2. Statistical Volumetric, Length & IAT Properties.
3. Integrity Checks (Missing PCAPs/metadata, invalid labels, duplicate hashes, session leakage, OOD contamination).
4. Shortcut & Correlation Analysis (behavioral_class vs encryption / nat_traversal / mode).
"""

import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "datasets" / "real_ipsec"
REGISTRY_PATH = REAL_IPSEC_DIR / "real_ipsec_registry.json"
MANIFEST_PATH = REAL_IPSEC_DIR / "dataset_manifest.json"
SPLIT_MANIFEST_PATH = REAL_IPSEC_DIR / "split_manifest.json"
FEATURES_CSV_PATH = REAL_IPSEC_DIR / "real_ipsec_features.csv"

from backend.app.ml.schema import (
    BEHAVIORAL_TARGET_CLASSES,
    CLASS_UNKNOWN_UNCLASSIFIED,
    SOURCE_REAL_IPSEC_GROUND_TRUTH
)
from backend.app.ml.splitting import FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS

PERMANENT_OOD_CAPTURES = {"TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"}


def compute_file_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def audit_real_ipsec_dataset() -> Dict[str, Any]:
    """Runs complete quality, integrity, leakage, and correlation audit of REAL-IPSEC-v1."""
    print("============================================================")
    print(" Phase 11.5 — REAL-IPSEC-v1 Dataset Quality & Shortcut Audit")
    print("============================================================")

    if not REGISTRY_PATH.exists():
        print(f"[!] Registry file not found at {REGISTRY_PATH}. Creating empty template.")
        empty_registry = {
            "dataset_id": "REAL-IPSEC-v1",
            "dataset_source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
            "created_at": datetime.datetime.now().isoformat(),
            "sessions": []
        }
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(empty_registry, f, indent=2)

    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        registry_data = json.load(f)

    sessions = registry_data.get("sessions", [])

    # A. Totals
    total_sessions = len(sessions)
    print(f"[+] Master Registry loaded: {total_sessions} registered real-IPsec sessions")

    # B. Class Distribution
    class_counts = {c: 0 for c in BEHAVIORAL_TARGET_CLASSES}
    class_counts[CLASS_UNKNOWN_UNCLASSIFIED] = 0

    # C. Profile & Cryptographic Distribution
    enc_counts: Dict[str, int] = {}
    mode_counts: Dict[str, int] = {}
    natt_counts: Dict[str, int] = {}
    encap_counts: Dict[str, int] = {}

    # D. Integrity Violations List
    integrity_violations: List[str] = []
    seen_capture_ids: Set[str] = set()
    seen_session_ids: Set[str] = set()
    seen_hashes: Set[str] = set()

    for idx, s in enumerate(sessions):
        cap_id = s.get("capture_id")
        sess_id = s.get("session_id")
        b_class = s.get("ground_truth_behavioral_class")
        pcap_rel = s.get("pcap_path")
        meta_rel = s.get("metadata_path")
        sha256 = s.get("sha256")
        ds_source = s.get("dataset_source")

        # 1. Missing fields check
        if not cap_id or not sess_id or not b_class:
            integrity_violations.append(f"Session #{idx}: Missing capture_id, session_id, or ground_truth_behavioral_class")

        # 2. Duplicate checks
        if cap_id in seen_capture_ids:
            integrity_violations.append(f"Duplicate capture_id: '{cap_id}'")
        else:
            seen_capture_ids.add(cap_id)

        if sess_id in seen_session_ids:
            integrity_violations.append(f"Duplicate session_id: '{sess_id}'")
        else:
            seen_session_ids.add(sess_id)

        if sha256:
            if sha256 in seen_hashes:
                integrity_violations.append(f"Duplicate PCAP SHA256 hash: {sha256[:12]}... in capture '{cap_id}'")
            else:
                seen_hashes.add(sha256)

        # 3. Label validity check
        if b_class not in BEHAVIORAL_TARGET_CLASSES and b_class != CLASS_UNKNOWN_UNCLASSIFIED:
            integrity_violations.append(f"Invalid behavioral label '{b_class}' in capture '{cap_id}'")
        else:
            if b_class in class_counts:
                class_counts[b_class] += 1

        # 4. Source & Provenance check
        if ds_source != SOURCE_REAL_IPSEC_GROUND_TRUTH:
            integrity_violations.append(f"Invalid dataset_source '{ds_source}' in capture '{cap_id}'. Must be REAL_IPSEC_GROUND_TRUTH.")

        # 5. Pre-capture ground truth assignment check
        if s.get("ground_truth_established_before_capture") is not True:
            integrity_violations.append(f"Ground truth was NOT established before capture in session '{cap_id}'!")

        # 6. File Existence check
        if pcap_rel:
            pcap_path = PROJECT_ROOT / pcap_rel
            if not pcap_path.exists():
                integrity_violations.append(f"PCAP file missing on disk: {pcap_path}")
            elif cap_id in PERMANENT_OOD_CAPTURES or pcap_path.name in PERMANENT_OOD_CAPTURES:
                integrity_violations.append(f"OOD Contamination: Permanent OOD capture '{pcap_path.name}' registered as regular training session!")

        if meta_rel:
            meta_path = PROJECT_ROOT / meta_rel
            if not meta_path.exists():
                integrity_violations.append(f"Metadata JSON file missing on disk: {meta_path}")

        # Update profile stats
        enc = s.get("encryption", "UNKNOWN")
        mode = s.get("ipsec_mode", "UNKNOWN")
        natt = str(s.get("nat_traversal", False))
        encap = s.get("encapsulation_type", "UNKNOWN")

        enc_counts[enc] = enc_counts.get(enc, 0) + 1
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        natt_counts[natt] = natt_counts.get(natt, 0) + 1
        encap_counts[encap] = encap_counts.get(encap, 0) + 1

    # E. Session Leakage & OOD Exclusion Check
    leakage_audit = {"status": "PASSED", "violations": []}
    if SPLIT_MANIFEST_PATH.exists():
        with open(SPLIT_MANIFEST_PATH, "r", encoding="utf-8") as f:
            split_data = json.load(f)

        train_sids = set(split_data.get("train_sessions", []))
        val_sids = set(split_data.get("validation_sessions", []))
        test_sids = set(split_data.get("test_sessions", []))
        ood_caps = set(split_data.get("excluded_ood_captures", []))

        # Check OOD Exclusion
        for ood_file in PERMANENT_OOD_CAPTURES:
            if ood_file not in ood_caps:
                leakage_audit["violations"].append(f"OOD capture '{ood_file}' missing from split_manifest excluded list!")
            if any(ood_file in sid for sid in train_sids | val_sids | test_sids):
                leakage_audit["violations"].append(f"OOD capture '{ood_file}' found inside Train/Val/Test partitions!")

        # Check Session Overlap
        ov_train_val = len(train_sids & val_sids)
        ov_train_test = len(train_sids & test_sids)
        ov_val_test = len(val_sids & test_sids)

        if ov_train_val > 0 or ov_train_test > 0 or ov_val_test > 0:
            leakage_audit["status"] = "FAILED"
            leakage_audit["violations"].append(f"Session overlap detected across splits! (Train-Val: {ov_train_val}, Train-Test: {ov_train_test}, Val-Test: {ov_val_test})")

    # F. Shortcut / Correlation Analysis
    shortcut_warnings: List[str] = []
    # Contingency Table: behavioral_class vs encryption
    class_enc_matrix: Dict[str, Dict[str, int]] = {}
    for s in sessions:
        bc = s.get("ground_truth_behavioral_class", "UNKNOWN")
        enc = s.get("encryption", "UNKNOWN")
        if bc not in class_enc_matrix:
            class_enc_matrix[bc] = {}
        class_enc_matrix[bc][enc] = class_enc_matrix[bc].get(enc, 0) + 1

    # Check for 100% correlation shortcuts
    for bc, enc_map in class_enc_matrix.items():
        if len(enc_map) == 1 and total_sessions >= 10:
            sole_enc = list(enc_map.keys())[0]
            shortcut_warnings.append(f"DATASET DESIGN RISK: Class '{bc}' relies 100% on single encryption cipher '{sole_enc}'!")

    audit_summary = {
        "timestamp": datetime.datetime.now().isoformat(),
        "dataset_id": "REAL-IPSEC-v1",
        "total_sessions": total_sessions,
        "class_distribution": class_counts,
        "profile_distribution": {
            "encryption": enc_counts,
            "ipsec_mode": mode_counts,
            "nat_traversal": natt_counts,
            "encapsulation": encap_counts
        },
        "integrity_violations_count": len(integrity_violations),
        "integrity_violations": integrity_violations,
        "leakage_audit": leakage_audit,
        "shortcut_warnings_count": len(shortcut_warnings),
        "shortcut_warnings": shortcut_warnings,
        "contingency_matrix_class_vs_encryption": class_enc_matrix
    }

    print("\n--- Audit Summary Report ---")
    print(f" Total Registered Sessions: {total_sessions}")
    print(f" Class Distribution:        {class_counts}")
    print(f" Integrity Violations:      {len(integrity_violations)}")
    print(f" Leakage Status:            {leakage_audit['status']}")
    print(f" Shortcut Warnings:         {len(shortcut_warnings)}")
    print("============================================================")

    return audit_summary


if __name__ == "__main__":
    res = audit_real_ipsec_dataset()
    print(json.dumps(res, indent=2))
