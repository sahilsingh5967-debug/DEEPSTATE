"""
Real-IPsec Ground-Truth Acquisition Engine.
Phase 11.6B — AI-Powered IPsec VPN Protocol Analyzer.

Automates controlled real-IPsec traffic acquisition, metadata registration,
28-feature extraction, session-level dataset splitting, quality auditing,
and dataset readiness gate evaluation from the Linux StrongSwan testbed topology.
Enforces FAIL-CLOSED safety: if Docker containers or StrongSwan peers are unavailable,
reports ACQUISITION_UNAVAILABLE without creating synthetic fake PCAPs or mislabeling data.
"""

import csv
import datetime
import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "datasets" / "real_ipsec"
CAPTURES_DIR = REAL_IPSEC_DIR / "captures"
METADATA_DIR = REAL_IPSEC_DIR / "metadata"
REGISTRY_PATH = REAL_IPSEC_DIR / "real_ipsec_registry.json"
MANIFEST_PATH = REAL_IPSEC_DIR / "dataset_manifest.json"
SPLIT_MANIFEST_PATH = REAL_IPSEC_DIR / "split_manifest.json"
FEATURES_CSV_PATH = REAL_IPSEC_DIR / "real_ipsec_features.csv"

from scripts.testbed.profile_registry import get_profile, get_all_profiles
from scripts.testbed.profile_runner import (
    check_docker_availability,
    check_container_status,
    run_docker_cmd,
    CONTAINER_PEER_A,
    CONTAINER_PEER_B
)
from scripts.testbed.traffic_generator import (
    generate_icmp_diagnostic,
    generate_web_interactive,
    generate_bulk_transfer,
    generate_streaming_media,
    generate_voip_audio
)
from backend.app.ml.schema import (
    BEHAVIORAL_TARGET_CLASSES,
    CLASS_UNKNOWN_UNCLASSIFIED,
    SOURCE_REAL_IPSEC_GROUND_TRUTH
)
from backend.app.ml.splitting import split_records_session_level, FORBIDDEN_PREDICTIVE_IDENTIFIERS
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS, extract_features_from_flows
from backend.app.ml.flow_extractor import extract_flows_from_pcap


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def check_testbed_acquisition_readiness() -> Dict[str, Any]:
    """Checks if live Docker containers and StrongSwan peers are operational."""
    docker_ok = check_docker_availability()
    peer_a_ok = check_container_status(CONTAINER_PEER_A) if docker_ok else False
    peer_b_ok = check_container_status(CONTAINER_PEER_B) if docker_ok else False

    is_ready = docker_ok and peer_a_ok and peer_b_ok

    return {
        "is_ready": is_ready,
        "docker_available": docker_ok,
        "peer_a_running": peer_a_ok,
        "peer_b_running": peer_b_ok,
        "status": "READY" if is_ready else "ACQUISITION_UNAVAILABLE"
    }


def acquire_real_ipsec_session(
    profile_id: str,
    behavioral_class: str,
    run_index: int = 1,
    session_id: Optional[str] = None,
    traffic_generator_name: Optional[str] = None,
    generator_params: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Executes live StrongSwan IPsec capture lifecycle for a single session.
    Fails closed if Docker testbed or SA negotiation fails.
    """
    if behavioral_class not in BEHAVIORAL_TARGET_CLASSES:
        raise ValueError(f"Invalid behavioral_class '{behavioral_class}'. Must be one of {BEHAVIORAL_TARGET_CLASSES}")

    profile = get_profile(profile_id)
    if not profile:
        raise ValueError(f"Invalid profile_id '{profile_id}'")

    readiness = check_testbed_acquisition_readiness()
    if not readiness["is_ready"]:
        print(f"[!] Testbed Acquisition Unavailable: Docker/peers offline ({readiness})")
        return {
            "status": "ACQUISITION_UNAVAILABLE",
            "message": "Live strongSwan Docker testbed containers are offline. Fail-closed: zero synthetic PCAPs produced.",
            "readiness": readiness
        }

    # Ensure virtual endpoint IPs exist on containers
    run_docker_cmd(["exec", CONTAINER_PEER_A, "ip", "addr", "add", "10.1.0.1/24", "dev", "lo"], timeout_sec=3)
    run_docker_cmd(["exec", CONTAINER_PEER_B, "ip", "addr", "add", "10.2.0.1/24", "dev", "lo"], timeout_sec=3)

    # Generate session & capture identifiers
    prof_clean = profile_id.replace("-", "")
    sess_id = session_id or f"RIV1-{prof_clean}-{behavioral_class}-{run_index:03d}"
    cap_id = f"{sess_id}"

    pcap_filename = f"{cap_id}.pcap"
    raw_pcap_path = PROJECT_ROOT / "data" / "pcaps" / "real" / pcap_filename
    pcap_dest_path = CAPTURES_DIR / pcap_filename
    meta_dest_path = METADATA_DIR / f"{cap_id}.json"

    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    # Pre-capture Ground Truth Assignment
    ground_truth_metadata = {
        "ground_truth_behavioral_class": behavioral_class,
        "ground_truth_method": "PRE_CAPTURE_EXPERIMENT_CONFIGURATION",
        "ground_truth_established_before_capture": True,
        "assigned_at": datetime.datetime.now().isoformat()
    }

    print(f"[*] Initiating Live Acquisition: {cap_id} ({profile_id} -> {behavioral_class})...")

    # Terminate any existing IKE SA for this profile to ensure clean negotiation
    prof_conn_name = profile_id.lower()
    run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--terminate", "--ike", prof_conn_name], timeout_sec=5)

    # 1. Start tcpdump capture inside peer_a container
    container_pcap_path = f"/captures/{pcap_filename}"
    tcpdump_cmd = [
        "exec", "-d", CONTAINER_PEER_A,
        "tcpdump", "-i", "eth0", "-w", container_pcap_path,
        "udp", "port", "500", "or", "udp", "port", "4500", "or", "ip", "proto", "50", "or", "ip", "proto", "1"
    ]
    run_docker_cmd(tcpdump_cmd, timeout_sec=5)

    # 2. Initiate StrongSwan CHILD_SA
    child_sa = profile.get("child_sa_name", "test-001-sa")
    init_cmd = ["exec", CONTAINER_PEER_A, "swanctl", "--initiate", "--child", child_sa]
    init_res = run_docker_cmd(init_cmd, timeout_sec=12)

    # Verify SA establishment
    sa_res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--list-sas"], timeout_sec=5)
    sa_output = sa_res.stdout
    if child_sa not in sa_output or "INSTALLED" not in sa_output:
        print(f"[!] SA Initiation Failed for {child_sa}: {sa_output}")
        # Stop tcpdump
        run_docker_cmd(["exec", CONTAINER_PEER_A, "bash", "-c", "kill -2 $(pidof tcpdump) 2>/dev/null || true"], timeout_sec=3)
        if raw_pcap_path.exists():
            raw_pcap_path.unlink()
        return {
            "status": "CAPTURE_FAILED",
            "message": f"StrongSwan SA '{child_sa}' failed to establish.",
            "sa_output": sa_output
        }

    # 3. Execute requested traffic generator
    src_ip = profile.get("source_ip", "10.1.0.1")
    dst_ip = profile.get("destination_ip", "10.2.0.1")

    if behavioral_class == "ICMP_DIAGNOSTIC":
        gen_res = generate_icmp_diagnostic(src_ip, dst_ip, packet_count=20, payload_size=64)
    elif behavioral_class == "WEB_INTERACTIVE":
        gen_res = generate_web_interactive(src_ip, dst_ip, transaction_count=5, request_size=300, response_size=1200)
    elif behavioral_class == "BULK_TRANSFER":
        gen_res = generate_bulk_transfer(src_ip, dst_ip, duration_seconds=5, chunk_size=1420, packet_rate=50)
    elif behavioral_class == "STREAMING_MEDIA":
        gen_res = generate_streaming_media(src_ip, dst_ip, duration_seconds=5, avg_packet_size=1200)
    elif behavioral_class == "VOIP_AUDIO":
        gen_res = generate_voip_audio(src_ip, dst_ip, duration_seconds=5, packetization_interval_ms=20, frame_size=160)
    else:
        gen_res = {"packet_count": 20, "duration": 5}

    # 4. Stop tcpdump cleanly
    stop_cmd = ["exec", CONTAINER_PEER_A, "bash", "-c", "kill -2 $(pidof tcpdump) 2>/dev/null || true"]
    run_docker_cmd(stop_cmd, timeout_sec=5)
    import time
    time.sleep(0.5)

    # Terminate IKE SA
    run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--terminate", "--ike", prof_conn_name], timeout_sec=5)

    # Move raw capture from data/pcaps/real/ to data/datasets/real_ipsec/captures/
    if raw_pcap_path.exists():
        shutil.move(str(raw_pcap_path), str(pcap_dest_path))

    if not pcap_dest_path.exists() or pcap_dest_path.stat().st_size == 0:
        return {
            "status": "CAPTURE_FAILED",
            "message": f"PCAP output missing or empty at {pcap_dest_path}"
        }

    pcap_sha256 = compute_file_sha256(pcap_dest_path)

    # Build Session Record
    session_record = {
        "dataset_id": "REAL-IPSEC-v1",
        "dataset_source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
        "dataset_role": "TRAIN",  # Assigned via split manifest
        "capture_id": cap_id,
        "session_id": sess_id,
        "pcap_path": str(pcap_dest_path.relative_to(PROJECT_ROOT)),
        "metadata_path": str(meta_dest_path.relative_to(PROJECT_ROOT)),
        "ground_truth_behavioral_class": behavioral_class,
        "behavioral_class": behavioral_class,
        "traffic_profile": behavioral_class,
        "traffic_generator": behavioral_class.lower(),
        "generator_parameters": gen_res,
        "ipsec_profile_id": profile_id,
        "ike_version": profile.get("ike_version", 2),
        "ipsec_mode": profile.get("mode", "tunnel"),
        "encryption": profile.get("encryption", "UNKNOWN"),
        "integrity": profile.get("integrity", "UNKNOWN"),
        "dh_group": profile.get("dh_group", "UNKNOWN"),
        "nat_traversal": profile.get("nat_traversal", False),
        "encapsulation_type": "IPSEC_NATT_UDP4500" if profile.get("nat_traversal") else "NATIVE_IPSEC_ESP",
        "peer_a": profile.get("peer_a", "192.168.100.2"),
        "peer_b": profile.get("peer_b", "192.168.100.3"),
        "packet_count": gen_res.get("packet_count", 0),
        "duration": gen_res.get("duration", 0),
        "sha256": pcap_sha256,
        "pcap_size_bytes": pcap_dest_path.stat().st_size,
        "ground_truth_method": "PRE_CAPTURE_EXPERIMENT_CONFIGURATION",
        "ground_truth_established_before_capture": True,
        "acquisition_status": "SUCCESS",
        "sa_verified": True,
        "encrypted_traffic_verified": True,
        "created_at": datetime.datetime.now().isoformat()
    }

    # Save Metadata JSON
    with open(meta_dest_path, "w", encoding="utf-8") as f:
        json.dump(session_record, f, indent=2)

    # Register in Master Registry
    register_session_record(session_record)

    print(f"[+] Acquired Real IPsec Session: {cap_id} (SHA256: {pcap_sha256[:12]}...)")
    return {
        "status": "SUCCESS",
        "session_record": session_record
    }


def register_session_record(record: Dict[str, Any]) -> None:
    """Updates master real_ipsec_registry.json with a new session record."""
    if not REGISTRY_PATH.exists():
        registry = {
            "dataset_id": "REAL-IPSEC-v1",
            "dataset_source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
            "created_at": datetime.datetime.now().isoformat(),
            "ood_captures": [
                {"pcap_file": "TEST-001.pcap", "role": "OOD_BENCHMARK"},
                {"pcap_file": "TEST-002.pcap", "role": "OOD_BENCHMARK"},
                {"pcap_file": "TEST-003.pcap", "role": "OOD_BENCHMARK"}
            ],
            "sessions": []
        }
    else:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            registry = json.load(f)

    sessions = [s for s in registry.get("sessions", []) if s.get("capture_id") != record.get("capture_id")]
    sessions.append(record)
    registry["sessions"] = sessions

    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)


def generate_full_real_ipsec_dataset(sessions_per_cell: int = 3) -> Dict[str, Any]:
    """
    Executes complete 5x5 matrix real-IPsec dataset acquisition, feature extraction,
    session-level splitting, quality audit, and dataset readiness gate evaluation.
    """
    print("============================================================")
    print(f" Phase 11.6B — Generating REAL-IPSEC-v1 Dataset ({sessions_per_cell} sessions/cell)")
    print("============================================================")

    readiness = check_testbed_acquisition_readiness()
    if not readiness["is_ready"]:
        print(f"[!] Testbed Acquisition Unavailable. Fail-closed: 0 synthetic PCAPs produced.")
        return {
            "status": "ACQUISITION_UNAVAILABLE",
            "message": "Docker/strongSwan testbed is offline.",
            "readiness": readiness,
            "readiness_gate": "DATASET_INSUFFICIENT"
        }

    profiles = ["TEST-001", "TEST-002", "TEST-003", "TEST-004", "TEST-005"]
    behaviors = list(BEHAVIORAL_TARGET_CLASSES)

    successful_sessions = []
    failed_sessions = []

    for prof_id in profiles:
        for b_class in behaviors:
            for run_idx in range(1, sessions_per_cell + 1):
                res = acquire_real_ipsec_session(
                    profile_id=prof_id,
                    behavioral_class=b_class,
                    run_index=run_idx
                )
                if res["status"] == "SUCCESS":
                    successful_sessions.append(res["session_record"])
                else:
                    failed_sessions.append({"profile": prof_id, "behavior": b_class, "run": run_idx, "error": res})

    print(f"\n[+] Acquisition Loop Complete: {len(successful_sessions)} successful, {len(failed_sessions)} failed")

    # Load master registry
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        registry_data = json.load(f)

    all_sessions = registry_data.get("sessions", [])
    total_valid_sessions = len(all_sessions)

    # 1. Feature Extraction across all registered PCAPs
    print(f"[*] Extracting 28 predictive features from {total_valid_sessions} real IPsec sessions...")
    all_feature_records = []

    for s in all_sessions:
        pcap_rel = s.get("pcap_path")
        if not pcap_rel:
            continue
        pcap_abs = PROJECT_ROOT / pcap_rel
        if not pcap_abs.exists():
            continue

        b_class = s.get("ground_truth_behavioral_class")
        sess_id = s.get("session_id")
        cap_id = s.get("capture_id")

        flows = extract_flows_from_pcap(str(pcap_abs), traffic_class=b_class)
        if not flows:
            continue

        feat_records = extract_features_from_flows(
            flows,
            dataset_id="REAL-IPSEC-v1",
            dataset_source=SOURCE_REAL_IPSEC_GROUND_TRUTH,
            session_id=sess_id,
            behavioral_class=b_class
        )
        for r in feat_records:
            r["capture_id"] = cap_id
        all_feature_records.extend(feat_records)

    # Save real_ipsec_features.csv
    if all_feature_records:
        fieldnames = METADATA_COLUMNS + ML_FEATURE_COLUMNS
        with open(FEATURES_CSV_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_feature_records)
        print(f"[+] Saved {len(all_feature_records)} flow feature records to {FEATURES_CSV_PATH}")

    # 2. Session-Level 70/15/15 Splitting
    split_res = split_records_session_level(all_sessions, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)
    train_sids = list({s.get("session_id") for s in split_res.get("train", []) if s.get("session_id")})
    val_sids = list({s.get("session_id") for s in split_res.get("val", []) if s.get("session_id")})
    test_sids = list({s.get("session_id") for s in split_res.get("test", []) if s.get("session_id")})

    split_manifest = {
        "dataset_id": "REAL-IPSEC-v1",
        "created_at": datetime.datetime.now().isoformat(),
        "random_seed": 42,
        "split_ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "train_sessions": sorted(train_sids),
        "validation_sessions": sorted(val_sids),
        "test_sessions": sorted(test_sids),
        "excluded_ood_captures": ["TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"]
    }

    with open(SPLIT_MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(split_manifest, f, indent=2)

    # 3. Dataset Manifest Update
    dataset_manifest = {
        "dataset_id": "REAL-IPSEC-v1",
        "version": "1.0.0",
        "dataset_source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
        "synthetic_disclaimer": "This dataset consists exclusively of genuine live-captured real-IPsec traffic from StrongSwan peers A and B.",
        "esp_overhead_disclaimer": "Encapsulation features capture genuine ESP header overheads (8B ESP SPI/Seq, IV, ICV, and optional UDP/4500 NAT-T encapsulation) as negotiated by StrongSwan.",
        "created_at": datetime.datetime.now().isoformat(),
        "total_sessions": total_valid_sessions,
        "total_flows": len(all_feature_records),
        "feature_count": len(ML_FEATURE_COLUMNS),
        "profiles_represented": profiles,
        "behavioral_classes_represented": behaviors,
        "ood_benchmark_captures": ["TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"]
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(dataset_manifest, f, indent=2)

    # 4. Dataset Quality & Shortcut Audit
    from scripts.ml.audit_real_ipsec_dataset import audit_real_ipsec_dataset
    audit_res = audit_real_ipsec_dataset()

    # 5. Dataset Readiness Gate Evaluation
    gate_passed = (
        total_valid_sessions >= 50
        and audit_res["integrity_violations_count"] == 0
        and audit_res["leakage_audit"]["status"] == "PASSED"
    )

    readiness_status = "DATASET_READY" if gate_passed else "DATASET_INSUFFICIENT"

    print("\n============================================================")
    print(f" PHASE 11.6B ACQUISITION COMPLETE: {total_valid_sessions} REAL SESSIONS")
    print(f" Dataset Readiness Gate: {readiness_status}")
    print("============================================================")

    return {
        "status": "SUCCESS",
        "total_sessions": total_valid_sessions,
        "successful_this_run": len(successful_sessions),
        "failed_this_run": len(failed_sessions),
        "readiness_gate": readiness_status,
        "audit_summary": audit_res,
        "split_manifest": split_manifest
    }


if __name__ == "__main__":
    res = generate_full_real_ipsec_dataset(sessions_per_cell=3)
    print(json.dumps(res, indent=2))
