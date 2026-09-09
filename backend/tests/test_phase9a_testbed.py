"""
Automated Pytest Suite for Phase 9A-1 — DEEPSTATE Demonstration Lab & Testbed Integration.
Verifies profile registries, API schemas, capture execution metadata, and ground-truth PCAP isolation.
"""

import os
import hashlib
from pathlib import Path

# Disable Scapy resolv reading before importing scapy
os.environ["SCAPY_USE_NETIFACES"] = "0"
try:
    from scapy.config import conf
    conf.read_resolv_conf = False
except Exception:
    pass

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from scripts.testbed.profile_registry import (
    get_all_profiles, get_profile, get_all_traffic_profiles, get_traffic_profile
)
from scripts.testbed.profile_runner import get_testbed_status
from scripts.testbed.capture_manager import execute_testbed_capture


client = TestClient(app)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def get_file_md5(filepath: Path) -> str:
    """Computes MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(filepath, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def test_profile_registry_functions():
    """Verifies that IPsec profile registry returns expected metadata."""
    profiles = get_all_profiles()
    assert len(profiles) >= 3
    profile_ids = [p["profile_id"] for p in profiles]
    assert "TEST-001" in profile_ids
    assert "TEST-002" in profile_ids
    assert "TEST-003" in profile_ids

    test_001 = get_profile("TEST-001")
    assert test_001 is not None
    assert test_001["encryption"] == "AES-128-CBC"
    assert test_001["mode"] == "tunnel"

    test_002 = get_profile("TEST-002")
    assert test_002 is not None
    assert test_002["encryption"] == "AES-256-GCM"


def test_traffic_profile_registry_functions():
    """Verifies that traffic profile registry defines ICMP, UDP, TCP."""
    traffic_profs = get_all_traffic_profiles()
    assert len(traffic_profs) >= 3
    t_ids = [t["traffic_profile_id"] for t in traffic_profs]
    assert "ICMP" in t_ids
    assert "UDP" in t_ids
    assert "TCP" in t_ids

    udp_prof = get_traffic_profile("UDP")
    assert udp_prof is not None
    assert udp_prof["supports_custom_port"] is True


def test_testbed_api_endpoints():
    """Tests GET /api/v1/testbed/profiles, traffic-profiles, and status."""
    # 1. Profiles
    res_prof = client.get("/api/v1/testbed/profiles")
    assert res_prof.status_code == 200
    data_prof = res_prof.json()
    assert isinstance(data_prof, list)
    assert any(p["profile_id"] == "TEST-001" for p in data_prof)

    # 2. Traffic Profiles
    res_traffic = client.get("/api/v1/testbed/traffic-profiles")
    assert res_traffic.status_code == 200
    data_traffic = res_traffic.json()
    assert isinstance(data_traffic, list)
    assert any(t["traffic_profile_id"] == "UDP" for t in data_traffic)

    # 3. Status
    res_status = client.get("/api/v1/testbed/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert "docker_available" in data_status
    assert "peer_a_status" in data_status
    assert "peer_b_status" in data_status


def test_testbed_api_capture_validation():
    """Tests POST /api/v1/testbed/capture error handling for invalid profiles."""
    # Invalid profile
    res_invalid_p = client.post("/api/v1/testbed/capture", json={
        "profile_id": "INVALID-999",
        "traffic_profile": "ICMP",
        "duration": 5,
        "packet_count": 10
    })
    assert res_invalid_p.status_code == 400
    assert "Invalid or unregistered profile_id" in res_invalid_p.json()["detail"]

    # Invalid traffic profile
    res_invalid_t = client.post("/api/v1/testbed/capture", json={
        "profile_id": "TEST-001",
        "traffic_profile": "INVALID_TRAFFIC",
        "duration": 5,
        "packet_count": 10
    })
    assert res_invalid_t.status_code == 400
    assert "Invalid or unregistered traffic_profile" in res_invalid_t.json()["detail"]


def test_testbed_api_capture_execution():
    """Tests POST /api/v1/testbed/capture producing valid PCAP metadata."""
    payload = {
        "profile_id": "TEST-002",
        "traffic_profile": "UDP",
        "duration": 2,
        "packet_count": 5,
        "port": 5001
    }
    res = client.post("/api/v1/testbed/capture", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "completed"
    assert data["profile_id"] == "TEST-002"
    assert data["traffic_profile"] == "UDP"
    assert "file_path" in data
    assert data["file_path"].startswith("data/pcaps/generated/")
    assert data["packet_count"] >= 1
    assert data["size_bytes"] > 0

    # Pass generated PCAP to /api/v1/analyze to verify seamless handoff
    analyze_res = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": data["file_path"]
    })
    assert analyze_res.status_code == 200
    anal_data = analyze_res.json()
    assert "protocol_identification" in anal_data
    assert "security_assessment" in anal_data
    assert "traffic_classification" in anal_data


def test_ground_truth_pcap_isolation():
    """Verifies that ground-truth PCAPs in data/pcaps/real/ are never modified."""
    real_dir = PROJECT_ROOT / "data" / "pcaps" / "real"
    gt_files = ["TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"]

    initial_hashes = {}
    for filename in gt_files:
        filepath = real_dir / filename
        if filepath.exists():
            initial_hashes[filename] = get_file_md5(filepath)

    # Execute a capture session
    execute_testbed_capture("TEST-001", "ICMP", duration=1, packet_count=5)

    for filename, initial_hash in initial_hashes.items():
        filepath = real_dir / filename
        assert filepath.exists()
        current_hash = get_file_md5(filepath)
        assert current_hash == initial_hash, f"Ground truth file {filename} was modified!"
