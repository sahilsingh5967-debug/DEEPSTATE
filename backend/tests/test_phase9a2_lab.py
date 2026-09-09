"""
Automated Pytest Suite for Phase 9A-2 — Demonstration Lab 2.0 (Operator-Controlled IPsec Experimentation).
Verifies configuration options, experiment validation, custom execution, history logging, and ground-truth isolation.
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
from scripts.testbed.experiment_model import (
    CONFIG_OPTIONS, EXPERIMENT_PRESETS, ExperimentConfig, validate_experiment_config
)
from scripts.testbed.experiment_history import list_experiments, save_experiment_record


client = TestClient(app)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def get_file_md5(filepath: Path) -> str:
    """Computes MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(filepath, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def test_config_options_endpoint():
    """Verifies GET /api/v1/testbed/config/options schema and contents."""
    res = client.get("/api/v1/testbed/config/options")
    assert res.status_code == 200
    data = res.json()

    assert "options" in data
    assert "presets" in data
    assert "educational_kb" in data

    options = data["options"]
    assert "encryptions" in options
    assert "modes" in options
    assert "dh_groups" in options
    assert "traffic_types" in options

    # Verify presets contain expected entries
    preset_ids = [p["preset_id"] for p in data["presets"]]
    assert "SECURE_ENTERPRISE" in preset_ids
    assert "LEGACY_VPN" in preset_ids
    assert "TRANSPORT_MODE" in preset_ids
    assert "VOIP_LIKE" in preset_ids
    assert "WEB_LIKE" in preset_ids


def test_experiment_validation_logic():
    """Verifies POST /api/v1/testbed/validate for valid and invalid configurations."""
    # Valid AEAD configuration
    valid_cfg = {
        "name": "Test Valid Experiment",
        "mode": "tunnel",
        "encryption": "AES-256-GCM",
        "integrity": "NONE",
        "dh_group": "ECP256",
        "traffic_type": "WEB",
        "destination_port": 443,
        "packet_count": 20,
        "packet_rate": 10,
        "payload_size": 512,
        "duration": 5,
        "execution_mode": "synthetic"
    }
    res_val = client.post("/api/v1/testbed/validate", json=valid_cfg)
    assert res_val.status_code == 200
    assert res_val.json()["valid"] is True

    # Invalid CBC configuration without integrity
    invalid_cfg = {
        "name": "Invalid Experiment",
        "mode": "tunnel",
        "encryption": "AES-128-CBC",
        "integrity": "NONE",  # Error: CBC requires integrity
        "dh_group": "MODP2048",
        "traffic_type": "UDP",
        "destination_port": 5001,
        "packet_count": 20,
        "duration": 5,
        "execution_mode": "synthetic"
    }
    res_inval = client.post("/api/v1/testbed/validate", json=invalid_cfg)
    assert res_inval.status_code == 200
    val_data = res_inval.json()
    assert val_data["valid"] is False
    assert len(val_data["errors"]) > 0


def test_custom_experiment_execution_and_history():
    """Verifies POST /api/v1/testbed/experiment execution and history logging."""
    exp_payload = {
        "name": "Operator Custom Web Experiment",
        "mode": "tunnel",
        "encryption": "AES-256-GCM",
        "integrity": "NONE",
        "dh_group": "ECP256",
        "traffic_type": "WEB",
        "destination_port": 443,
        "packet_count": 15,
        "packet_rate": 10,
        "payload_size": 800,
        "duration": 2,
        "execution_mode": "synthetic"
    }

    res = client.post("/api/v1/testbed/experiment", json=exp_payload)
    assert res.status_code == 200
    data = res.json()

    assert "experiment_id" in data
    assert data["experiment_id"].startswith("EXP-")
    assert "file_path" in data
    assert data["file_path"].startswith("data/pcaps/generated/")
    assert data["packet_count"] >= 1
    assert data["size_bytes"] > 0

    exp_id = data["experiment_id"]

    # Verify experiment appears in GET /api/v1/testbed/experiments
    res_hist = client.get("/api/v1/testbed/experiments")
    assert res_hist.status_code == 200
    history = res_hist.json()
    assert isinstance(history, list)
    assert any(h["experiment_id"] == exp_id for h in history)

    # Verify single experiment GET /api/v1/testbed/experiments/{id}
    res_single = client.get(f"/api/v1/testbed/experiments/{exp_id}")
    assert res_single.status_code == 200
    assert res_single.json()["experiment_id"] == exp_id

    # Test POST /api/v1/testbed/experiments/{id}/analyze handoff
    res_anal = client.post(f"/api/v1/testbed/experiments/{exp_id}/analyze")
    assert res_anal.status_code == 200
    anal_data = res_anal.json()

    assert "protocol_identification" in anal_data
    assert "security_assessment" in anal_data
    assert "traffic_classification" in anal_data


def test_ground_truth_pcap_isolation_phase9a2():
    """Verifies that ground-truth PCAPs in data/pcaps/real/ are never modified during experiments."""
    real_dir = PROJECT_ROOT / "data" / "pcaps" / "real"
    gt_files = ["TEST-001.pcap", "TEST-002.pcap", "TEST-003.pcap"]

    initial_hashes = {}
    for filename in gt_files:
        filepath = real_dir / filename
        if filepath.exists():
            initial_hashes[filename] = get_file_md5(filepath)

    # Execute custom experiment
    exp_payload = {
        "name": "Isolation Test Experiment",
        "mode": "transport",
        "encryption": "AES-128-CBC",
        "integrity": "SHA256",
        "dh_group": "MODP2048",
        "traffic_type": "ICMP",
        "destination_port": 5001,
        "packet_count": 5,
        "duration": 1,
        "execution_mode": "synthetic"
    }
    client.post("/api/v1/testbed/experiment", json=exp_payload)

    for filename, initial_hash in initial_hashes.items():
        filepath = real_dir / filename
        assert filepath.exists()
        current_hash = get_file_md5(filepath)
        assert current_hash == initial_hash, f"Ground truth file {filename} was modified!"
