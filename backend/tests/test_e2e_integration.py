"""
Phase 6 End-to-End System Integration & Validation Test Suite.
AI-Powered IPsec VPN Protocol Analyzer.

Verifies:
1. Backend app startup & /health endpoint.
2. GET /api/v1/pcaps endpoint returns available presets.
3. POST /api/v1/analyze returns HTTP 200 success.
4. Response matches AnalysisResult Pydantic schema.
5. Protocol identification details present (observed facts).
6. Security assessment details present (Phase 4 policy evaluation).
7. Traffic classification details present (Phase 5 ML inference).
8. ML probabilities contain all 8 target classes.
9. ML probabilities sum approximately to 1.0.
10. ML confidence is bounded between 0 and 1.
11. ML disclaimer is present with exact policy notice.
12. Deterministic facts remain separate from ML inferences.
13. Missing PCAP path returns controlled HTTP 404 error.
14. Missing ML artifact does not break deterministic analysis.
15. TEST-001 end-to-end unified response verification.
16. TEST-002 end-to-end unified response verification.
17. TEST-003 end-to-end unified response verification.
18. Zero forbidden predictive identifiers in feature matrix.
"""

from pathlib import Path
import json
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.ml.evaluator import TARGET_CLASSES
from backend.app.ml.features import ML_FEATURE_COLUMNS
from backend.app.ml.splitting import FORBIDDEN_PREDICTIVE_IDENTIFIERS

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_PCAPS_DIR = PROJECT_ROOT / "data" / "pcaps" / "real"
SYNTH_PCAPS_DIR = PROJECT_ROOT / "data" / "pcaps" / "synthetic"

client = TestClient(app)


def test_e2e_1_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_e2e_2_list_available_pcaps_endpoint():
    response = client.get("/api/v1/pcaps")
    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) >= 3
    names = [i["id"] for i in items]
    assert "TEST-001.pcap" in names
    assert "TEST-002.pcap" in names
    assert "TEST-003.pcap" in names


def test_e2e_3_post_analyze_http_success():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"


def test_e2e_4_response_conforms_to_analysis_result():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    assert "analysis_id" in data
    assert "pcap_metadata" in data
    assert "protocol_identification" in data
    assert "security_assessment" in data
    assert "traffic_classification" in data


def test_e2e_5_protocol_identification_facts_present():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    proto = data["protocol_identification"]
    assert proto["has_ike"] is True
    assert proto["has_esp"] is True
    assert "IPv4" in proto["ip_versions"]


def test_e2e_6_security_assessment_present():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    sec = data["security_assessment"]
    assert 0.0 <= sec["security_score"] <= 100.0
    assert sec["overall_status"] in ("SECURE", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL_RISK", "LIMITED_ASSESSMENT")


def test_e2e_7_traffic_classification_present():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    ml = data["traffic_classification"]
    assert ml["status"] in ("inferred", "no_flows")
    assert ml["dominant_class"] in TARGET_CLASSES


def test_e2e_8_all_8_target_classes_in_probabilities():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    probs = data["traffic_classification"]["class_probabilities"]
    assert len(probs) == 8
    for cname in TARGET_CLASSES:
        assert cname in probs


def test_e2e_9_probabilities_sum_approximately_to_1():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    probs = data["traffic_classification"]["class_probabilities"]
    total_p = sum(probs.values())
    assert abs(total_p - 1.0) < 0.02, f"Probabilities sum to {total_p}"


def test_e2e_10_confidence_bounded_0_to_1():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    conf = data["traffic_classification"]["confidence"]
    assert 0.0 <= conf <= 1.0


def test_e2e_11_ml_disclaimer_present():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()
    disclaimer = data["traffic_classification"]["disclaimer"]
    assert "NOT an observed protocol fact" in disclaimer


def test_e2e_12_fact_vs_inference_separation():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    data = response.json()

    # Fact: Scapy observed ESP
    assert data["protocol_identification"]["has_esp"] is True

    # Inference: ML statistical prediction
    assert data["traffic_classification"]["status"] == "inferred"
    assert data["traffic_classification"]["dominant_class"] in TARGET_CLASSES


def test_e2e_13_missing_pcap_returns_404():
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": "data/pcaps/nonexistent_sample.pcap"
    })
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()


def test_e2e_14_missing_ml_artifact_fault_tolerance(monkeypatch):
    import backend.app.ml.inference as ml_inf
    monkeypatch.setattr(ml_inf, "FINAL_MODEL_PATH", Path("/tmp/nonexistent_model.pkl"))

    pcap_path = SYNTH_PCAPS_DIR / "SYNTH-TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["protocol_identification"] is not None
    assert data["security_assessment"] is not None
    assert data["traffic_classification"]["status"] == "unavailable"


def test_e2e_15_test_001_unified_response():
    pcap_path = REAL_PCAPS_DIR / "TEST-001.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pcap_metadata"]["packet_count"] == 19
    assert data["security_assessment"]["security_score"] == 90.0
    assert data["traffic_classification"]["flow_count"] == 4


def test_e2e_16_test_002_unified_response():
    pcap_path = REAL_PCAPS_DIR / "TEST-002.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pcap_metadata"]["packet_count"] == 16
    assert data["security_assessment"]["security_score"] == 90.0
    assert data["traffic_classification"]["flow_count"] == 4


def test_e2e_17_test_003_unified_response():
    pcap_path = REAL_PCAPS_DIR / "TEST-003.pcap"
    response = client.post("/api/v1/analyze", json={
        "source_type": "pcap_file",
        "file_path": str(pcap_path)
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pcap_metadata"]["packet_count"] >= 10
    assert data["security_assessment"]["security_score"] == 90.0
    assert data["traffic_classification"]["flow_count"] >= 1


def test_e2e_18_zero_forbidden_predictive_identifiers():
    for forbidden in FORBIDDEN_PREDICTIVE_IDENTIFIERS:
        assert forbidden not in ML_FEATURE_COLUMNS, f"Forbidden identifier {forbidden} found in features!"
