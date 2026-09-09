import pytest
import os
import json
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

TEST_PCAP_PATH = "data/pcaps/real/TEST-001.pcap"


def test_phase8_health_endpoint():
    """Verify backend health endpoint for Phase 8."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ("ok", "healthy")


def test_phase8_pcaps_listing_endpoint():
    """Verify available PCAPs listing endpoint for Phase 8 demonstration."""
    response = client.get("/api/v1/pcaps")
    assert response.status_code == 200
    pcaps = response.json()
    assert isinstance(pcaps, list)
    assert len(pcaps) > 0

    pcap_paths = [p.get("file_path", "") for p in pcaps]
    assert any("TEST-001.pcap" in path for path in pcap_paths)
    assert any("TEST-002.pcap" in path for path in pcap_paths)
    assert any("TEST-003.pcap" in path for path in pcap_paths)


def test_phase8_unified_analysis_schema_and_tiers():
    """Verify 3-tier analysis schema for Phase 8 demonstration."""
    assert os.path.exists(TEST_PCAP_PATH)
    response = client.post("/api/v1/analyze", json={"source_type": "pcap_file", "file_path": TEST_PCAP_PATH})
    assert response.status_code == 200
    result = response.json()

    # Base Fields
    assert "analysis_id" in result
    assert "pcap_metadata" in result

    # Tier A: Observed Facts
    assert "protocol_identification" in result
    assert "ike" in result
    assert "esp" in result
    assert "mode_inference" in result

    # Tier B: Security Assessment
    assert "security_assessment" in result
    sec = result["security_assessment"]
    assert "security_score" in sec
    assert "overall_status" in sec
    assert "findings" in sec
    assert isinstance(sec["findings"], list)

    # Tier C: ML Classification & Mandatory Disclaimer
    assert "traffic_classification" in result
    ml = result["traffic_classification"]
    assert ml["status"] == "inferred"
    assert "dominant_class" in ml
    assert "confidence" in ml
    assert "class_probabilities" in ml
    assert len(ml["class_probabilities"]) == 8

    # Mandatory Disclaimer Verification
    assert "disclaimer" in ml
    assert ml["disclaimer"] == "This classification is an ML model inference based on encrypted flow statistics and is NOT an observed protocol fact."


def test_phase8_report_export_json_payload_format():
    """Verify JSON report export payload structure matches AnalysisResult schema."""
    response = client.post("/api/v1/analyze", json={"source_type": "pcap_file", "file_path": TEST_PCAP_PATH})
    assert response.status_code == 200
    result = response.json()

    # Serialize and deserialize to verify JSON export validity
    json_bytes = json.dumps(result, indent=2).encode('utf-8')
    exported_data = json.loads(json_bytes.decode('utf-8'))

    assert exported_data["analysis_id"] == result["analysis_id"]
    assert exported_data["security_assessment"]["security_score"] == result["security_assessment"]["security_score"]
    assert exported_data["traffic_classification"]["dominant_class"] == result["traffic_classification"]["dominant_class"]
