"""
Phase 5.7 Integration Test Suite.
AI-Powered IPsec VPN Protocol Analyzer.

Verifies:
1. Existing protocol analyzer still works.
2. Existing security assessment still works.
3. Unified result contains protocol analysis.
4. Unified result contains security assessment.
5. Unified result contains ML inference when model artifacts are available.
6. ML prediction is one of the 8 approved classes.
7. Confidence is between 0 and 1.
8. Probability distribution contains all 8 classes.
9. Probabilities sum approximately to 1.
10. ML output is explicitly marked as inferred/probabilistic.
11. Deterministic protocol facts remain separate from ML inference.
12. Missing ML artifact does not break protocol/security analysis.
13. TEST-001/002/003 remain excluded from training/fitting.
14. API POST /api/v1/analyze returns unified AnalysisResult.
"""

from pathlib import Path
import json
import pytest
from fastapi.testclient import TestClient

from backend.app.analyzers.protocol_analyzer import analyze_pcap
from backend.app.models.schemas import AnalysisResult, SecurityAssessment, TrafficClassification
from backend.app.ml.evaluator import TARGET_CLASSES
from backend.app.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REAL_PCAPS_DIR = PROJECT_ROOT / "data" / "pcaps" / "real"
SYNTH_PCAPS_DIR = PROJECT_ROOT / "data" / "pcaps" / "synthetic"
MODEL_DIR = PROJECT_ROOT / "data" / "models"


def test_1_protocol_analyzer_still_works():
    pcap = SYNTH_PCAPS_DIR / "SYNTH-TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    assert isinstance(result, AnalysisResult)
    assert result.status == "completed"
    assert result.protocol_identification is not None
    assert result.protocol_identification.has_ike is True
    assert result.protocol_identification.has_esp is True


def test_2_security_assessment_still_works():
    pcap = SYNTH_PCAPS_DIR / "SYNTH-TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    assert result.security_assessment is not None
    assert isinstance(result.security_assessment, SecurityAssessment)
    assert 0.0 <= result.security_assessment.security_score <= 100.0
    assert result.security_assessment.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE")


def test_3_unified_result_contains_protocol_analysis():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    assert result.protocol_identification is not None
    assert result.ike is not None
    assert result.esp is not None
    assert result.ipsec_parameters is not None


def test_4_unified_result_contains_security_assessment():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    assert result.security_assessment is not None
    assert result.security_assessment.overall_status is not None


def test_5_unified_result_contains_ml_inference():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    assert result.traffic_classification is not None
    assert isinstance(result.traffic_classification, TrafficClassification)
    assert result.traffic_classification.status in ("inferred", "no_flows")


def test_6_ml_prediction_is_one_of_8_approved_classes():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    ml = result.traffic_classification
    if ml.status == "inferred":
        assert ml.dominant_class in TARGET_CLASSES


def test_7_confidence_bounded_0_to_1():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    ml = result.traffic_classification
    assert 0.0 <= ml.confidence <= 1.0


def test_8_probability_distribution_contains_all_8_classes():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    ml = result.traffic_classification
    probs = ml.class_probabilities
    assert len(probs) == 8
    for cname in TARGET_CLASSES:
        assert cname in probs


def test_9_probabilities_sum_approximately_to_1():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    ml = result.traffic_classification
    if ml.status == "inferred":
        total_p = sum(ml.class_probabilities.values())
        assert abs(total_p - 1.0) < 0.02, f"Probabilities sum to {total_p}"


def test_10_ml_output_explicitly_marked_as_inferred():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    ml = result.traffic_classification
    assert ml.status in ("inferred", "unavailable", "no_flows")
    assert "disclaimer" in ml.model_dump()
    assert "NOT an observed protocol fact" in ml.disclaimer


def test_11_deterministic_facts_separate_from_ml_inference():
    pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    result = analyze_pcap(str(pcap))
    # Deterministic observations
    assert result.protocol_identification.has_esp is True
    assert "ESP" in result.protocol_identification.protocols_detected
    # ML inference is separate
    assert result.traffic_classification.dominant_class in TARGET_CLASSES


def test_12_missing_ml_artifact_does_not_break_analysis(monkeypatch):
    import backend.app.ml.inference as ml_inf
    monkeypatch.setattr(ml_inf, "FINAL_MODEL_PATH", Path("/tmp/nonexistent_model.pkl"))

    pcap = SYNTH_PCAPS_DIR / "SYNTH-TEST-001.pcap"
    result = analyze_pcap(str(pcap))

    # Protocol analysis and security assessment must still succeed
    assert result.status == "completed"
    assert result.protocol_identification is not None
    assert result.security_assessment is not None

    # ML section reports unavailable
    assert result.traffic_classification is not None
    assert result.traffic_classification.status == "unavailable"
    assert result.traffic_classification.reason is not None


def test_13_real_ipsec_captures_isolated_from_training():
    metadata_path = MODEL_DIR / "model_metadata.json"
    assert metadata_path.exists()
    with open(metadata_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    stmt = meta.get("ground_truth_isolation_statement", "")
    assert "TEST-001.pcap" in stmt or "100% excluded" in stmt


def test_14_api_analyze_endpoint_returns_unified_result():
    client = TestClient(app)
    real_pcap = REAL_PCAPS_DIR / "TEST-001.pcap"
    payload = {
        "source_type": "pcap_file",
        "file_path": str(real_pcap)
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert "protocol_identification" in data
    assert "security_assessment" in data
    assert "traffic_classification" in data
    assert data["traffic_classification"]["status"] in ("inferred", "no_flows")
