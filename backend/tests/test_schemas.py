from datetime import datetime
from backend.app.models.schemas import (
    AnalysisRequest,
    AnalysisResult,
    HealthResponse,
    IPsecParameters,
    SecurityAssessment,
    SecurityFinding,
    TrafficClassification,
)


def test_analysis_request_schema():
    req = AnalysisRequest(
        source_type="pcap_file",
        file_path="/data/pcaps/sample.pcap",
        options={"filter": "esp"}
    )
    assert req.source_type == "pcap_file"
    assert req.file_path == "/data/pcaps/sample.pcap"
    assert req.options["filter"] == "esp"


def test_ipsec_parameters_schema():
    params = IPsecParameters(
        ike_version="IKEv2",
        mode="Tunnel",
        encryption_algorithms=["AES-CBC-256"],
        integrity_algorithms=["HMAC-SHA2-256"],
        dh_groups=["Group 14 (2048-bit)"]
    )
    assert params.ike_version == "IKEv2"
    assert params.mode == "Tunnel"
    assert "AES-CBC-256" in params.encryption_algorithms


def test_security_finding_and_assessment_schemas():
    finding = SecurityFinding(
        id="SEC-001",
        title="Weak DH Group",
        severity="HIGH",
        category="WEAK_CRYPTO",
        description="Diffie-Hellman Group 2 is deprecated",
        recommendation="Upgrade to DH Group 14 or higher"
    )
    assessment = SecurityAssessment(
        security_score=75.0,
        risk_level="MEDIUM",
        findings=[finding],
        recommendations_summary=["Upgrade DH Group"]
    )
    assert assessment.security_score == 75.0
    assert len(assessment.findings) == 1
    assert assessment.findings[0].id == "SEC-001"


def test_traffic_classification_schema():
    classification = TrafficClassification(
        detected_type="VOIP",
        confidence=0.92,
        probabilities={"VOIP": 0.92, "WEB_HTTPS": 0.08}
    )
    assert classification.detected_type == "VOIP"
    assert classification.confidence == 0.92


def test_analysis_result_schema():
    result = AnalysisResult(
        analysis_id="test-123",
        status="completed",
        timestamp=datetime.utcnow(),
        ipsec_parameters=IPsecParameters(ike_version="IKEv2"),
        security_assessment=SecurityAssessment(security_score=90.0),
        traffic_classification=TrafficClassification(detected_type="HTTPS")
    )
    assert result.analysis_id == "test-123"
    assert result.status == "completed"
    assert result.ipsec_parameters.ike_version == "IKEv2"
    assert result.security_assessment.security_score == 90.0
    assert result.traffic_classification.detected_type == "HTTPS"
