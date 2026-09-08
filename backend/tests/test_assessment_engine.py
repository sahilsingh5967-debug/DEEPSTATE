import json
import pytest
from backend.app.analyzers.protocol_analyzer import analyze_pcap
from backend.app.assessment.engine import SecurityAssessmentEngine, assess_analysis_result
from backend.app.models.schemas import (
    AnalysisResult,
    ESPAnalysisDetail,
    IKEAnalysisDetail,
    InferredValue,
    IPsecParameters,
    ModeInferenceDetail,
    ProtocolIdentification,
    SecurityAssessment,
)


def create_mock_analysis_result(
    ike_version="IKEv2",
    encryption_algorithms=None,
    integrity_algorithms=None,
    dh_groups=None,
    pfs_evidence=None,
    has_esp=True
) -> AnalysisResult:
    """Helper factory for creating mock AnalysisResult objects without PCAPs."""
    enc = encryption_algorithms if encryption_algorithms is not None else []
    integ = integrity_algorithms if integrity_algorithms is not None else []
    dh = dh_groups if dh_groups is not None else []

    ev_list = []
    if pfs_evidence:
        ev_list.append(pfs_evidence)

    return AnalysisResult(
        analysis_id="mock-test-001",
        status="completed",
        pcap_metadata={"file_name": "mock.pcap", "packet_count": 10, "file_size_bytes": 1000},
        protocol_identification=ProtocolIdentification(
            ip_versions=["IPv4"],
            protocols_detected=["IKE", "ESP"] if has_esp else ["IKE"],
            has_ike=True,
            has_esp=has_esp
        ),
        ike=IKEAnalysisDetail(
            detected=True,
            version=ike_version,
            initiator_spi="0x1122334455667788",
            encryption_algorithms=enc,
            integrity_algorithms=integ,
            dh_groups=dh
        ),
        esp=ESPAnalysisDetail(
            detected=has_esp,
            spis=["0x0a0b0c0d"] if has_esp else [],
            packet_count=10 if has_esp else 0,
            sequence_numbers=[1, 2, 3, 4, 5] if has_esp else [],
            encapsulation="Direct-ESP"
        ),
        ipsec_parameters=IPsecParameters(
            ike_version=ike_version,
            mode="Tunnel",
            encryption_algorithms=enc,
            integrity_algorithms=integ,
            dh_groups=dh,
            encapsulation="Direct-ESP"
        ),
        mode_inference=ModeInferenceDetail(
            inferred_mode=InferredValue(
                value="Tunnel",
                confidence=0.90,
                evidence=ev_list or ["Mock Tunnel Mode Evidence"]
            )
        )
    )


def test_1_modern_strong_configuration():
    result = create_mock_analysis_result(
        ike_version="IKEv2",
        encryption_algorithms=["AES-256-GCM"],
        integrity_algorithms=["HMAC-SHA2-256-128"],
        dh_groups=["Group 19 (ECP-256)"],
        pfs_evidence="PFS enabled with Group 19"
    )
    assessment = assess_analysis_result(result)
    assert isinstance(assessment, SecurityAssessment)
    assert assessment.security_score >= 95.0
    assert assessment.overall_status == "SECURE"
    assert assessment.failed_checks == 0


def test_2_acceptable_cbc_configuration():
    result = create_mock_analysis_result(
        ike_version="IKEv2",
        encryption_algorithms=["AES-128-CBC"],
        integrity_algorithms=["HMAC-SHA2-256-128"],
        dh_groups=["Group 14 (2048-bit)"],
        pfs_evidence="PFS enabled"
    )
    assessment = assess_analysis_result(result)
    assert assessment.failed_checks == 0
    assert assessment.warning_checks >= 1  # Legacy CBC warning
    assert assessment.security_score < 100.0


def test_3_weak_3des_encryption():
    result = create_mock_analysis_result(
        ike_version="IKEv2",
        encryption_algorithms=["3DES-CBC"],
        integrity_algorithms=["HMAC-SHA1-96"],
        dh_groups=["Group 2 (1024-bit)"]
    )
    assessment = assess_analysis_result(result)
    assert assessment.failed_checks >= 1
    assert assessment.risk_level in ("HIGH", "CRITICAL")
    assert any(f.status == "FAIL" for f in assessment.findings)


def test_4_ikev1_legacy_warning():
    result = create_mock_analysis_result(
        ike_version="IKEv1",
        encryption_algorithms=["AES-256-GCM"],
        dh_groups=["Group 14"]
    )
    assessment = assess_analysis_result(result)
    assert any(f.id == "SEC-PROTO-IKEv1-WARNING" and f.status == "WARNING" for f in assessment.findings)


def test_5_pfs_disabled():
    result = create_mock_analysis_result(
        ike_version="IKEv2",
        pfs_evidence="PFS disabled for child SA"
    )
    assessment = assess_analysis_result(result)
    assert any(f.category == "PERFECT_FORWARD_SECRECY" and f.status == "WARNING" for f in assessment.findings)


def test_6_pfs_unknown_not_fail():
    result = create_mock_analysis_result(pfs_evidence=None)
    assessment = assess_analysis_result(result)
    pfs_findings = [f for f in assessment.findings if f.category == "PERFECT_FORWARD_SECRECY"]
    assert len(pfs_findings) == 1
    assert pfs_findings[0].status == "UNKNOWN"
    assert pfs_findings[0].status != "FAIL"


def test_7_encryption_unknown_not_weak():
    result = create_mock_analysis_result(encryption_algorithms=[])
    assessment = assess_analysis_result(result)
    enc_findings = [f for f in assessment.findings if f.category == "CRYPTOGRAPHY" and "ENC" in f.id]
    assert len(enc_findings) == 1
    assert enc_findings[0].status == "UNKNOWN"
    assert enc_findings[0].status != "FAIL"


def test_8_dh_group_unknown_not_weak():
    result = create_mock_analysis_result(dh_groups=[])
    assessment = assess_analysis_result(result)
    dh_findings = [f for f in assessment.findings if f.category == "KEY_EXCHANGE"]
    assert len(dh_findings) == 1
    assert dh_findings[0].status == "UNKNOWN"
    assert dh_findings[0].status != "FAIL"


def test_9_missing_replay_evidence():
    result = create_mock_analysis_result(has_esp=False)
    assessment = assess_analysis_result(result)
    replay_findings = [f for f in assessment.findings if f.category == "REPLAY_PROTECTION"]
    assert len(replay_findings) == 1
    assert replay_findings[0].status == "NOT_OBSERVED"


def test_10_missing_key_lifetime_evidence():
    result = create_mock_analysis_result()
    assessment = assess_analysis_result(result)
    lifetime_findings = [f for f in assessment.findings if f.category == "KEY_LIFETIME"]
    assert len(lifetime_findings) == 1
    assert lifetime_findings[0].status == "UNKNOWN"


def test_11_metadata_exposure_findings():
    result = create_mock_analysis_result()
    assessment = assess_analysis_result(result)
    meta_findings = [f for f in assessment.findings if f.category == "METADATA_EXPOSURE"]
    assert len(meta_findings) >= 1
    assert all(f.status == "PASS" for f in meta_findings)


def test_12_empty_analysis_result_handling():
    empty_result = AnalysisResult(
        analysis_id="empty-001",
        status="completed",
        pcap_metadata={}
    )
    engine = SecurityAssessmentEngine()
    assessment = engine.assess(empty_result)
    assert isinstance(assessment, SecurityAssessment)
    assert assessment.overall_status == "LIMITED_ASSESSMENT"
    assert assessment.assessment_coverage == 0.0


def test_13_scoring_determinism():
    result = create_mock_analysis_result(
        ike_version="IKEv2",
        encryption_algorithms=["AES-256-GCM"],
        dh_groups=["Group 19"]
    )
    assessment1 = assess_analysis_result(result)
    assessment2 = assess_analysis_result(result)
    assert assessment1.security_score == assessment2.security_score
    assert assessment1.assessment_coverage == assessment2.assessment_coverage
    assert len(assessment1.findings) == len(assessment2.findings)


def test_14_end_to_end_synthetic_pcap_flow():
    # PCAP -> AnalysisResult -> SecurityAssessment
    result = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-001.pcap")
    assessment = assess_analysis_result(result)

    assert isinstance(assessment, SecurityAssessment)
    assert assessment.unknown_checks > 0
    assert assessment.assessment_coverage < 1.0
    assert len(assessment.assessment_warnings) > 0

    # Verify JSON serialization
    json_str = assessment.model_dump_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert "security_score" in parsed
    assert "assessment_coverage" in parsed
