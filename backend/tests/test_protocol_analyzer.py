import json
from backend.app.analyzers.protocol_analyzer import analyze_pcap
from backend.app.models.schemas import AnalysisResult


def test_analyze_synth_test_001():
    result = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-001.pcap")
    assert isinstance(result, AnalysisResult)
    assert result.status == "completed"
    assert result.pcap_metadata["packet_count"] == 11

    # Check Protocol Identification
    assert result.protocol_identification is not None
    assert result.protocol_identification.has_ike is True
    assert result.protocol_identification.has_esp is True
    assert "IPv4" in result.protocol_identification.ip_versions

    # Check IKE Details
    assert result.ike is not None
    assert result.ike.detected is True
    assert result.ike.version == "IKEv2"
    assert "IKE_SA_INIT" in result.ike.exchange_types
    assert result.ike.initiator_spi is not None

    # Check ESP Details
    assert result.esp is not None
    assert result.esp.detected is True
    assert result.esp.packet_count == 10
    assert "0x0a0b0c0d" in result.esp.spis
    assert result.esp.encapsulation == "Direct-ESP"

    # Check Mode Inference (Deterministic & Evidence-based)
    assert result.mode_inference is not None
    assert result.mode_inference.inferred_mode.value in ("Unknown", "Tunnel", "Transport")
    assert isinstance(result.mode_inference.inferred_mode.confidence, float)
    assert len(result.mode_inference.inferred_mode.evidence) > 0

    # Check Traffic Analysis
    assert result.traffic_analysis is not None
    assert result.traffic_analysis.encrypted_payload_only is True

    # Check Analysis Warnings
    assert isinstance(result.analysis_warnings, list)


def test_analyze_synth_test_002():
    result = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-002.pcap")
    assert result.status == "completed"
    assert result.protocol_identification.has_ike is True
    assert result.protocol_identification.has_esp is True
    assert result.esp.packet_count == 10


def test_analyze_synth_test_003():
    result = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-003.pcap")
    assert result.status == "completed"
    assert result.protocol_identification.has_ike is True
    assert result.protocol_identification.has_esp is True
    assert result.esp.packet_count == 10


def test_determinism():
    """Verify multiple executions on the same PCAP yield identical results."""
    res1 = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-001.pcap")
    res2 = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-001.pcap")

    assert res1.protocol_identification == res2.protocol_identification
    assert res1.ike.version == res2.ike.version
    assert res1.ike.initiator_spi == res2.ike.initiator_spi
    assert res1.esp.spis == res2.esp.spis
    assert res1.mode_inference.inferred_mode.value == res2.mode_inference.inferred_mode.value


def test_json_serialization():
    result = analyze_pcap("data/pcaps/synthetic/SYNTH-TEST-001.pcap")
    json_str = result.model_dump_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["analysis_id"] == result.analysis_id
    assert parsed["status"] == "completed"
