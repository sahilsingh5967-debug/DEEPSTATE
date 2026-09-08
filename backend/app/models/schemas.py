from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InferredValue(BaseModel):
    """
    Structured model for derived/inferred qualitative or categorical values.
    Requires explicit confidence score and supporting observational evidence.
    """
    value: str = Field(..., description="Inferred value (e.g. 'Tunnel', 'Transport', 'Unknown')")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 (uncertain) and 1.0 (certain)"
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Observational evidence from PCAP layers supporting this inference"
    )


class ProtocolIdentification(BaseModel):
    """
    Direct protocol observations extracted from packet headers.
    """
    ip_versions: List[str] = Field(
        default_factory=list,
        description="Observed IP versions ('IPv4', 'IPv6')"
    )
    protocols_detected: List[str] = Field(
        default_factory=list,
        description="List of detected network & transport protocols (e.g. 'IKE', 'ESP', 'AH', 'UDP', 'TCP')"
    )
    has_ike: bool = Field(False, description="True if IKE (UDP 500 / 4500) traffic is detected")
    has_esp: bool = Field(False, description="True if IPsec ESP (IP Proto 50) traffic is detected")
    has_ah: bool = Field(False, description="True if IPsec AH (IP Proto 51) traffic is detected")


class IKEAnalysisDetail(BaseModel):
    """
    Detailed protocol observations extracted from IKE packets.
    """
    detected: bool = Field(False, description="Whether IKE traffic was detected")
    version: Optional[str] = Field(None, description="Observed IKE version ('IKEv1', 'IKEv2', or None)")
    exchange_types: List[str] = Field(
        default_factory=list,
        description="Observed IKE exchange type names (e.g. 'IKE_SA_INIT', 'IKE_AUTH')"
    )
    initiator_spi: Optional[str] = Field(None, description="Observed Initiator SPI (hex)")
    responder_spi: Optional[str] = Field(None, description="Observed Responder SPI (hex)")
    message_ids: List[int] = Field(default_factory=list, description="Observed IKE message IDs")
    proposals: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw SA proposal structures extracted from IKE negotiation payloads"
    )
    dh_groups: List[str] = Field(
        default_factory=list,
        description="Diffie-Hellman groups observed in IKE proposals"
    )
    encryption_algorithms: List[str] = Field(
        default_factory=list,
        description="Encryption algorithms observed in IKE proposals"
    )
    integrity_algorithms: List[str] = Field(
        default_factory=list,
        description="Integrity algorithms observed in IKE proposals"
    )
    prf_algorithms: List[str] = Field(
        default_factory=list,
        description="Pseudo-Random Functions observed in IKE proposals"
    )


class ESPAnalysisDetail(BaseModel):
    """
    Detailed protocol observations extracted from ESP packets.
    """
    detected: bool = Field(False, description="Whether ESP traffic was detected")
    spis: List[str] = Field(
        default_factory=list,
        description="Observed ESP Security Parameter Indices (hex string format 0x...)"
    )
    packet_count: int = Field(0, description="Total count of observed ESP packets")
    sequence_numbers: List[int] = Field(
        default_factory=list,
        description="Sample of observed ESP sequence numbers"
    )
    payload_lengths: List[int] = Field(
        default_factory=list,
        description="Distribution or sample of observed ESP payload lengths in bytes"
    )
    encapsulation: str = Field(
        "Direct-ESP",
        description="Observed encapsulation mode ('Direct-ESP', 'ESP-in-UDP', 'Unknown')"
    )


class AHAnalysisDetail(BaseModel):
    """
    Detailed protocol observations extracted from AH packets.
    """
    detected: bool = Field(False, description="Whether AH traffic was detected")
    spis: List[str] = Field(
        default_factory=list,
        description="Observed AH Security Parameter Indices (hex format)"
    )
    packet_count: int = Field(0, description="Total count of observed AH packets")


class ModeInferenceDetail(BaseModel):
    """
    Inferred VPN Mode (Tunnel vs Transport).
    """
    inferred_mode: InferredValue = Field(
        default_factory=lambda: InferredValue(
            value="Unknown",
            confidence=0.0,
            evidence=["Insufficient evidence in PCAP bytes"]
        ),
        description="Inferred mode details with confidence and evidence"
    )


class TrafficAnalysisDetail(BaseModel):
    """
    Traffic classification analysis based on PCAP inspection.
    """
    inferred_traffic_type: InferredValue = Field(
        default_factory=lambda: InferredValue(
            value="UNKNOWN",
            confidence=0.0,
            evidence=["Payload encrypted or uninspectable"]
        ),
        description="Inferred traffic type"
    )
    observed_layers: List[str] = Field(
        default_factory=list,
        description="All observed packet layer types in PCAP"
    )
    encrypted_payload_only: bool = Field(
        True,
        description="True if traffic payload is encrypted inside ESP and cannot be inspected directly"
    )


class AnalysisRequest(BaseModel):
    source_type: str = Field(
        ...,
        description="Source of traffic: 'pcap_file', 'live_interface', or 'sample'"
    )
    file_path: Optional[str] = Field(
        None,
        description="Absolute or relative path to PCAP file if source_type is 'pcap_file'"
    )
    interface_name: Optional[str] = Field(
        None,
        description="Network interface name if source_type is 'live_interface'"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional configuration options for the analysis"
    )


class IPsecParameters(BaseModel):
    ike_version: Optional[str] = Field(None, description="IKE version (e.g. 'IKEv1', 'IKEv2')")
    mode: Optional[str] = Field(None, description="VPN mode: 'Tunnel', 'Transport', or 'Unknown'")
    encryption_algorithms: List[str] = Field(
        default_factory=list,
        description="Observed encryption algorithms (e.g. 'AES-CBC-256', '3DES')"
    )
    integrity_algorithms: List[str] = Field(
        default_factory=list,
        description="Observed integrity algorithms (e.g. 'HMAC-SHA2-256', 'HMAC-MD5')"
    )
    dh_groups: List[str] = Field(
        default_factory=list,
        description="Diffie-Hellman groups observed (e.g. 'Group 14 (2048-bit)', 'Group 2 (1024-bit)')"
    )
    prf_algorithms: List[str] = Field(
        default_factory=list,
        description="Pseudo-Random Function algorithms observed"
    )
    encapsulation: Optional[str] = Field(
        None,
        description="Observed encapsulation type (e.g. 'ESP-in-UDP', 'Direct-ESP', 'AH')"
    )
    security_associations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Observed Security Association (SA) characteristics"
    )


class SecurityFinding(BaseModel):
    """
    Detailed model for an individual security finding or policy check result.
    """
    id: str = Field(..., description="Unique finding ID (e.g. 'SEC-CRYPTO-001')")
    finding_id: Optional[str] = Field(None, description="Alias for finding ID")
    title: str = Field(..., description="Short title of the finding")
    severity: str = Field(
        ...,
        description="Severity level: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'"
    )
    category: str = Field(
        ...,
        description="Category: e.g. 'CRYPTOGRAPHY', 'PROTOCOL_VERSION', 'KEY_EXCHANGE', 'PERFECT_FORWARD_SECRECY', 'SECURITY_ASSOCIATION', 'METADATA_EXPOSURE', 'REPLAY_PROTECTION'"
    )
    status: str = Field(
        "UNKNOWN",
        description="Assessment status: 'PASS', 'FAIL', 'WARNING', 'UNKNOWN', or 'NOT_OBSERVED'"
    )
    description: str = Field(..., description="Detailed technical description of the finding")
    observed_value: Optional[str] = Field(None, description="Observed parameter value from AnalysisResult")
    expected_value: Optional[str] = Field(None, description="Expected parameter value according to policy")
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Observed evidence supporting the finding"
    )
    rationale: Optional[str] = Field(None, description="Technical rationale explaining why finding matters")
    recommendation: str = Field(..., description="Actionable recommendation to fix or mitigate the issue")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence level of assessment decision")
    references: List[str] = Field(default_factory=list, description="Reference standards or RFCs")
    limitations: Optional[str] = Field(None, description="Limitations of observation (e.g. unobservable parameters)")


class SecurityAssessment(BaseModel):
    """
    Comprehensive security assessment evaluation output.
    Contains overall score, coverage metric, risk status, category breakdown, threat matrix, and findings list.
    """
    security_score: float = Field(
        100.0,
        ge=0.0,
        le=100.0,
        description="Overall security score (0.0 = completely insecure, 100.0 = fully secure)"
    )
    score_confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Confidence level of score calculation based on observation coverage"
    )
    assessment_coverage: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Ratio of evaluated checks (PASS/FAIL/WARNING) over total applicable checks"
    )
    overall_status: str = Field(
        "SECURE",
        description="Overall risk status: 'SECURE', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK', 'LIMITED_ASSESSMENT', or 'UNKNOWN'"
    )
    risk_level: str = Field(
        "LOW",
        description="Overall risk level: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'SECURE'"
    )
    findings: List[SecurityFinding] = Field(
        default_factory=list,
        description="List of detailed security findings"
    )
    passed_checks: int = Field(0, description="Count of PASS checks")
    failed_checks: int = Field(0, description="Count of FAIL checks")
    warning_checks: int = Field(0, description="Count of WARNING checks")
    unknown_checks: int = Field(0, description="Count of UNKNOWN checks")
    category_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Status and score breakdown by category"
    )
    threat_matrix: Dict[str, Any] = Field(
        default_factory=dict,
        description="Risk/Threat matrix mapping severity to impact and likelihood"
    )
    metadata_exposure: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evaluated metadata exposure metrics"
    )
    recommendations_summary: List[str] = Field(
        default_factory=list,
        description="High-level summary of actionable recommendations"
    )
    assessment_warnings: List[str] = Field(
        default_factory=list,
        description="Warnings regarding limited evidence or unobservable parameters"
    )


class TrafficClassification(BaseModel):
    status: str = Field(
        "inferred",
        description="ML classification status: 'inferred', 'unavailable', 'failed', or 'no_flows'"
    )
    dominant_class: str = Field(
        "UNKNOWN",
        description="Inferred dominant traffic class (e.g. 'ICMP', 'Web Browsing', 'VoIP', etc.)"
    )
    detected_type: str = Field(
        "UNKNOWN",
        description="Alias for dominant_class for backward compatibility"
    )
    confidence: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Model confidence score between 0.0 and 1.0"
    )
    class_probabilities: Dict[str, float] = Field(
        default_factory=dict,
        description="Probability distribution across all 8 target traffic classes"
    )
    probabilities: Dict[str, float] = Field(
        default_factory=dict,
        description="Alias for class_probabilities for backward compatibility"
    )
    flow_count: int = Field(
        0,
        description="Total number of network traffic flows evaluated"
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting statistical flow evidence"
    )
    extracted_features: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key statistical features extracted from encrypted traffic"
    )
    model_used: Optional[str] = Field(
        "Random Forest",
        description="Name of ML model used for inference"
    )
    disclaimer: str = Field(
        "This classification is an ML model inference based on encrypted flow statistics and is NOT an observed protocol fact.",
        description="Mandatory disclaimer distinguishing statistical inference from deterministic protocol facts"
    )
    reason: Optional[str] = Field(
        None,
        description="Reason if ML inference status is unavailable or failed"
    )


class AnalysisResult(BaseModel):
    """
    Top-level response object containing complete protocol analysis results.
    """
    analysis_id: str = Field(..., description="Unique ID for this analysis job")
    status: str = Field(
        "pending",
        description="Job status: 'pending', 'processing', 'completed', or 'failed'"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when analysis was generated"
    )
    pcap_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata about analyzed traffic (e.g. packet count, duration, size)"
    )
    protocol_identification: Optional[ProtocolIdentification] = Field(
        None,
        description="Extracted protocol presence indicators"
    )
    ike: Optional[IKEAnalysisDetail] = Field(
        None,
        description="Extracted IKE protocol details"
    )
    esp: Optional[ESPAnalysisDetail] = Field(
        None,
        description="Extracted ESP protocol details"
    )
    ah: Optional[AHAnalysisDetail] = Field(
        None,
        description="Extracted AH protocol details"
    )
    ipsec_parameters: Optional[IPsecParameters] = Field(
        None,
        description="Extracted IPsec & IKE protocol parameters"
    )
    mode_inference: Optional[ModeInferenceDetail] = Field(
        None,
        description="Inferred VPN mode (Tunnel vs Transport) with confidence score"
    )
    traffic_analysis: Optional[TrafficAnalysisDetail] = Field(
        None,
        description="Traffic type inference and layer observation"
    )
    security_assessment: Optional[SecurityAssessment] = Field(
        None,
        description="Security strength assessment results (Phase 4)"
    )
    traffic_classification: Optional[TrafficClassification] = Field(
        None,
        description="ML-based traffic classification results (Phase 5)"
    )
    analysis_warnings: List[str] = Field(
        default_factory=list,
        description="Warnings regarding packet parsing or unobservable fields"
    )
    errors: List[str] = Field(
        default_factory=list,
        description="List of error messages encountered during analysis"
    )


class HealthResponse(BaseModel):
    status: str = Field("ok", description="Operational status of backend")
    version: str = Field(..., description="Backend application version")
    timestamp: str = Field(..., description="Server timestamp")
