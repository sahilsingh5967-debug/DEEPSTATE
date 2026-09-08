from typing import List
from backend.app.assessment.policies import AssessmentPolicy
from backend.app.models.schemas import AnalysisResult, SecurityFinding


def evaluate_metadata_exposure(result: AnalysisResult, policy: AssessmentPolicy) -> List[SecurityFinding]:
    """
    Evaluates observable metadata exposure (outer IP endpoints, packet sizing, timing, encapsulation).
    Explains metadata exposure objectively without exaggerating risk.
    """
    findings: List[SecurityFinding] = []

    pcap_meta = result.pcap_metadata or {}
    pkt_count = pcap_meta.get("packet_count", 0)
    file_size = pcap_meta.get("file_size_bytes", 0)
    duration = pcap_meta.get("duration_seconds", 0.0)

    # 1. Endpoint IP Exposure Finding
    findings.append(
        SecurityFinding(
            id="SEC-META-ENDPOINT-EXPOSURE",
            finding_id="SEC-META-ENDPOINT-EXPOSURE",
            title="Outer IP Gateway Endpoints Exposed",
            severity="INFO",
            category="METADATA_EXPOSURE",
            status="PASS",
            description="Outer IP header source and destination addresses are exposed on the network layer.",
            observed_value="Outer IPv4/IPv6 Headers Visible",
            expected_value="Visible Outer IP Headers (Inherent to IPsec)",
            evidence={
                "ip_versions": result.protocol_identification.ip_versions if result.protocol_identification else [],
                "protocols": result.protocol_identification.protocols_detected if result.protocol_identification else [],
            },
            rationale="Outer IP headers are inherently visible to network routers for packet delivery. While payload contents are encrypted, adversary passive observers can identify communicating gateway IP addresses.",
            recommendation="Consider network-level topology obfuscation or NAT-T encapsulation if gateway IP privacy is required.",
            confidence=1.0,
            references=["RFC 4301 Section 3.1"],
        )
    )

    # 2. Traffic Flow & Volume Metadata Exposure Finding
    if pkt_count > 0:
        findings.append(
            SecurityFinding(
                id="SEC-META-FLOW-PATTERN-EXPOSURE",
                finding_id="SEC-META-FLOW-PATTERN-EXPOSURE",
                title="Traffic Volume and Frequency Patterns Observable",
                severity="INFO",
                category="METADATA_EXPOSURE",
                status="PASS",
                description=f"Observed {pkt_count} packets ({file_size} bytes) over {duration}s duration.",
                observed_value=f"Packets: {pkt_count}, Size: {file_size} bytes, Duration: {duration}s",
                expected_value="Observable Traffic Volume and Inter-Arrival Timing",
                evidence={
                    "packet_count": pkt_count,
                    "file_size_bytes": file_size,
                    "duration_seconds": duration,
                },
                rationale="ESP encryption protects packet payload content but leaves packet size distributions and inter-arrival timing unencrypted, enabling statistical side-channel traffic inference.",
                recommendation="Enable Traffic Flow Confidentiality (TFC) padding if high-sensitivity traffic patterns must be hidden.",
                confidence=1.0,
                references=["RFC 4303 Section 2.4"],
            )
        )

    return findings
