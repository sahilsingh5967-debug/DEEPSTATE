from typing import List
from backend.app.assessment.policies import AssessmentPolicy
from backend.app.models.schemas import AnalysisResult, SecurityFinding


def evaluate_protocol(result: AnalysisResult, policy: AssessmentPolicy) -> List[SecurityFinding]:
    """
    Evaluates IKE protocol version and exchange characteristics.
    """
    findings: List[SecurityFinding] = []

    ike_version = None
    if result.ike:
        ike_version = result.ike.version
    elif result.ipsec_parameters:
        ike_version = result.ipsec_parameters.ike_version

    if not ike_version:
        findings.append(
            SecurityFinding(
                id="SEC-PROTO-IKE-VERSION-UNKNOWN",
                finding_id="SEC-PROTO-IKE-VERSION-UNKNOWN",
                title="IKE Version Not Observable",
                severity="INFO",
                category="PROTOCOL_VERSION",
                status="UNKNOWN",
                description="IKE protocol version could not be determined from the available capture.",
                observed_value="Not Observable",
                expected_value=policy.minimum_ike_version,
                evidence={"ike_version": None},
                rationale="Capture contains only ESP packets or truncated UDP headers without IKE negotiation headers.",
                recommendation="Capture IKE_SA_INIT negotiation packets or inspect gateway configuration.",
                confidence=1.0,
                references=["RFC 7296"],
                limitations="No IKE negotiation header present in capture."
            )
        )
    elif ike_version == "IKEv2":
        findings.append(
            SecurityFinding(
                id="SEC-PROTO-IKEv2-PASS",
                finding_id="SEC-PROTO-IKEv2-PASS",
                title="Modern IKEv2 Protocol Version Observed",
                severity="INFO",
                category="PROTOCOL_VERSION",
                status="PASS",
                description="Observed modern IKEv2 protocol version.",
                observed_value="IKEv2",
                expected_value=policy.minimum_ike_version,
                evidence={"ike_version": "IKEv2"},
                rationale="IKEv2 (RFC 7296) features simplified exchanges, built-in NAT-T support, and improved DoS resilience.",
                recommendation="Maintain current IKEv2 configuration.",
                confidence=1.0,
                references=["RFC 7296"],
            )
        )
    elif ike_version == "IKEv1":
        findings.append(
            SecurityFinding(
                id="SEC-PROTO-IKEv1-WARNING",
                finding_id="SEC-PROTO-IKEv1-WARNING",
                title="Legacy IKEv1 Protocol Version Observed",
                severity="MEDIUM",
                category="PROTOCOL_VERSION",
                status="WARNING",
                description="Observed legacy IKEv1 protocol version.",
                observed_value="IKEv1",
                expected_value=policy.minimum_ike_version,
                evidence={"ike_version": "IKEv1"},
                rationale="IKEv1 (RFC 2409) is legacy, slower, lacks modern EAP/NAT-T enhancements, and is vulnerable to Amplification attacks.",
                recommendation="Plan migration to IKEv2 across all VPN endpoints.",
                confidence=1.0,
                references=["RFC 7296", "NIST SP 800-77 Rev. 1"],
            )
        )

    return findings
