from typing import List
from backend.app.assessment.policies import AssessmentPolicy
from backend.app.models.schemas import AnalysisResult, SecurityFinding


def is_strong_dh(group_str: str, policy: AssessmentPolicy) -> bool:
    g = group_str.lower()
    return any(s in g for s in policy.strong_dh_groups)


def is_weak_dh(group_str: str, policy: AssessmentPolicy) -> bool:
    g = group_str.lower()
    if is_strong_dh(group_str, policy):
        return False
    return any(w in g for w in policy.weak_dh_groups) or "group 1" in g or "group 2" in g or "group 5" in g


def evaluate_sa_and_key_exchange(result: AnalysisResult, policy: AssessmentPolicy) -> List[SecurityFinding]:
    """
    Evaluates Key Exchange (DH Groups), Perfect Forward Secrecy (PFS), Security Associations,
    Key Lifetimes, and Replay Protection using observable evidence and conservative state semantics.
    """
    findings: List[SecurityFinding] = []

    # 1. Diffie-Hellman Group Assessment
    dh_groups = []
    if result.ike:
        dh_groups.extend(result.ike.dh_groups)
    if result.ipsec_parameters:
        dh_groups.extend(result.ipsec_parameters.dh_groups)
    dh_groups = list(dict.fromkeys(dh_groups))

    if not dh_groups:
        findings.append(
            SecurityFinding(
                id="SEC-KEYEX-DH-UNKNOWN",
                finding_id="SEC-KEYEX-DH-UNKNOWN",
                title="Diffie-Hellman Group Not Observable",
                severity="INFO",
                category="KEY_EXCHANGE",
                status="UNKNOWN",
                description="Diffie-Hellman group could not be determined from the available capture.",
                observed_value="Not Observable",
                expected_value="Group 14 (2048-bit), Group 19 (ECP-256)",
                evidence={"dh_groups": []},
                rationale="Capture does not expose unencrypted IKE proposal or key exchange payloads.",
                recommendation="Capture complete IKE negotiation or inspect gateway configuration.",
                confidence=1.0,
                references=["NIST SP 800-77 Rev. 1"],
                limitations="DH group parameter unobservable in capture."
            )
        )
    else:
        for group in dh_groups:
            if is_strong_dh(group, policy):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-KEYEX-DH-STRONG-{group}",
                        finding_id=f"SEC-KEYEX-DH-STRONG-{group}",
                        title="Strong Diffie-Hellman Key Exchange Group Observed",
                        severity="INFO",
                        category="KEY_EXCHANGE",
                        status="PASS",
                        description=f"Observed strong Diffie-Hellman group '{group}'.",
                        observed_value=group,
                        expected_value="Group 14 (2048-bit) or Group 19 (ECP-256)",
                        evidence={"dh_group": group},
                        rationale="DH Group 14+ (2048-bit MODP / ECP-256) provides 112+ bits of security margin against factorization.",
                        recommendation="Maintain current Diffie-Hellman key exchange configuration.",
                        confidence=1.0,
                        references=["RFC 8221"],
                    )
                )
            elif is_weak_dh(group, policy):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-KEYEX-DH-WEAK-{group}",
                        finding_id=f"SEC-KEYEX-DH-WEAK-{group}",
                        title="Weak Diffie-Hellman Group Detected",
                        severity="HIGH" if "group 1" in group.lower() or "768" in group.lower() else "MEDIUM",
                        category="KEY_EXCHANGE",
                        status="FAIL",
                        description=f"Observed weak or deprecated Diffie-Hellman group '{group}'.",
                        observed_value=group,
                        expected_value="Group 14 (2048-bit) or Group 19 (ECP-256)",
                        evidence={"dh_group": group},
                        rationale="Diffie-Hellman groups under 2048-bit (MODP < 2048) are vulnerable to precomputation attacks (Logjam).",
                        recommendation="Upgrade Diffie-Hellman key exchange group to Group 14 (2048-bit) or Group 19 (ECP-256).",
                        confidence=1.0,
                        references=["RFC 8221", "NIST SP 800-77 Rev. 1"],
                    )
                )

    # 2. Perfect Forward Secrecy (PFS) Assessment
    pfs_status = "UNKNOWN"
    pfs_evidence = "PFS status cannot be established from binary ESP traffic alone without IKE CHILD_SA proposals."

    if result.mode_inference and result.mode_inference.inferred_mode.evidence:
        for ev in result.mode_inference.inferred_mode.evidence:
            if "pfs enabled" in ev.lower() or "modp2048" in ev.lower() or "ecp256" in ev.lower():
                pfs_status = "PASS"
                pfs_evidence = "Observed CHILD_SA proposal with explicit DH key re-exchange."
                break
            elif "pfs disabled" in ev.lower() or "no pfs" in ev.lower():
                pfs_status = "WARNING"
                pfs_evidence = "Observed CHILD_SA proposal without PFS DH re-exchange."
                break

    if pfs_status == "UNKNOWN":
        findings.append(
            SecurityFinding(
                id="SEC-PFS-STATUS-UNKNOWN",
                finding_id="SEC-PFS-STATUS-UNKNOWN",
                title="Perfect Forward Secrecy (PFS) Status Not Observable",
                severity="INFO",
                category="PERFECT_FORWARD_SECRECY",
                status="UNKNOWN",
                description="PFS status could not be determined from the available capture.",
                observed_value="Not Observable",
                expected_value="Enabled (PFS Active)",
                evidence={"pfs_status": "UNKNOWN", "details": pfs_evidence},
                rationale="Determining whether PFS is active requires inspecting CHILD_SA proposal payloads in IKE negotiation.",
                recommendation="Verify PFS configuration on IPsec gateway.",
                confidence=1.0,
                references=["NIST SP 800-77 Rev. 1"],
                limitations="CHILD_SA proposal unobservable."
            )
        )
    elif pfs_status == "PASS":
        findings.append(
            SecurityFinding(
                id="SEC-PFS-ENABLED-PASS",
                finding_id="SEC-PFS-ENABLED-PASS",
                title="Perfect Forward Secrecy (PFS) Enabled",
                severity="INFO",
                category="PERFECT_FORWARD_SECRECY",
                status="PASS",
                description="PFS is active for CHILD_SA key re-exchange.",
                observed_value="Enabled",
                expected_value="Enabled",
                evidence={"pfs_status": "Enabled", "details": pfs_evidence},
                rationale="PFS ensures compromise of long-term gateway private keys does not compromise past session keys.",
                recommendation="Maintain PFS enabled on all IPsec connections.",
                confidence=1.0,
                references=["RFC 7296"],
            )
        )
    elif pfs_status == "WARNING":
        findings.append(
            SecurityFinding(
                id="SEC-PFS-DISABLED-WARNING",
                finding_id="SEC-PFS-DISABLED-WARNING",
                title="Perfect Forward Secrecy (PFS) Disabled or Inactive",
                severity="MEDIUM",
                category="PERFECT_FORWARD_SECRECY",
                status="WARNING",
                description="PFS is disabled for CHILD_SA key re-exchange.",
                observed_value="Disabled",
                expected_value="Enabled",
                evidence={"pfs_status": "Disabled", "details": pfs_evidence},
                rationale="Without PFS, compromise of the long-term private key allows decryption of all historical recorded traffic.",
                recommendation="Enable PFS on CHILD_SA configurations using DH Group 14 or higher.",
                confidence=1.0,
                references=["NIST SP 800-77 Rev. 1"],
            )
        )

    # 3. Security Association SPI & Replay Protection Assessment
    if result.esp and result.esp.detected:
        if result.esp.sequence_numbers and len(result.esp.sequence_numbers) > 1:
            seqs = result.esp.sequence_numbers
            is_monotonically_increasing = all(x < y for x, y in zip(seqs, seqs[1:]))
            if is_monotonically_increasing:
                findings.append(
                    SecurityFinding(
                        id="SEC-SA-REPLAY-PROGRESSION",
                        finding_id="SEC-SA-REPLAY-PROGRESSION",
                        title="ESP Sequence Numbers Monotonically Increasing",
                        severity="INFO",
                        category="REPLAY_PROTECTION",
                        status="PASS",
                        description="Observed ESP packet sequence numbers progressing sequentially.",
                        observed_value=f"Sequence sample: {seqs[:5]}...",
                        expected_value="Monotonically increasing sequence numbers",
                        evidence={"sequence_numbers": seqs[:10]},
                        rationale="Sequential ESP sequence numbers are necessary for anti-replay window protection.",
                        recommendation="Ensure anti-replay window check (64+ packets) is active on gateway.",
                        confidence=0.85,
                        references=["RFC 4303 Section 3.4.3"],
                    )
                )
    else:
        findings.append(
            SecurityFinding(
                id="SEC-SA-REPLAY-NOT-OBSERVED",
                finding_id="SEC-SA-REPLAY-NOT-OBSERVED",
                title="Replay Protection Information Not Observed",
                severity="INFO",
                category="REPLAY_PROTECTION",
                status="NOT_OBSERVED",
                description="No ESP packet sequence numbers observed in capture.",
                observed_value="Not Observed",
                expected_value="Monotonically increasing sequence numbers",
                evidence={"sequence_numbers": []},
                rationale="Replay protection evaluation requires observing ESP packet sequences.",
                recommendation="Inspect gateway SA status via swanctl or ipsec status.",
                confidence=1.0,
                references=["RFC 4303"],
            )
        )

    # 4. Key Lifetime Assessment
    findings.append(
        SecurityFinding(
            id="SEC-SA-LIFETIME-NOT-OBSERVED",
            finding_id="SEC-SA-LIFETIME-NOT-OBSERVED",
            title="SA Key Lifetime Information Not Observable",
            severity="INFO",
            category="KEY_LIFETIME",
            status="UNKNOWN",
            description="SA key lifetime parameters are not exposed in raw PCAP packet headers.",
            observed_value="Not Observable",
            expected_value="Configured rekey time (e.g. 28800s / 8h)",
            evidence={"lifetime_info": None},
            rationale="Key lifetime negotiation is defined in local gateway policy or encrypted IKE payloads.",
            recommendation="Verify SA key lifetime policies directly on VPN gateways.",
            confidence=1.0,
            references=["NIST SP 800-77 Rev. 1"],
            limitations="Key lifetime not exposed in packet headers."
        )
    )

    return findings
