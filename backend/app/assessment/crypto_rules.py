from typing import List
from backend.app.assessment.policies import AssessmentPolicy
from backend.app.models.schemas import AnalysisResult, SecurityFinding


def evaluate_cryptography(result: AnalysisResult, policy: AssessmentPolicy) -> List[SecurityFinding]:
    """
    Evaluates observable cryptographic algorithms and cipher suite combinations.
    Applies strict UNKNOWN-handling for missing/unobservable parameters.
    """
    findings: List[SecurityFinding] = []

    # Extract observed algorithm lists
    enc_algos = []
    integ_algos = []
    prf_algos = []

    if result.ike:
        enc_algos.extend(result.ike.encryption_algorithms)
        integ_algos.extend(result.ike.integrity_algorithms)
        prf_algos.extend(result.ike.prf_algorithms)

    if result.ipsec_parameters:
        enc_algos.extend(result.ipsec_parameters.encryption_algorithms)
        integ_algos.extend(result.ipsec_parameters.integrity_algorithms)
        prf_algos.extend(result.ipsec_parameters.prf_algorithms)

    # Dedup while preserving order
    enc_algos = list(dict.fromkeys(enc_algos))
    integ_algos = list(dict.fromkeys(integ_algos))
    prf_algos = list(dict.fromkeys(prf_algos))

    # 1. Encryption Algorithm Check
    if not enc_algos:
        findings.append(
            SecurityFinding(
                id="SEC-CRYPTO-ENC-UNKNOWN",
                finding_id="SEC-CRYPTO-ENC-UNKNOWN",
                title="Encryption Algorithm Not Observable",
                severity="INFO",
                category="CRYPTOGRAPHY",
                status="UNKNOWN",
                description="Encryption algorithm could not be determined from the available capture.",
                observed_value="Not Observable",
                expected_value=", ".join(policy.strong_encryption + policy.acceptable_encryption),
                evidence={"encryption_algorithms": []},
                rationale="Capture does not contain unencrypted IKE proposal payloads exposing encryption algorithm selection.",
                recommendation="Capture complete IKE_SA_INIT negotiation packets or inspect gateway configuration directly.",
                confidence=1.0,
                references=["NIST SP 800-77 Rev. 1"],
                limitations="Encryption payload encrypted or absent in synthetic/truncated capture."
            )
        )
    else:
        for algo in enc_algos:
            if any(weak.lower() in algo.lower() for weak in policy.weak_encryption):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-CRYPTO-ENC-WEAK-{algo}",
                        finding_id=f"SEC-CRYPTO-ENC-WEAK-{algo}",
                        title="Deprecated or Weak Encryption Algorithm Detected",
                        severity="CRITICAL" if "des" in algo.lower() or "null" in algo.lower() else "HIGH",
                        category="CRYPTOGRAPHY",
                        status="FAIL",
                        description=f"Observed weak or deprecated encryption algorithm '{algo}'.",
                        observed_value=algo,
                        expected_value=", ".join(policy.strong_encryption),
                        evidence={"encryption_algorithm": algo},
                        rationale="Deprecated ciphers like 3DES and DES suffer from small block sizes (64-bit) and known birthday attacks (Sweet32).",
                        recommendation=f"Disable '{algo}' on IPsec gateway and migrate to AES-GCM-256 or AES-CBC-256.",
                        confidence=1.0,
                        references=["NIST SP 800-77 Rev. 1", "RFC 8221"],
                    )
                )
            elif any(strong.lower() in algo.lower() for strong in policy.strong_encryption):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-CRYPTO-ENC-STRONG-{algo}",
                        finding_id=f"SEC-CRYPTO-ENC-STRONG-{algo}",
                        title="Strong Authenticated Encryption (AEAD) Algorithm Observed",
                        severity="INFO",
                        category="CRYPTOGRAPHY",
                        status="PASS",
                        description=f"Observed strong AEAD encryption algorithm '{algo}'.",
                        observed_value=algo,
                        expected_value=", ".join(policy.strong_encryption),
                        evidence={"encryption_algorithm": algo},
                        rationale="AEAD ciphers provide high-speed authenticated encryption with built-in integrity verification.",
                        recommendation="Maintain current AEAD cipher configuration.",
                        confidence=1.0,
                        references=["RFC 8221", "NIST SP 800-77 Rev. 1"],
                    )
                )
            elif any(acc.lower() in algo.lower() for acc in policy.acceptable_encryption):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-CRYPTO-ENC-ACCEPT-{algo}",
                        finding_id=f"SEC-CRYPTO-ENC-ACCEPT-{algo}",
                        title="Acceptable Cipher Block Chaining (CBC) Encryption Algorithm Observed",
                        severity="LOW",
                        category="CRYPTOGRAPHY",
                        status="WARNING",
                        description=f"Observed legacy CBC-mode encryption algorithm '{algo}'.",
                        observed_value=algo,
                        expected_value=", ".join(policy.strong_encryption),
                        evidence={"encryption_algorithm": algo},
                        rationale="CBC mode is secure when combined with strong HMAC integrity, but AEAD ciphers (AES-GCM) are preferred.",
                        recommendation="Consider planning migration to AES-256-GCM or AES-128-GCM where supported.",
                        confidence=1.0,
                        references=["NIST SP 800-77 Rev. 1"],
                    )
                )

    # 2. Integrity Algorithm Check
    if not integ_algos:
        # Note: If AEAD is present, integrity algorithm may be implicit
        has_aead = any(any(s.lower() in a.lower() for s in policy.strong_encryption) for a in enc_algos)
        if not has_aead:
            findings.append(
                SecurityFinding(
                    id="SEC-CRYPTO-INTEG-UNKNOWN",
                    finding_id="SEC-CRYPTO-INTEG-UNKNOWN",
                    title="Integrity Algorithm Not Observable",
                    severity="INFO",
                    category="CRYPTOGRAPHY",
                    status="UNKNOWN",
                    description="Integrity algorithm could not be determined from the available capture.",
                    observed_value="Not Observable",
                    expected_value=", ".join(policy.strong_integrity),
                    evidence={"integrity_algorithms": []},
                    rationale="Capture does not expose unencrypted IKE proposal payloads.",
                    recommendation="Capture complete IKE negotiation or inspect gateway configuration.",
                    confidence=1.0,
                    references=["RFC 8221"],
                    limitations="Integrity algorithm unobservable."
                )
            )
    else:
        for algo in integ_algos:
            if any(weak.lower() in algo.lower() for weak in policy.weak_integrity):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-CRYPTO-INTEG-WEAK-{algo}",
                        finding_id=f"SEC-CRYPTO-INTEG-WEAK-{algo}",
                        title="Weak or Deprecated Integrity Algorithm Detected",
                        severity="HIGH",
                        category="CRYPTOGRAPHY",
                        status="FAIL",
                        description=f"Observed weak integrity algorithm '{algo}'.",
                        observed_value=algo,
                        expected_value=", ".join(policy.strong_integrity),
                        evidence={"integrity_algorithm": algo},
                        rationale="MD5 and SHA-1 suffer from collision vulnerabilities and are deprecated for IPsec integrity.",
                        recommendation="Migrate to HMAC-SHA2-256-128 or higher.",
                        confidence=1.0,
                        references=["RFC 8221", "NIST SP 800-131A"],
                    )
                )
            elif any(strong.lower() in algo.lower() for strong in policy.strong_integrity):
                findings.append(
                    SecurityFinding(
                        id=f"SEC-CRYPTO-INTEG-STRONG-{algo}",
                        finding_id=f"SEC-CRYPTO-INTEG-STRONG-{algo}",
                        title="Strong HMAC Integrity Algorithm Observed",
                        severity="INFO",
                        category="CRYPTOGRAPHY",
                        status="PASS",
                        description=f"Observed strong integrity algorithm '{algo}'.",
                        observed_value=algo,
                        expected_value=", ".join(policy.strong_integrity),
                        evidence={"integrity_algorithm": algo},
                        rationale="HMAC-SHA2 algorithms provide cryptographically strong integrity and authenticity verification.",
                        recommendation="Maintain current HMAC-SHA2 integrity configuration.",
                        confidence=1.0,
                        references=["RFC 8221"],
                    )
                )

    return findings
