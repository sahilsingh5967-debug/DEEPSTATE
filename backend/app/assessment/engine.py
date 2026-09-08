from typing import List, Optional
from backend.app.assessment.crypto_rules import evaluate_cryptography
from backend.app.assessment.metadata_rules import evaluate_metadata_exposure
from backend.app.assessment.policies import AssessmentPolicy, default_policy
from backend.app.assessment.protocol_rules import evaluate_protocol
from backend.app.assessment.sa_rules import evaluate_sa_and_key_exchange
from backend.app.assessment.scoring import calculate_scoring_and_metrics
from backend.app.models.schemas import AnalysisResult, SecurityAssessment, SecurityFinding


class SecurityAssessmentEngine:
    """
    Deterministic IPsec Security Assessment Engine.
    Consumes Phase 3 AnalysisResult directly without raw PCAP dependencies,
    evaluates security rules against a policy, applies strict unknown-handling,
    and returns a structured SecurityAssessment object.
    """

    def __init__(self, policy: Optional[AssessmentPolicy] = None):
        self.policy = policy or default_policy

    def assess(self, result: AnalysisResult) -> SecurityAssessment:
        """
        Executes complete security evaluation pipeline on an AnalysisResult.

        Args:
            result: Populated AnalysisResult model from Phase 3 protocol analyzer.

        Returns:
            Populated SecurityAssessment model.
        """
        findings: List[SecurityFinding] = []
        assessment_warnings: List[str] = []

        # Handle empty/failed AnalysisResult gracefully
        if not result or result.status == "failed" or not result.protocol_identification:
            assessment_warnings.append("AnalysisResult is empty or failed; performing limited baseline assessment.")
            return SecurityAssessment(
                security_score=50.0,
                score_confidence=0.0,
                assessment_coverage=0.0,
                overall_status="LIMITED_ASSESSMENT",
                risk_level="UNKNOWN",
                findings=[],
                passed_checks=0,
                failed_checks=0,
                warning_checks=0,
                unknown_checks=1,
                category_summary={},
                threat_matrix={},
                metadata_exposure={},
                recommendations_summary=["Provide a valid PCAP capture to enable protocol security evaluation."],
                assessment_warnings=assessment_warnings,
            )

        # 1. Evaluate Cryptographic Strength & Algorithms
        findings.extend(evaluate_cryptography(result, self.policy))

        # 2. Evaluate Protocol Version & Exchange
        findings.extend(evaluate_protocol(result, self.policy))

        # 3. Evaluate Key Exchange, PFS, SA, Replay & Lifetime
        findings.extend(evaluate_sa_and_key_exchange(result, self.policy))

        # 4. Evaluate Metadata Exposure
        findings.extend(evaluate_metadata_exposure(result, self.policy))

        # Include warnings from Phase 3 protocol analyzer
        if result.analysis_warnings:
            assessment_warnings.extend(result.analysis_warnings)

        # 5. Compute Deterministic Scoring, Metrics & Threat Matrix
        (
            score,
            confidence,
            coverage,
            status,
            risk_level,
            passed,
            failed,
            warning,
            unknown,
            cat_summary,
            threat_matrix,
        ) = calculate_scoring_and_metrics(findings, self.policy)

        # Collect actionable recommendations from FAIL and WARNING findings
        recommendations = [
            f.recommendation for f in findings if f.status in ("FAIL", "WARNING") and f.recommendation
        ]
        if not recommendations:
            recommendations.append("No critical security policy violations detected. Maintain current configuration.")

        if coverage < 0.5:
            assessment_warnings.append(
                f"Low assessment coverage ({int(coverage * 100)}%). Key cryptographic parameters were unobservable in the capture."
            )

        # Metadata exposure summary
        meta_exposure_summary = {
            "outer_ip_exposed": True,
            "packet_count": result.pcap_metadata.get("packet_count", 0) if result.pcap_metadata else 0,
            "encapsulation": result.esp.encapsulation if result.esp else "Unknown",
        }

        # Dedup warnings while maintaining order
        unique_warnings = list(dict.fromkeys(assessment_warnings))

        return SecurityAssessment(
            security_score=score,
            score_confidence=confidence,
            assessment_coverage=coverage,
            overall_status=status,
            risk_level=risk_level,
            findings=findings,
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warning,
            unknown_checks=unknown,
            category_summary=cat_summary,
            threat_matrix=threat_matrix,
            metadata_exposure=meta_exposure_summary,
            recommendations_summary=recommendations,
            assessment_warnings=unique_warnings,
        )


def assess_analysis_result(result: AnalysisResult, policy: Optional[AssessmentPolicy] = None) -> SecurityAssessment:
    """Helper function to run security assessment on an AnalysisResult."""
    engine = SecurityAssessmentEngine(policy=policy)
    return engine.assess(result)
