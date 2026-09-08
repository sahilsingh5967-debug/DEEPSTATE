from typing import Any, Dict, List, Tuple
from backend.app.assessment.policies import AssessmentPolicy
from backend.app.models.schemas import SecurityFinding


def calculate_scoring_and_metrics(
    findings: List[SecurityFinding],
    policy: AssessmentPolicy
) -> Tuple[float, float, float, str, str, int, int, int, int, Dict[str, Any], Dict[str, Any]]:
    """
    Computes deterministic security score (0-100), assessment coverage (0-1), score confidence,
    risk status, category summary, and threat matrix.

    Methodology:
    - Base score = 100.0
    - Penalizes only confirmed FAIL and WARNING security findings.
    - UNKNOWN and NOT_OBSERVED findings do NOT incur score penalties.
    - Coverage = evaluated_checks / total_applicable_checks.

    Returns:
        Tuple of (
            security_score,
            score_confidence,
            assessment_coverage,
            overall_status,
            risk_level,
            passed_checks,
            failed_checks,
            warning_checks,
            unknown_checks,
            category_summary,
            threat_matrix
        )
    """
    passed = 0
    failed = 0
    warning = 0
    unknown = 0
    not_observed = 0

    category_counts: Dict[str, Dict[str, int]] = {}
    threat_matrix: Dict[str, List[Dict[str, str]]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }

    total_penalties = 0.0

    for f in findings:
        cat = f.category
        if cat not in category_counts:
            category_counts[cat] = {"PASS": 0, "FAIL": 0, "WARNING": 0, "UNKNOWN": 0, "NOT_OBSERVED": 0}

        st = f.status.upper()
        if st == "PASS":
            passed += 1
            category_counts[cat]["PASS"] += 1
        elif st == "FAIL":
            failed += 1
            category_counts[cat]["FAIL"] += 1
            penalty = policy.severity_penalties.get(f.severity, 10.0)
            total_penalties += penalty
            threat_matrix.get(f.severity, threat_matrix["HIGH"]).append({
                "id": f.id,
                "title": f.title,
                "impact": "HIGH" if f.severity in ("CRITICAL", "HIGH") else "MEDIUM",
                "likelihood": "HIGH" if f.severity in ("CRITICAL", "HIGH") else "MEDIUM",
            })
        elif st == "WARNING":
            warning += 1
            category_counts[cat]["WARNING"] += 1
            penalty = policy.severity_penalties.get(f.severity, 5.0) * 0.5
            total_penalties += penalty
            threat_matrix.get(f.severity, threat_matrix["LOW"]).append({
                "id": f.id,
                "title": f.title,
                "impact": "LOW",
                "likelihood": "MEDIUM",
            })
        elif st == "UNKNOWN":
            unknown += 1
            category_counts[cat]["UNKNOWN"] += 1
        elif st == "NOT_OBSERVED":
            not_observed += 1
            category_counts[cat]["NOT_OBSERVED"] += 1

    evaluated_checks = passed + failed + warning
    total_applicable_checks = evaluated_checks + unknown

    if total_applicable_checks > 0:
        coverage = round(evaluated_checks / total_applicable_checks, 4)
    else:
        coverage = 0.0

    if evaluated_checks > 0:
        raw_score = max(0.0, 100.0 - total_penalties)
        security_score = round(raw_score, 2)
        score_confidence = round(coverage, 2)
    else:
        security_score = 50.0
        score_confidence = 0.0

    # Risk level and overall status determination
    if failed == 0 and warning == 0 and evaluated_checks > 0:
        overall_status = "SECURE"
        risk_level = "SECURE"
    elif failed > 0:
        has_critical = any(f.severity == "CRITICAL" for f in findings if f.status == "FAIL")
        has_high = any(f.severity == "HIGH" for f in findings if f.status == "FAIL")
        if has_critical:
            overall_status = "CRITICAL_RISK"
            risk_level = "CRITICAL"
        elif has_high:
            overall_status = "HIGH_RISK"
            risk_level = "HIGH"
        else:
            overall_status = "MEDIUM_RISK"
            risk_level = "MEDIUM"
    elif warning > 0 and failed == 0:
        overall_status = "LOW_RISK"
        risk_level = "LOW"
    else:
        overall_status = "LIMITED_ASSESSMENT"
        risk_level = "UNKNOWN"

    category_summary = {
        cat: {
            "total_checks": sum(counts.values()),
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "warning": counts["WARNING"],
            "unknown": counts["UNKNOWN"],
            "status": "PASS" if counts["FAIL"] == 0 and counts["WARNING"] == 0 and counts["PASS"] > 0 else (
                "FAIL" if counts["FAIL"] > 0 else ("WARNING" if counts["WARNING"] > 0 else "UNKNOWN")
            )
        }
        for cat, counts in category_counts.items()
    }

    return (
        security_score,
        score_confidence,
        coverage,
        overall_status,
        risk_level,
        passed,
        failed,
        warning,
        unknown,
        category_summary,
        threat_matrix,
    )
