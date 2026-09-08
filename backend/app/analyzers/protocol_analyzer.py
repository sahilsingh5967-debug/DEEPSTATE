#!/usr/bin/env python3
"""
Main IPsec Protocol Analyzer Orchestrator.

Ingests PCAP captures, executes modular protocol analysis pipelines,
maintains strict separation between observed facts and inferred values,
and outputs a structured AnalysisResult Pydantic model.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

# Ensure project imports work
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.analyzers.esp_analyzer import analyze_esp
from backend.app.analyzers.ike_analyzer import analyze_ike
from backend.app.analyzers.mode_detector import detect_mode
from backend.app.analyzers.packet_classifier import classify_packets
from backend.app.analyzers.pcap_reader import read_pcap_file
from backend.app.analyzers.traffic_analyzer import analyze_traffic
from backend.app.assessment.engine import assess_analysis_result
from backend.app.ml.inference import classify_pcap_for_integration
from backend.app.models.schemas import (
    AHAnalysisDetail,
    AnalysisResult,
    IPsecParameters,
    TrafficClassification,
)


def analyze_pcap(pcap_path: str) -> AnalysisResult:
    """
    Main entry point for protocol analysis.
    Ingests a PCAP file, extracts observable IPsec/IKE parameters, executes Phase 4 Security Assessment,
    runs Phase 5 ML Traffic Classification, and returns a unified AnalysisResult.

    Args:
        pcap_path: Path to the target PCAP file.

    Returns:
        Populated AnalysisResult object.
    """
    analysis_id = str(uuid.uuid4())
    warnings_accumulated = []
    errors_accumulated = []

    # 1. Load PCAP and extract file metadata
    try:
        packets, pcap_meta, reader_warnings = read_pcap_file(pcap_path)
        warnings_accumulated.extend(reader_warnings)
    except Exception as e:
        errors_accumulated.append(f"PCAP ingestion error: {str(e)}")
        return AnalysisResult(
            analysis_id=analysis_id,
            status="failed",
            timestamp=datetime.utcnow(),
            pcap_metadata={"file_path": pcap_path},
            errors=errors_accumulated,
        )

    if not packets:
        base_empty = AnalysisResult(
            analysis_id=analysis_id,
            status="completed",
            timestamp=datetime.utcnow(),
            pcap_metadata=pcap_meta,
            analysis_warnings=warnings_accumulated,
            errors=errors_accumulated,
        )
        try:
            base_empty.security_assessment = assess_analysis_result(base_empty)
        except Exception:
            pass
        base_empty.traffic_classification = classify_pcap_for_integration(pcap_path)
        return base_empty

    # 2. Classify protocol layers
    proto_id, class_warnings = classify_packets(packets)
    warnings_accumulated.extend(class_warnings)

    # 3. Analyze IKE protocol details
    ike_detail, ike_warnings = analyze_ike(packets)
    warnings_accumulated.extend(ike_warnings)

    # 4. Analyze ESP protocol details
    esp_detail, esp_warnings = analyze_esp(packets)
    warnings_accumulated.extend(esp_warnings)

    # 5. Analyze AH protocol details (Placeholder for AH)
    ah_detail = AHAnalysisDetail(detected=proto_id.has_ah)

    # 6. Infer VPN Mode (Tunnel vs Transport)
    mode_detail, mode_warnings = detect_mode(packets, proto_id, ike_detail, esp_detail)
    warnings_accumulated.extend(mode_warnings)

    # 7. Analyze Traffic Metadata
    traffic_detail, traffic_warnings = analyze_traffic(packets)
    warnings_accumulated.extend(traffic_warnings)

    # 8. Assemble observable IPsecParameters summary
    sa_records = []
    if esp_detail.detected:
        for spi in esp_detail.spis:
            sa_records.append({
                "spi": spi,
                "protocol": "ESP",
                "packet_count": esp_detail.packet_count,
                "encapsulation": esp_detail.encapsulation,
            })
    if ike_detail.detected and ike_detail.initiator_spi:
        sa_records.append({
            "initiator_spi": ike_detail.initiator_spi,
            "responder_spi": ike_detail.responder_spi,
            "protocol": "IKE",
            "version": ike_detail.version,
        })

    ipsec_params = IPsecParameters(
        ike_version=ike_detail.version,
        mode=mode_detail.inferred_mode.value,
        encryption_algorithms=ike_detail.encryption_algorithms,
        integrity_algorithms=ike_detail.integrity_algorithms,
        dh_groups=ike_detail.dh_groups,
        prf_algorithms=ike_detail.prf_algorithms,
        encapsulation=esp_detail.encapsulation if esp_detail.detected else None,
        security_associations=sa_records,
    )

    # Dedup warnings while maintaining order
    unique_warnings = list(dict.fromkeys(warnings_accumulated))

    # Assemble intermediate Phase 3 AnalysisResult
    result = AnalysisResult(
        analysis_id=analysis_id,
        status="completed",
        timestamp=datetime.utcnow(),
        pcap_metadata=pcap_meta,
        protocol_identification=proto_id,
        ike=ike_detail,
        esp=esp_detail,
        ah=ah_detail,
        ipsec_parameters=ipsec_params,
        mode_inference=mode_detail,
        traffic_analysis=traffic_detail,
        analysis_warnings=unique_warnings,
        errors=errors_accumulated,
    )

    # 9. Phase 4 — Security Assessment Engine Evaluation
    try:
        result.security_assessment = assess_analysis_result(result)
    except Exception as e:
        result.analysis_warnings.append(f"Security assessment warning: {str(e)}")

    # 10. Phase 5 — ML Traffic Classification Inference
    try:
        result.traffic_classification = classify_pcap_for_integration(pcap_path)
    except Exception as e:
        result.analysis_warnings.append(f"ML classification warning: {str(e)}")
        target_classes = ["ICMP", "Web Browsing", "Email", "Chat", "Streaming", "File Transfer", "VoIP", "P2P"]
        default_p = {c: 0.0 for c in target_classes}
        result.traffic_classification = TrafficClassification(
            status="unavailable",
            dominant_class="UNKNOWN",
            detected_type="UNKNOWN",
            confidence=0.0,
            class_probabilities=default_p,
            probabilities=default_p,
            flow_count=0,
            reason=f"ML inference error: {str(e)}"
        )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered IPsec VPN Protocol Analyzer - Unified CLI"
    )
    parser.add_argument("pcap_path", help="Path to PCAP capture file")
    parser.add_argument("--json", action="store_true", help="Output raw JSON serialization")
    args = parser.parse_args()

    try:
        result = analyze_pcap(args.pcap_path)
        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            print("\n============================================================")
            print(" Unified IPsec VPN Protocol Analysis & ML Report")
            print("============================================================")
            print(f" Analysis ID : {result.analysis_id}")
            print(f" PCAP File   : {result.pcap_metadata.get('file_name')} ({result.pcap_metadata.get('file_size_bytes')} bytes)")
            print(f" Packets     : {result.pcap_metadata.get('packet_count')} | Duration: {result.pcap_metadata.get('duration_seconds')}s")
            print("------------------------------------------------------------")
            print(" Protocol Identification:")
            if result.protocol_identification:
                print(f"   IP Versions : {', '.join(result.protocol_identification.ip_versions) or 'None'}")
                print(f"   Protocols   : {', '.join(result.protocol_identification.protocols_detected) or 'None'}")
            print("------------------------------------------------------------")
            print(" IKE Analysis:")
            if result.ike and result.ike.detected:
                print(f"   Detected     : Yes (Version: {result.ike.version or 'Unknown'})")
                print(f"   Exchanges    : {', '.join(result.ike.exchange_types) or 'None'}")
                print(f"   Initiator SPI: {result.ike.initiator_spi or 'Unknown'}")
                print(f"   Encryption   : {', '.join(result.ike.encryption_algorithms) or 'None (Not observable / Encrypted)'}")
                print(f"   Integrity    : {', '.join(result.ike.integrity_algorithms) or 'None (Not observable / Encrypted)'}")
                print(f"   DH Groups    : {', '.join(result.ike.dh_groups) or 'None (Not observable / Encrypted)'}")
            else:
                print("   Detected     : No IKE packets observed")
            print("------------------------------------------------------------")
            print(" ESP Analysis:")
            if result.esp and result.esp.detected:
                print(f"   Detected     : Yes ({result.esp.packet_count} ESP packets)")
                print(f"   SPIs         : {', '.join(result.esp.spis) or 'None'}")
                print(f"   Encapsulation: {result.esp.encapsulation}")
            else:
                print("   Detected     : No ESP packets observed")
            print("------------------------------------------------------------")
            print(" Mode Inference:")
            if result.mode_inference:
                inf = result.mode_inference.inferred_mode
                print(f"   Inferred Mode: {inf.value} (Confidence: {inf.confidence})")
                for ev in inf.evidence:
                    print(f"     Evidence   : {ev}")
            print("------------------------------------------------------------")
            print(" Security Assessment Engine (Phase 4):")
            if result.security_assessment:
                sec = result.security_assessment
                print(f"   Security Score: {sec.security_score:.1f}/100.0 (Status: {sec.overall_status}, Risk: {sec.risk_level})")
                print(f"   Checks Summary: Passed {sec.passed_checks} | Failed {sec.failed_checks} | Warnings {sec.warning_checks} | Unknown {sec.unknown_checks}")
            else:
                print("   Security Assessment: Not available")
            print("------------------------------------------------------------")
            print(" ML Traffic Classification (Phase 5):")
            if result.traffic_classification:
                ml = result.traffic_classification
                print(f"   ML Status    : {ml.status.upper()}")
                print(f"   Inferred Class: {ml.dominant_class} (Confidence: {ml.confidence:.4f})")
                print(f"   Flow Count   : {ml.flow_count}")
                if ml.class_probabilities:
                    print("   Probabilities:")
                    for cname, pval in ml.class_probabilities.items():
                        print(f"     - {cname:<14}: {pval:.4f}")
                print(f"   Disclaimer   : {ml.disclaimer}")
            else:
                print("   ML Classification: Unavailable")
            print("------------------------------------------------------------")
            if result.analysis_warnings:
                print(" Analysis Warnings:")
                for w in result.analysis_warnings:
                    print(f"   [!] {w}")
            print("============================================================\n")

    except Exception as e:
        print(f"Error during analysis: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
