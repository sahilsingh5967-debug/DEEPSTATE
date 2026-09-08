from typing import List, Tuple
from scapy.all import Packet, IP, IPv6
from backend.app.models.schemas import (
    ESPAnalysisDetail,
    IKEAnalysisDetail,
    InferredValue,
    ModeInferenceDetail,
    ProtocolIdentification,
)


def detect_mode(
    packets: List[Packet],
    proto_id: ProtocolIdentification,
    ike_detail: IKEAnalysisDetail,
    esp_detail: ESPAnalysisDetail,
) -> Tuple[ModeInferenceDetail, List[str]]:
    """
    Infers Tunnel vs Transport vs Unknown mode using observable packet evidence and IKE proposals.
    Provides explicit confidence score and evidence list for all inferences.

    Returns:
        Tuple of (ModeInferenceDetail, warnings_list)
    """
    warnings: List[str] = []
    evidence: List[str] = []
    inferred_mode = "Unknown"
    confidence = 0.0

    # 1. Check IKE proposal payloads for explicit mode attributes
    if ike_detail.detected and ike_detail.proposals:
        for prop in ike_detail.proposals:
            mode_attr = prop.get("mode")
            if mode_attr == "tunnel":
                inferred_mode = "Tunnel"
                confidence = 0.95
                evidence.append("Observed explicit Tunnel mode attribute in IKE SA proposal payload.")
                break
            elif mode_attr == "transport":
                inferred_mode = "Transport"
                confidence = 0.95
                evidence.append("Observed explicit Transport mode attribute in IKE SA proposal payload.")
                break

    # 2. Inspect IP layer structures if mode is still unknown
    if inferred_mode == "Unknown" and (proto_id.has_esp or proto_id.has_ah):
        has_nested_ip = False
        sample_esp_count = 0

        for pkt in packets:
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                # Check if payload contains an inner IP layer
                if hasattr(ip_layer.payload, "name") and ip_layer.payload.name in ("IP", "IPv6"):
                    has_nested_ip = True
                    sample_esp_count += 1

        if has_nested_ip:
            inferred_mode = "Tunnel"
            confidence = 0.90
            evidence.append(f"Observed outer and inner IP header encapsulation in {sample_esp_count} packets.")

    # 3. Handle encrypted ESP traffic without observable inner headers
    if inferred_mode == "Unknown" and esp_detail.detected:
        confidence = 0.0
        evidence.append(
            "Encrypted ESP traffic (Proto 50) observed. Mode cannot be conclusively determined "
            "from binary encrypted payloads alone without unencrypted IKE negotiation payloads."
        )
        warnings.append("Insufficient observable evidence in PCAP to verify Tunnel vs Transport mode.")

    mode_detail = ModeInferenceDetail(
        inferred_mode=InferredValue(
            value=inferred_mode,
            confidence=confidence,
            evidence=evidence
        )
    )

    return mode_detail, warnings
