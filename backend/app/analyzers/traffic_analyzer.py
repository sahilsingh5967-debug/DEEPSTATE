from typing import List, Tuple
from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP
try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None
from backend.app.models.schemas import InferredValue, TrafficAnalysisDetail


def analyze_traffic(packets: List[Packet]) -> Tuple[TrafficAnalysisDetail, List[str]]:
    """
    Analyzes observable traffic metadata from packet layers.
    Distinguishes unencrypted observable traffic from encrypted ESP payloads.

    Returns:
        Tuple of (TrafficAnalysisDetail, warnings_list)
    """
    warnings: List[str] = []
    observed_layers = set()
    has_esp = False
    has_unencrypted_icmp = False
    has_unencrypted_tcp = False
    has_unencrypted_udp = False
    has_dns = False

    for pkt in packets:
        layer = pkt
        while layer and not isinstance(layer, bytes):
            layer_name = getattr(layer, "name", type(layer).__name__)
            observed_layers.add(layer_name)

            if layer_name == "IP":
                if getattr(layer, "proto", None) == 50:
                    has_esp = True
            elif layer_name == "ICMP":
                has_unencrypted_icmp = True
            elif layer_name == "TCP":
                has_unencrypted_tcp = True
            elif layer_name == "UDP":
                has_unencrypted_udp = True
            elif layer_name == "DNS":
                has_dns = True

            layer = getattr(layer, "payload", None)

    # Classify traffic based strictly on observable layers
    if has_unencrypted_icmp:
        inferred_type = "ICMP Traffic"
        confidence = 0.95
        evidence = ["Observed unencrypted ICMP layer packets in PCAP"]
        encrypted_only = False
    elif has_dns:
        inferred_type = "DNS Traffic"
        confidence = 0.90
        evidence = ["Observed unencrypted DNS query/response packets in PCAP"]
        encrypted_only = False
    elif has_unencrypted_tcp:
        inferred_type = "TCP Traffic"
        confidence = 0.85
        evidence = ["Observed unencrypted TCP layer packets in PCAP"]
        encrypted_only = False
    elif has_esp:
        inferred_type = "Encrypted ESP Payload"
        confidence = 0.0
        evidence = ["Payload is encrypted inside ESP (IP Proto 50) and cannot be directly inspected"]
        encrypted_only = True
        warnings.append("Traffic payload is encrypted inside ESP; deep traffic classification unavailable without decryption keys.")
    else:
        inferred_type = "UNKNOWN"
        confidence = 0.0
        evidence = ["No recognized unencrypted traffic layer observed in PCAP"]
        encrypted_only = False

    traffic_detail = TrafficAnalysisDetail(
        inferred_traffic_type=InferredValue(
            value=inferred_type,
            confidence=confidence,
            evidence=evidence
        ),
        observed_layers=sorted(list(observed_layers)),
        encrypted_payload_only=encrypted_only
    )

    return traffic_detail, warnings
