from typing import List, Tuple
from scapy.all import Packet, IP, IPv6, UDP, TCP, ICMP
from backend.app.models.schemas import ProtocolIdentification


def classify_packets(packets: List[Packet]) -> Tuple[ProtocolIdentification, List[str]]:
    """
    Classifies packets into IP versions, transport layer protocols, and IPsec protocols.

    Returns:
        Tuple of (ProtocolIdentification, warnings_list)
    """
    warnings: List[str] = []
    ip_versions = set()
    protocols = set()
    has_ike = False
    has_esp = False
    has_ah = False

    for idx, pkt in enumerate(packets):
        try:
            if pkt.haslayer(IP):
                ip_versions.add("IPv4")
                proto = pkt[IP].proto
                if proto == 50:
                    has_esp = True
                    protocols.add("ESP")
                elif proto == 51:
                    has_ah = True
                    protocols.add("AH")
            elif pkt.haslayer(IPv6):
                ip_versions.add("IPv6")
                nh = pkt[IPv6].nh
                if nh == 50:
                    has_esp = True
                    protocols.add("ESP")
                elif nh == 51:
                    has_ah = True
                    protocols.add("AH")

            if pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                protocols.add("UDP")
                if sport in (500, 4500) or dport in (500, 4500):
                    has_ike = True
                    protocols.add("IKE")

            if pkt.haslayer(TCP):
                protocols.add("TCP")

            if pkt.haslayer(ICMP):
                protocols.add("ICMP")

        except Exception as e:
            warnings.append(f"Packet #{idx+1}: Classification warning: {str(e)}")

    if not has_ike and not has_esp and not has_ah:
        warnings.append("No IPsec (IKE, ESP, or AH) traffic detected in PCAP capture.")

    proto_id = ProtocolIdentification(
        ip_versions=sorted(list(ip_versions)),
        protocols_detected=sorted(list(protocols)),
        has_ike=has_ike,
        has_esp=has_esp,
        has_ah=has_ah
    )

    return proto_id, warnings
