from typing import List, Tuple
from scapy.all import Packet, IP, IPv6, UDP, Raw
from backend.app.models.schemas import ESPAnalysisDetail


def analyze_esp(packets: List[Packet]) -> Tuple[ESPAnalysisDetail, List[str]]:
    """
    Parses observable ESP protocol characteristics (SPIs, sequence numbers, packet counts, payload stats).

    Returns:
        Tuple of (ESPAnalysisDetail, warnings_list)
    """
    warnings: List[str] = []
    esp_spis = set()
    sequence_numbers = []
    payload_lengths = []
    packet_count = 0
    encapsulation = "Direct-ESP"

    for pkt in packets:
        try:
            is_esp = False
            raw_payload = None

            # 1. Direct ESP (IP proto 50 / IPv6 nh 50)
            if pkt.haslayer(IP) and pkt[IP].proto == 50:
                is_esp = True
                raw_payload = bytes(pkt[IP].payload)
            elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 50:
                is_esp = True
                raw_payload = bytes(pkt[IPv6].payload)
            # 2. ESP-in-UDP (UDP 4500 encapsulation)
            elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
                payload_bytes = bytes(pkt[UDP].payload)
                # ESP-in-UDP has non-zero 4-byte SPI at start (unlike IKE NAT-T which starts with 4 zero bytes)
                if len(payload_bytes) >= 8 and payload_bytes[:4] != b"\x00\x00\x00\x00":
                    is_esp = True
                    raw_payload = payload_bytes
                    encapsulation = "ESP-in-UDP"

            if is_esp and raw_payload and len(raw_payload) >= 8:
                packet_count += 1
                spi_num = int.from_bytes(raw_payload[0:4], "big")
                seq_num = int.from_bytes(raw_payload[4:8], "big")

                esp_spis.add(f"0x{spi_num:08x}")
                if len(sequence_numbers) < 20:
                    sequence_numbers.append(seq_num)
                if len(payload_lengths) < 20:
                    payload_lengths.append(len(raw_payload))

        except Exception as e:
            warnings.append(f"ESP packet extraction warning: {str(e)}")

    if packet_count == 0:
        return ESPAnalysisDetail(detected=False), warnings

    esp_detail = ESPAnalysisDetail(
        detected=True,
        spis=sorted(list(esp_spis)),
        packet_count=packet_count,
        sequence_numbers=sequence_numbers,
        payload_lengths=payload_lengths,
        encapsulation=encapsulation,
    )

    return esp_detail, warnings
