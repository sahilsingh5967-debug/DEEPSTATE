#!/usr/bin/env python3
"""
PCAP Inspection and Verification Utility.

Parses binary PCAPs in data/pcaps/real/ and data/pcaps/synthetic/
and displays packet counts, protocol layers, and metadata integrity.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Prevent Scapy from attempting sandbox-restricted OS config reads
os.environ["SCAPY_USE_NETIFACES"] = "0"

try:
    from scapy.config import conf
    conf.read_resolv_conf = False
    from scapy.all import rdpcap, IP, UDP
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    sys.exit(1)


def inspect_pcap_file(pcap_path: Path):
    if not pcap_path.exists():
        print(f"[-] File not found: {pcap_path}")
        return

    file_size = pcap_path.stat().st_size
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[-] Error reading PCAP {pcap_path.name}: {e}")
        return

    print(f"\n============================================================")
    print(f" File: {pcap_path.relative_to(PROJECT_ROOT)}")
    print(f" Size: {file_size} bytes | Packets: {len(packets)}")
    print(f"============================================================")

    protocol_counts = {}
    for pkt in packets:
        proto = "OTHER"
        if pkt.haslayer(UDP) and (pkt[UDP].sport == 500 or pkt[UDP].dport == 500):
            proto = "IKE (UDP 500)"
        elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
            proto = "IKE / NAT-T (UDP 4500)"
        elif pkt.haslayer(IP) and pkt[IP].proto == 50:
            proto = "IPsec ESP (Proto 50)"
        elif pkt.haslayer(IP) and pkt[IP].proto == 51:
            proto = "IPsec AH (Proto 51)"
        elif pkt.haslayer(IP):
            proto = f"IP Proto {pkt[IP].proto}"

        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    for proto, count in protocol_counts.items():
        print(f"  - {proto}: {count} packets")


def main():
    print("Inspecting PCAP files across project directories...")
    
    real_dir = PROJECT_ROOT / "data" / "pcaps" / "real"
    synthetic_dir = PROJECT_ROOT / "data" / "pcaps" / "synthetic"

    real_pcaps = list(real_dir.glob("*.pcap"))
    synthetic_pcaps = list(synthetic_dir.glob("*.pcap"))

    print(f"\n[REAL EXPERIMENTAL CAPTURES] ({len(real_pcaps)} files found)")
    if not real_pcaps:
        print("  (No live Linux IPsec captures recorded yet on this host environment)")
    for p in real_pcaps:
        inspect_pcap_file(p)

    print(f"\n[SYNTHETIC DEVELOPMENT FIXTURES] ({len(synthetic_pcaps)} files found)")
    for p in synthetic_pcaps:
        inspect_pcap_file(p)


if __name__ == "__main__":
    main()
