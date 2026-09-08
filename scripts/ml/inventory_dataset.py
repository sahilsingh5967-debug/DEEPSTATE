#!/usr/bin/env python3
"""
Dataset Inventory & Audit Script.
Phase 5.2.1 — AI-Powered IPsec VPN Protocol Analyzer.

Recursively inspects datasets in data/datasets/public/iscx_vpn2016/
and output metadata to data/datasets/dataset_inventory.json.
Excludes real IPsec ground-truth and synthetic fixtures from public training counts.
"""

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from scapy.all import rdpcap
from backend.app.ml.flow_extractor import extract_flows_from_pcap

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PUBLIC_DATASET_DIR = PROJECT_ROOT / "data" / "datasets" / "public" / "iscx_vpn2016"
REAL_IPSEC_DIR = PROJECT_ROOT / "data" / "pcaps" / "real"
INVENTORY_OUTPUT = PROJECT_ROOT / "data" / "datasets" / "dataset_inventory.json"


def audit_pcaps_in_dir(directory: Path, capture_tier: str) -> List[Dict[str, Any]]:
    records = []
    if not directory.exists():
        return records

    for pcap_file in sorted(directory.rglob("*.pcap")):
        file_size = pcap_file.stat().st_size
        pkt_count = 0
        flow_count = 0
        corrupt = False
        empty = file_size == 0
        error_msg = None

        try:
            flows = extract_flows_from_pcap(str(pcap_file))
            flow_count = len(flows)
            pkt_count = sum(len(f.packets) for f in flows)
            if pkt_count == 0:
                empty = True
        except Exception as e:
            corrupt = True
            error_msg = str(e)

        # Infer class & VPN type from filename
        fname = pcap_file.name.lower()
        vpn_type = "VPN" if "vpn_" in fname and "nonvpn" not in fname else ("Non-VPN" if "nonvpn" in fname else "General/IPsec")

        if "icmp" in fname:
            traffic_class = "ICMP"
        elif "web" in fname:
            traffic_class = "Web Browsing"
        elif "email" in fname:
            traffic_class = "Email"
        elif "chat" in fname:
            traffic_class = "Chat"
        elif "stream" in fname:
            traffic_class = "Streaming"
        elif "file" in fname or "transfer" in fname:
            traffic_class = "File Transfer"
        elif "voip" in fname:
            traffic_class = "VoIP"
        elif "p2p" in fname:
            traffic_class = "P2P"
        else:
            traffic_class = "IPsec Experimental / General"

        records.append({
            "file_name": pcap_file.name,
            "relative_path": str(pcap_file.relative_to(PROJECT_ROOT)),
            "capture_tier": capture_tier,
            "traffic_class": traffic_class,
            "vpn_type": vpn_type,
            "file_size_bytes": file_size,
            "packet_count": pkt_count,
            "extracted_flow_count": flow_count,
            "is_corrupt": corrupt,
            "is_empty": empty,
            "error_notes": error_msg
        })

    return records


def generate_inventory() -> Dict[str, Any]:
    print("============================================================")
    print(" Generating Dataset Inventory & Audit (Phase 5.2.1)...")
    print("============================================================")

    public_records = audit_pcaps_in_dir(PUBLIC_DATASET_DIR, "PUBLIC_DATASET")
    real_records = audit_pcaps_in_dir(REAL_IPSEC_DIR, "REAL_IPSEC_GROUND_TRUTH")

    # Metrics for PUBLIC training set only
    pub_files = len(public_records)
    pub_bytes = sum(r["file_size_bytes"] for r in public_records)
    pub_packets = sum(r["packet_count"] for r in public_records)
    pub_flows = sum(r["extracted_flow_count"] for r in public_records)

    sizes = [r["file_size_bytes"] for r in public_records if r["file_size_bytes"] > 0]
    pkts = [r["packet_count"] for r in public_records]

    min_size = min(sizes) if sizes else 0
    max_size = max(sizes) if sizes else 0
    avg_size = (pub_bytes / pub_files) if pub_files > 0 else 0.0

    min_pkts = min(pkts) if pkts else 0
    max_pkts = max(pkts) if pkts else 0
    avg_pkts = (pub_packets / pub_files) if pub_files > 0 else 0.0

    class_distribution: Dict[str, int] = {}
    vpn_distribution: Dict[str, int] = {}
    files_per_class: Dict[str, int] = {}
    files_per_vpn_type: Dict[str, int] = {}

    for r in public_records:
        tc = r["traffic_class"]
        vt = r["vpn_type"]
        fc = r["extracted_flow_count"]

        class_distribution[tc] = class_distribution.get(tc, 0) + fc
        vpn_distribution[vt] = vpn_distribution.get(vt, 0) + fc
        files_per_class[tc] = files_per_class.get(tc, 0) + 1
        files_per_vpn_type[vt] = files_per_vpn_type.get(vt, 0) + 1

    # Check duplicates & corrupts
    filenames = [r["file_name"] for r in public_records]
    duplicate_files = [f for f in set(filenames) if filenames.count(f) > 1]
    corrupt_files = [r["file_name"] for r in public_records if r["is_corrupt"]]
    empty_files = [r["file_name"] for r in public_records if r["is_empty"]]

    inventory = {
        "inventory_timestamp": datetime.datetime.now().isoformat(),
        "inventory_status": "VALIDATED",
        "public_dataset_metrics": {
            "total_pcap_files": pub_files,
            "total_size_bytes": pub_bytes,
            "total_size_mb": round(pub_bytes / (1024 * 1024), 2),
            "total_packet_count": pub_packets,
            "total_extracted_flow_count": pub_flows,
            "capture_size_metrics": {
                "min_file_size_bytes": min_size,
                "max_file_size_bytes": max_size,
                "average_file_size_bytes": round(avg_size, 2)
            },
            "packet_count_metrics": {
                "min_packets_per_capture": min_pkts,
                "max_packets_per_capture": max_pkts,
                "average_packets_per_capture": round(avg_pkts, 2)
            },
            "traffic_class_distribution": class_distribution,
            "vpn_vs_nonvpn_distribution": vpn_distribution,
            "files_per_traffic_class": files_per_class,
            "files_per_vpn_type": files_per_vpn_type
        },
        "quality_flags": {
            "duplicate_files_count": len(duplicate_files),
            "duplicate_files": duplicate_files,
            "corrupt_files_count": len(corrupt_files),
            "corrupt_files": corrupt_files,
            "empty_files_count": len(empty_files),
            "empty_files": empty_files
        },
        "public_files_detail": public_records,
        "real_ipsec_ground_truth_isolated": [r["file_name"] for r in real_records]
    }

    INVENTORY_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(INVENTORY_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)

    print(f"[+] Inventory complete. Saved to: {INVENTORY_OUTPUT}")
    print(f" Public PCAPs: {pub_files}")
    print(f" Total Disk Volume: {pub_bytes / (1024*1024):.2f} MB")
    print(f" Total Packets: {pub_packets:,}")
    print(f" Total Extracted Flows: {pub_flows:,}")
    print(f" Target Classes Covered: {list(class_distribution.keys())}")
    print("============================================================")
    return inventory


if __name__ == "__main__":
    generate_inventory()
