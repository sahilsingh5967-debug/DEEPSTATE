"""
Feature Extraction Module.
Phase 5.2 — AI-Powered IPsec VPN Protocol Analyzer.

Extracts volumetric, statistical length, inter-arrival time (IAT), directional ratio,
and IPsec protocol context features from Flow instances.
Maintains strict separation between predictive ML feature vectors and metadata/label columns.
"""

import math
from pathlib import Path
from typing import Dict, Any, List
from backend.app.ml.flow_extractor import Flow, FlowPacket
from backend.app.ml.schema import (
    map_legacy_class_to_behavioral,
    SOURCE_SYNTHETIC_DEVELOPMENT,
    CLASS_UNKNOWN_UNCLASSIFIED
)

# Feature column names list (predictive ML vector ONLY - no labels/IPs)
ML_FEATURE_COLUMNS = [
    "flow_duration_seconds",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_skewness",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_min",
    "flow_iat_max",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "fwd_bwd_packet_ratio",
    "fwd_bwd_byte_ratio",
    "esp_packet_count",
    "has_ike",
    "has_esp",
    "has_udp_4500"
]

METADATA_COLUMNS = [
    "dataset_id",
    "dataset_source",
    "capture_id",
    "session_id",
    "flow_id",
    "traffic_class",
    "behavioral_class"
]


def _calc_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "skew": 0.0}

    n = len(values)
    mean_val = sum(values) / n
    min_val = min(values)
    max_val = max(values)

    if n < 2:
        return {"mean": mean_val, "std": 0.0, "min": min_val, "max": max_val, "skew": 0.0}

    var_val = sum((x - mean_val) ** 2 for x in values) / (n - 1)
    std_val = math.sqrt(var_val)

    if std_val > 1e-6 and n > 2:
        m3 = sum((x - mean_val) ** 3 for x in values) / n
        skew_val = m3 / (std_val ** 3)
    else:
        skew_val = 0.0

    return {
        "mean": mean_val,
        "std": std_val,
        "min": min_val,
        "max": max_val,
        "skew": skew_val
    }


def _calc_iats(packets: List[FlowPacket]) -> List[float]:
    if len(packets) < 2:
        return []
    sorted_times = sorted([p.timestamp for p in packets])
    return [max(0.0, sorted_times[i] - sorted_times[i - 1]) for i in range(1, len(sorted_times))]


def extract_features_from_flow(
    flow: Flow,
    dataset_id: str = "ISCX-VPN2016",
    dataset_source: str = SOURCE_SYNTHETIC_DEVELOPMENT,
    session_id: str = None,
    behavioral_class: str = None
) -> Dict[str, Any]:
    """
    Extracts structured feature record for a single Flow.
    Returns dictionary with both metadata and predictive features.
    """
    pkts = flow.packets
    fwd_pkts = flow.fwd_packets
    bwd_pkts = flow.bwd_packets

    duration = flow.duration_seconds
    total_pkts = len(pkts)
    fwd_pkt_count = len(fwd_pkts)
    bwd_pkt_count = len(bwd_pkts)

    fwd_lengths = [float(p.length) for p in fwd_pkts]
    bwd_lengths = [float(p.length) for p in bwd_pkts]
    all_lengths = [float(p.length) for p in pkts]

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    total_bytes = total_fwd_bytes + total_bwd_bytes

    pkts_per_sec = (total_pkts / duration) if duration > 1e-6 else 0.0
    bytes_per_sec = (total_bytes / duration) if duration > 1e-6 else 0.0

    len_stats = _calc_stats(all_lengths)
    fwd_len_stats = _calc_stats(fwd_lengths)
    bwd_len_stats = _calc_stats(bwd_lengths)

    flow_iats = _calc_iats(pkts)
    fwd_iats = _calc_iats(fwd_pkts)
    bwd_iats = _calc_iats(bwd_pkts)

    flow_iat_stats = _calc_stats(flow_iats)
    fwd_iat_stats = _calc_stats(fwd_iats)
    bwd_iat_stats = _calc_stats(bwd_iats)

    fwd_bwd_pkt_ratio = (fwd_pkt_count / (bwd_pkt_count + 1.0))
    fwd_bwd_byte_ratio = (total_fwd_bytes / (total_bwd_bytes + 1.0))

    esp_count = sum(1 for p in pkts if p.has_esp or p.protocol == 50)
    has_ike_flag = int(any(p.has_ike for p in pkts))
    has_esp_flag = int(esp_count > 0)
    has_udp_4500_flag = int(flow.src_port == 4500 or flow.dst_port == 4500)

    eff_session_id = session_id or flow.pcap_source or "UNKNOWN_SESSION"
    eff_behavioral_class = behavioral_class or map_legacy_class_to_behavioral(flow.traffic_class)

    feature_dict = {
        # Metadata
        "dataset_id": dataset_id,
        "dataset_source": dataset_source,
        "capture_id": flow.pcap_source,
        "session_id": eff_session_id,
        "flow_id": flow.flow_id,
        "traffic_class": flow.traffic_class,
        "behavioral_class": eff_behavioral_class,

        # Volumetric
        "flow_duration_seconds": round(duration, 6),
        "total_fwd_packets": fwd_pkt_count,
        "total_bwd_packets": bwd_pkt_count,
        "total_packets": total_pkts,
        "total_fwd_bytes": int(total_fwd_bytes),
        "total_bwd_bytes": int(total_bwd_bytes),
        "total_bytes": int(total_bytes),
        "packets_per_second": round(pkts_per_sec, 4),
        "bytes_per_second": round(bytes_per_sec, 4),

        # Length Statistics
        "pkt_len_mean": round(len_stats["mean"], 4),
        "pkt_len_std": round(len_stats["std"], 4),
        "pkt_len_min": int(len_stats["min"]),
        "pkt_len_max": int(len_stats["max"]),
        "pkt_len_skewness": round(len_stats["skew"], 4),
        "fwd_pkt_len_mean": round(fwd_len_stats["mean"], 4),
        "bwd_pkt_len_mean": round(bwd_len_stats["mean"], 4),

        # Temporal / IAT Statistics
        "flow_iat_mean": round(flow_iat_stats["mean"], 6),
        "flow_iat_std": round(flow_iat_stats["std"], 6),
        "flow_iat_min": round(flow_iat_stats["min"], 6),
        "flow_iat_max": round(flow_iat_stats["max"], 6),
        "fwd_iat_mean": round(fwd_iat_stats["mean"], 6),
        "bwd_iat_mean": round(bwd_iat_stats["mean"], 6),

        # Directional Ratios
        "fwd_bwd_packet_ratio": round(fwd_bwd_pkt_ratio, 4),
        "fwd_bwd_byte_ratio": round(fwd_bwd_byte_ratio, 4),

        # IPsec Context
        "esp_packet_count": esp_count,
        "has_ike": has_ike_flag,
        "has_esp": has_esp_flag,
        "has_udp_4500": has_udp_4500_flag
    }

    return feature_dict


def extract_features_from_flows(
    flows: List[Flow],
    dataset_id: str = "ISCX-VPN2016",
    dataset_source: str = SOURCE_SYNTHETIC_DEVELOPMENT,
    session_id: str = None,
    behavioral_class: str = None
) -> List[Dict[str, Any]]:
    return [
        extract_features_from_flow(
            f,
            dataset_id=dataset_id,
            dataset_source=dataset_source,
            session_id=session_id,
            behavioral_class=behavioral_class
        )
        for f in flows
    ]


def generate_features_csv(input_dir: str, output_csv: str) -> str:
    import csv
    from pathlib import Path
    from backend.app.ml.flow_extractor import extract_flows_from_pcap

    in_path = Path(input_dir)
    out_path = Path(output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_records = []
    pcap_files = sorted(list(in_path.rglob("*.pcap")))

    print(f"[*] Extracting features from {len(pcap_files)} PCAPs in {input_dir}...")

    for pfile in pcap_files:
        # Determine class label from filename
        fname = pfile.name.lower()
        if "icmp" in fname:
            tc = "ICMP"
        elif "web" in fname:
            tc = "Web Browsing"
        elif "email" in fname:
            tc = "Email"
        elif "chat" in fname:
            tc = "Chat"
        elif "stream" in fname:
            tc = "Streaming"
        elif "file" in fname or "transfer" in fname:
            tc = "File Transfer"
        elif "voip" in fname:
            tc = "VoIP"
        elif "p2p" in fname:
            tc = "P2P"
        else:
            tc = "UNKNOWN"

        flows = extract_flows_from_pcap(str(pfile), traffic_class=tc)
        records = extract_features_from_flows(flows, dataset_id="ISCX-VPN2016")
        all_records.extend(records)

    if not all_records:
        print("[!] No flows extracted.")
        return str(out_path)

    fieldnames = METADATA_COLUMNS + ML_FEATURE_COLUMNS

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)

    print(f"[+] Extracted {len(all_records)} flow feature records to {out_path}")
    return str(out_path)


if __name__ == "__main__":
    import sys
    inp = "data/datasets/public/iscx_vpn2016"
    out = "data/datasets/features/iscx_vpn2016_features.csv"
    if Path(inp).exists():
        generate_features_csv(inp, out)

