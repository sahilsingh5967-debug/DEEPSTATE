import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Prevent Scapy sandbox DNS read issues
os.environ["SCAPY_USE_NETIFACES"] = "0"
try:
    from scapy.config import conf
    conf.read_resolv_conf = False
except Exception:
    pass

from scapy.all import Packet, rdpcap


def read_pcap_file(file_path: str) -> Tuple[List[Packet], Dict[str, Any], List[str]]:
    """
    Safely loads a PCAP file and extracts basic file metadata.
    Handles missing files, zero-byte captures, and malformed files without crashing.

    Returns:
        Tuple of (packets_list, metadata_dict, warnings_list)
    """
    warnings: List[str] = []
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file does not exist: {file_path}")

    file_size = path.stat().st_size
    if file_size == 0:
        warnings.append("PCAP file is empty (0 bytes).")
        return [], {
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": 0,
            "packet_count": 0,
            "duration_seconds": 0.0,
        }, warnings

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        warnings.append(f"Scapy failed to parse PCAP cleanly: {str(e)}")
        return [], {
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": file_size,
            "packet_count": 0,
            "duration_seconds": 0.0,
        }, warnings

    packet_count = len(packets)
    duration = 0.0
    first_ts = None
    last_ts = None

    if packet_count > 0:
        try:
            timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, "time")]
            if timestamps:
                first_ts = min(timestamps)
                last_ts = max(timestamps)
                duration = max(0.0, last_ts - first_ts)
        except Exception:
            warnings.append("Unable to extract timing metadata from packet timestamps.")

    metadata = {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "file_size_bytes": file_size,
        "packet_count": packet_count,
        "duration_seconds": round(duration, 4),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
    }

    return list(packets), metadata, warnings
