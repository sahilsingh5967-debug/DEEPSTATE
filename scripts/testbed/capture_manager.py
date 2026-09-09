"""
PCAP Capture Lifecycle Manager for DEEPSTATE Demonstration Lab 2.0.
Manages tcpdump capture sessions, custom operator experiment captures, PCAP file verification, synthetic fallback generation, and metadata extraction.
"""

import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from scripts.testbed.profile_registry import get_profile, get_traffic_profile
from scripts.testbed.profile_runner import (
    check_container_status, run_docker_cmd, initiate_ipsec_profile, CONTAINER_PEER_A
)
from scripts.testbed.traffic_generator import generate_live_traffic, generate_experiment_traffic
from scripts.testbed.experiment_model import ExperimentConfig
from scripts.testbed.experiment_history import save_experiment_record


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
GENERATED_PCAP_DIR = PROJECT_ROOT / "data" / "pcaps" / "generated"
GENERATED_PCAP_DIR.mkdir(parents=True, exist_ok=True)


def create_synthetic_demo_pcap(
    filepath: Path,
    profile_id: str = "TEST-001",
    traffic_type: str = "ICMP",
    packet_count: int = 20,
    payload_size: int = 512,
    mode: str = "tunnel"
) -> int:
    """Generates a valid synthetic PCAP file for demonstration lab testing when live Docker is unavailable."""
    os.environ["SCAPY_USE_NETIFACES"] = "0"
    try:
        from scapy.config import conf
        conf.read_resolv_conf = False
    except Exception:
        pass

    from scapy.all import IP, UDP, TCP, ICMP, Raw, wrpcap
    from scapy.layers.isakmp import ISAKMP

    profile = get_profile(profile_id) or get_profile("TEST-001")
    src_ip = profile.get("source_ip", "10.1.0.1")
    dst_ip = profile.get("destination_ip", "10.2.0.1")

    packets = []

    # 1. IKE_SA_INIT negotiation frame (UDP 500)
    isakmp_hdr = ISAKMP(
        init_cookie=os.urandom(8),
        resp_cookie=b"\x00" * 8,
        next_payload=33,
        version=0x20,
        exch_type=34,
        flags=0x08,
        id=0
    )
    payload = Raw(load=b"\x00\x00\x00\x28\x00\x00\x00\x24\x01\x01\x00\x00" + b"\x00" * 24)
    packets.append(IP(src="192.168.100.2", dst="192.168.100.3") / UDP(sport=500, dport=500) / isakmp_hdr / payload)

    # 2. Encrypted ESP frames (proto 50) representing IPsec tunnel payload
    raw_payload_len = max(32, min(payload_size, 1400))
    for seq in range(1, packet_count + 1):
        esp_header = Raw(load=(0x12345678).to_bytes(4, 'big') + seq.to_bytes(4, 'big') + os.urandom(raw_payload_len))
        packets.append(IP(src="192.168.100.2", dst="192.168.100.3", proto=50) / esp_header)

    wrpcap(str(filepath), packets)
    return len(packets)


def count_pcap_packets(filepath: Path) -> int:
    """Counts number of packets in a PCAP file using Scapy or binary header counting."""
    try:
        os.environ["SCAPY_USE_NETIFACES"] = "0"
        try:
            from scapy.config import conf
            conf.read_resolv_conf = False
        except Exception:
            pass
        from scapy.all import rdpcap
        pkts = rdpcap(str(filepath))
        return len(pkts)
    except Exception:
        size = filepath.stat().st_size
        return max(1, size // 120)


def execute_custom_experiment_capture(config: ExperimentConfig) -> Dict[str, Any]:
    """
    Executes an operator-configured IPsec experiment capture lifecycle:
    1. Generates unique capture filename
    2. Determines live container vs synthetic execution mode
    3. Initiates IPsec SA & tcpdump packet capture if containers active
    4. Generates operator-configured traffic pattern
    5. Finalizes PCAP & records experiment history metadata
    """
    capture_uuid = uuid.uuid4().hex[:8]
    exp_id = f"EXP-{capture_uuid}"
    timestamp = int(time.time())
    iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    filename = f"DEMO_{timestamp}_{config.mode}_{config.encryption}_{config.traffic_type}_{capture_uuid}.pcap"
    out_filepath = GENERATED_PCAP_DIR / filename

    requested_mode = config.execution_mode.lower()
    live_container = check_container_status(CONTAINER_PEER_A) if requested_mode != "synthetic" else False

    start_time = time.time()

    if live_container:
        try:
            # Map configuration to swanctl initiate profile if available, else test-001/002/003
            init_profile = "TEST-002" if "GCM" in config.encryption else "TEST-003" if config.mode == "transport" else "TEST-001"
            initiate_ipsec_profile(init_profile)

            container_pcap_path = f"/captures/generated/{filename}"
            run_docker_cmd(["exec", CONTAINER_PEER_A, "mkdir", "-p", "/captures/generated"], timeout_sec=5)

            tcpdump_cmd = [
                "exec", "-d", CONTAINER_PEER_A,
                "tcpdump", "-i", "eth0", "-w", container_pcap_path,
                "udp", "port", "500",
                "or", "udp", "port", "4500",
                "or", "ip", "proto", "50",
                "or", "ip", "proto", "1",
                "or", "tcp", "port", str(config.destination_port),
                "or", "udp", "port", str(config.destination_port)
            ]
            run_docker_cmd(tcpdump_cmd, timeout_sec=5)
            time.sleep(1.0)

            generate_experiment_traffic(
                src_ip=config.peer_a.traffic_ip,
                dst_ip=config.peer_b.traffic_ip,
                traffic_type=config.traffic_type,
                packet_count=config.packet_count,
                duration=config.duration,
                port=config.destination_port,
                payload_size=config.payload_size,
                packet_rate=config.packet_rate
            )

            time.sleep(1.5)

            stop_cmd = ["exec", CONTAINER_PEER_A, "bash", "-c", "kill -2 $(pidof tcpdump) 2>/dev/null || true"]
            run_docker_cmd(stop_cmd, timeout_sec=5)
            time.sleep(1.0)

            if not out_filepath.exists() or out_filepath.stat().st_size == 0:
                run_docker_cmd(["cp", f"{CONTAINER_PEER_A}:{container_pcap_path}", str(out_filepath)], timeout_sec=5)
        except Exception as err:
            print(f"Live container experiment execution notice: {err}")

    if not out_filepath.exists() or out_filepath.stat().st_size == 0:
        actual_packets = create_synthetic_demo_pcap(
            filepath=out_filepath,
            profile_id="TEST-002" if "GCM" in config.encryption else "TEST-001",
            traffic_type=config.traffic_type,
            packet_count=config.packet_count,
            payload_size=config.payload_size,
            mode=config.mode
        )
        execution_mode = "synthetic_fallback"
    else:
        actual_packets = count_pcap_packets(out_filepath)
        execution_mode = "live_container"

    duration_sec = round(time.time() - start_time, 2)
    file_size = out_filepath.stat().st_size
    rel_path = str(out_filepath.relative_to(PROJECT_ROOT))

    capture_metadata = {
        "experiment_id": exp_id,
        "capture_id": f"CAP-{capture_uuid}",
        "profile_id": config.name,
        "traffic_profile": config.traffic_type,
        "name": config.name,
        "status": "completed",
        "timestamp": iso_time,
        "file_path": rel_path,
        "absolute_path": str(out_filepath),
        "packet_count": actual_packets,
        "size_bytes": file_size,
        "duration_seconds": duration_sec,
        "execution_mode": execution_mode,
        "tunnel_status": "established",
        "analysis_status": "pending",
        "config": config.model_dump()
    }

    # Save to persistent history log
    save_experiment_record(capture_metadata)

    return capture_metadata


def execute_testbed_capture(
    profile_id: str,
    traffic_profile_id: str,
    duration: int = 5,
    packet_count: int = 20,
    port: Optional[int] = None
) -> Dict[str, Any]:
    """Backward compatibility wrapper for Phase 9A-1 profile capture."""
    prof = get_profile(profile_id)
    if not prof:
        raise ValueError(f"Invalid profile_id: '{profile_id}'")

    exp_config = ExperimentConfig(
        name=f"Profile {profile_id} ({traffic_profile_id})",
        mode=prof["mode"],
        encryption=prof["encryption"],
        integrity=prof["integrity"],
        dh_group=prof["dh_group"],
        traffic_type=traffic_profile_id,
        destination_port=port or (5060 if traffic_profile_id == "VOIP-LIKE" else 5001),
        packet_count=packet_count,
        duration=duration
    )
    res = execute_custom_experiment_capture(exp_config)
    res["profile_id"] = profile_id
    res["traffic_profile"] = traffic_profile_id
    return res
