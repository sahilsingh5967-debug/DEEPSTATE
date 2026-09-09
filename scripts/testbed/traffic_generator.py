"""
Traffic Generator for DEEPSTATE Demonstration Lab 2.0.
Generates live ICMP, UDP, TCP, WEB, DNS-LIKE, VOIP-LIKE, and FILE-TRANSFER-LIKE traffic patterns.
"""

import time
import subprocess
from typing import Dict, Any, Optional
from scripts.testbed.profile_registry import get_profile, get_traffic_profile
from scripts.testbed.profile_runner import check_container_status, run_docker_cmd, CONTAINER_PEER_A, CONTAINER_PEER_B


def generate_experiment_traffic(
    src_ip: str,
    dst_ip: str,
    traffic_type: str,
    packet_count: int = 20,
    duration: int = 5,
    port: Optional[int] = None,
    payload_size: int = 512,
    packet_rate: int = 20
) -> Dict[str, Any]:
    """
    Generates live container or synthetic fallback traffic according to specified experiment parameters.
    """
    t_type = traffic_type.upper()
    target_port = port if port is not None else 5060 if t_type in ("VOIP", "VOIP-LIKE", "VOIP_AUDIO") else 443 if t_type in ("WEB", "WEB-LIKE", "WEB_INTERACTIVE", "FILE_TRANSFER", "FILE-TRANSFER-LIKE", "BULK_TRANSFER") else 53 if t_type in ("DNS", "DNS-LIKE") else 8080 if t_type == "STREAMING_MEDIA" else 5001

    ICMP_TYPES = ("ICMP", "ICMP_DIAGNOSTIC")
    UDP_TYPES = ("UDP", "DNS", "DNS-LIKE", "VOIP", "VOIP-LIKE", "VOIP_AUDIO")
    TCP_TYPES = ("TCP", "WEB", "WEB-LIKE", "WEB_INTERACTIVE", "FILE_TRANSFER", "FILE-TRANSFER-LIKE", "BULK_TRANSFER", "STREAMING_MEDIA")

    if t_type not in ICMP_TYPES and t_type not in UDP_TYPES and t_type not in TCP_TYPES:
        raise ValueError(f"Unsupported or unrecognized traffic_type: '{traffic_type}'. Must be one of ICMP, UDP, TCP, WEB, DNS, VOIP, FILE_TRANSFER or valid Phase 11.5 aliases.")

    live_container = check_container_status(CONTAINER_PEER_A) and check_container_status(CONTAINER_PEER_B)

    if live_container:
        if t_type in ICMP_TYPES:
            cmd = ["exec", CONTAINER_PEER_A, "ping", "-I", src_ip, "-c", str(packet_count), dst_ip]
            res = run_docker_cmd(cmd, timeout_sec=max(15, duration + 5))
            output = res.stdout.strip()
        elif t_type in UDP_TYPES:
            interval = max(0.005, 1.0 / max(1, packet_rate))
            py_script = f"""
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('{src_ip}', 0))
payload = b'X' * {payload_size}
for i in range({packet_count}):
    sock.sendto(payload, ('{dst_ip}', {target_port}))
    time.sleep({interval})
sock.close()
"""
            cmd = ["exec", CONTAINER_PEER_A, "python3", "-c", py_script]
            res = run_docker_cmd(cmd, timeout_sec=max(15, duration + 5))
            output = f"Generated {packet_count} {t_type} UDP datagrams ({payload_size}B) to {dst_ip}:{target_port}"
        elif t_type in TCP_TYPES:
            interval = max(0.005, 1.0 / max(1, packet_rate))
            listener_script = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('{dst_ip}', {target_port}))
    s.listen(1)
    s.settimeout(15.0)
    conn, addr = s.accept()
    conn.settimeout(15.0)
    while True:
        data = conn.recv(65536)
        if not data:
            break
    conn.close()
except Exception as e:
    pass
finally:
    s.close()
"""
            run_docker_cmd(["exec", "-d", CONTAINER_PEER_B, "python3", "-c", listener_script], timeout_sec=5)
            time.sleep(0.3)

            client_script = f"""
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('{src_ip}', 0))
s.settimeout(5.0)
try:
    s.connect(('{dst_ip}', {target_port}))
    payload = b'W' * {payload_size}
    for i in range({packet_count}):
        s.sendall(payload)
        time.sleep({interval})
except Exception as e:
    print('TCP Client Exception:', e)
finally:
    s.close()
"""
            cmd = ["exec", CONTAINER_PEER_A, "python3", "-c", client_script]
            res = run_docker_cmd(cmd, timeout_sec=max(15, duration + 5))
            output = res.stdout.strip() or f"Generated {packet_count} {t_type} TCP packets ({payload_size}B) to {dst_ip}:{target_port}"
        else:
            output = f"Generated {packet_count} {t_type} packets to {dst_ip}"

        return {
            "status": "completed",
            "mode": "live_container",
            "traffic_type": t_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": target_port if t_type != "ICMP" else None,
            "packet_count": packet_count,
            "duration": duration,
            "output": output
        }
    else:
        return {
            "status": "completed",
            "mode": "synthetic_fallback",
            "traffic_type": t_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": target_port if t_type != "ICMP" else None,
            "packet_count": packet_count,
            "duration": duration,
            "output": f"Simulated {packet_count} {t_type} packets in synthetic fallback mode."
        }


def generate_live_traffic(
    profile_id: str,
    traffic_profile_id: str,
    packet_count: int = 10,
    duration: int = 5,
    port: Optional[int] = None
) -> Dict[str, Any]:
    """Backward compatibility wrapper for Phase 9A-1 profile-driven execution."""
    profile = get_profile(profile_id)
    if not profile:
        raise ValueError(f"Unknown IPsec profile_id: '{profile_id}'")

    src_ip = profile["source_ip"]
    dst_ip = profile["destination_ip"]

    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type=traffic_profile_id,
        packet_count=packet_count,
        duration=duration,
        port=port
    )


# --- Phase 11.5 Parameterized Behavioral Traffic Generators ---

def generate_icmp_diagnostic(
    src_ip: str,
    dst_ip: str,
    packet_count: int = 10,
    payload_size: int = 64,
    interval_seconds: float = 1.0,
    burst_count: int = 1
) -> Dict[str, Any]:
    """Generates ICMP ping bursts with controlled payload size and interval."""
    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type="ICMP",
        packet_count=packet_count * burst_count,
        duration=int(max(1, packet_count * interval_seconds * burst_count)),
        payload_size=payload_size
    )


def generate_web_interactive(
    src_ip: str,
    dst_ip: str,
    transaction_count: int = 5,
    request_size: int = 250,
    response_size: int = 1200,
    inter_request_delay: float = 0.5,
    server_port: int = 443
) -> Dict[str, Any]:
    """Generates application-like HTTP request/response exchange patterns."""
    total_pkts = transaction_count * 4
    total_duration = int(max(1, transaction_count * (0.1 + inter_request_delay)))
    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type="WEB",
        packet_count=total_pkts,
        duration=total_duration,
        port=server_port,
        payload_size=request_size
    )


def generate_bulk_transfer(
    src_ip: str,
    dst_ip: str,
    duration_seconds: int = 10,
    chunk_size: int = 1420,
    packet_rate: int = 100,
    server_port: int = 5001
) -> Dict[str, Any]:
    """Generates sustained high-volume bulk transfer streams."""
    total_pkts = duration_seconds * packet_rate
    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type="FILE-TRANSFER-LIKE",
        packet_count=total_pkts,
        duration=duration_seconds,
        port=server_port,
        payload_size=chunk_size,
        packet_rate=packet_rate
    )


def generate_streaming_media(
    src_ip: str,
    dst_ip: str,
    duration_seconds: int = 10,
    burst_duration: float = 1.0,
    idle_duration: float = 0.5,
    avg_packet_size: int = 1200,
    server_port: int = 8080
) -> Dict[str, Any]:
    """Generates variable-rate streaming traffic exhibiting burst/idle timing."""
    active_ratio = burst_duration / (burst_duration + idle_duration)
    packet_rate = int(50 * active_ratio)
    total_pkts = int(duration_seconds * packet_rate)
    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type="TCP",
        packet_count=total_pkts,
        duration=duration_seconds,
        port=server_port,
        payload_size=avg_packet_size
    )


def generate_voip_audio(
    src_ip: str,
    dst_ip: str,
    duration_seconds: int = 10,
    packetization_interval_ms: int = 20,
    frame_size: int = 160,
    server_port: int = 5060
) -> Dict[str, Any]:
    """Generates small periodic audio frame datagrams (default 20ms interval)."""
    pkts_per_sec = int(1000 / max(1, packetization_interval_ms))
    total_pkts = duration_seconds * pkts_per_sec
    return generate_experiment_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        traffic_type="VOIP-LIKE",
        packet_count=total_pkts,
        duration=duration_seconds,
        port=server_port,
        payload_size=frame_size,
        packet_rate=pkts_per_sec
    )
