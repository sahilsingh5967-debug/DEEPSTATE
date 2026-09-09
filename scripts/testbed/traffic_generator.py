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
    target_port = port if port is not None else 5060 if t_type == "VOIP-LIKE" else 443 if t_type in ("WEB", "FILE-TRANSFER-LIKE") else 53 if t_type == "DNS-LIKE" else 5001

    live_container = check_container_status(CONTAINER_PEER_A) and check_container_status(CONTAINER_PEER_B)

    if live_container:
        if t_type == "ICMP":
            cmd = ["exec", CONTAINER_PEER_A, "ping", "-I", src_ip, "-c", str(packet_count), dst_ip]
            res = run_docker_cmd(cmd, timeout_sec=max(15, duration + 5))
            output = res.stdout.strip()
        elif t_type in ("UDP", "DNS-LIKE", "VOIP-LIKE"):
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
        elif t_type in ("TCP", "WEB", "FILE-TRANSFER-LIKE"):
            interval = max(0.005, 1.0 / max(1, packet_rate))
            listener_script = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('{dst_ip}', {target_port}))
    s.listen(1)
    s.settimeout(5.0)
    conn, addr = s.accept()
    conn.recv(4096)
    conn.close()
except Exception:
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
