"""
StrongSwan Peer Execution Runner for DEEPSTATE Demonstration Lab.
Handles Docker container verification, configuration loading, SA initiation, and status queries.
"""

import shutil
import subprocess
from typing import Dict, Any, List, Optional
from scripts.testbed.profile_registry import get_profile, get_all_profiles


CONTAINER_PEER_A = "ipsec-peer-a"
CONTAINER_PEER_B = "ipsec-peer-b"


def find_docker_binary() -> Optional[str]:
    """Locates docker executable in system PATH or standard macOS/Linux paths."""
    docker_bin = shutil.which("docker")
    if docker_bin:
        return docker_bin

    candidates = [
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/Users/shahilraj/.docker/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker"
    ]
    for c in candidates:
        if shutil.which(c) or subprocess.run(["test", "-x", c], capture_output=True).returncode == 0:
            return c
    return None


def run_docker_cmd(args: List[str], timeout_sec: int = 10) -> subprocess.CompletedProcess:
    """Executes a docker command safely."""
    docker_bin = find_docker_binary()
    if not docker_bin:
        raise RuntimeError("Docker binary not found on host system.")
    return subprocess.run([docker_bin] + args, capture_output=True, text=True, timeout=timeout_sec)


def check_docker_availability() -> bool:
    """Returns True if docker binary exists and docker daemon is responding."""
    try:
        res = run_docker_cmd(["info"], timeout_sec=5)
        return res.returncode == 0
    except Exception:
        return False


def check_container_status(container_name: str) -> bool:
    """Returns True if the specified container is currently running."""
    try:
        res = run_docker_cmd(["inspect", "-f", "{{.State.Running}}", container_name], timeout_sec=5)
        return res.returncode == 0 and res.stdout.strip() == "true"
    except Exception:
        return False


def get_testbed_status() -> Dict[str, Any]:
    """
    Returns complete testbed operational status:
    - docker_available
    - peer_a_status
    - peer_b_status
    - strongswan_status
    - active_tunnels
    """
    docker_ok = check_docker_availability()
    peer_a_ok = check_container_status(CONTAINER_PEER_A) if docker_ok else False
    peer_b_ok = check_container_status(CONTAINER_PEER_B) if docker_ok else False

    strongswan_ok = False
    active_tunnels: List[str] = []

    if peer_a_ok:
        try:
            res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--list-sas"], timeout_sec=5)
            if res.returncode == 0:
                strongswan_ok = True
                output = res.stdout.strip()
                for line in output.splitlines():
                    line_str = line.strip()
                    if line_str and not line_str.startswith(" ") and ":" in line_str:
                        active_tunnels.append(line_str.split(":")[0])
        except Exception:
            pass

    return {
        "docker_available": docker_ok,
        "peer_a_status": "running" if peer_a_ok else "offline",
        "peer_b_status": "running" if peer_b_ok else "offline",
        "strongswan_status": "active" if strongswan_ok else "inactive",
        "active_tunnels": active_tunnels,
        "mode": "live_container" if (peer_a_ok and peer_b_ok) else "synthetic_fallback"
    }


def ensure_peers_running() -> Dict[str, Any]:
    """Verifies peers are running. Throws RuntimeError if containers are offline."""
    status = get_testbed_status()
    if not status["docker_available"]:
        raise RuntimeError("Docker daemon is not available on host system.")
    if status["peer_a_status"] != "running" or status["peer_b_status"] != "running":
        raise RuntimeError("StrongSwan peer containers (ipsec-peer-a, ipsec-peer-b) are not running.")
    return status


def initiate_ipsec_profile(profile_id: str) -> Dict[str, Any]:
    """
    Loads swanctl config and initiates the requested CHILD_SA for the given profile_id.
    """
    profile = get_profile(profile_id)
    if not profile:
        raise ValueError(f"Unknown IPsec profile_id: '{profile_id}'")

    child_sa = profile["child_sa_name"]
    ensure_peers_running()

    # 1. Ensure loopback aliases exist
    run_docker_cmd(["exec", CONTAINER_PEER_A, "ip", "addr", "add", "10.1.0.1/24", "dev", "lo"], timeout_sec=5)
    run_docker_cmd(["exec", CONTAINER_PEER_B, "ip", "addr", "add", "10.2.0.1/24", "dev", "lo"], timeout_sec=5)

    # 2. Reload configurations
    load_res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--load-all"], timeout_sec=10)
    if load_res.returncode != 0:
        raise RuntimeError(f"Failed to load swanctl configs on Peer A: {load_res.stderr.strip()}")

    run_docker_cmd(["exec", CONTAINER_PEER_B, "swanctl", "--load-all"], timeout_sec=10)

    # 3. Initiate CHILD_SA
    init_res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--initiate", "--child", child_sa], timeout_sec=15)
    if init_res.returncode != 0 and "established successfully" not in init_res.stdout:
        # Check if already active
        sas_res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--list-sas"], timeout_sec=5)
        if child_sa not in sas_res.stdout:
            raise RuntimeError(f"Failed to initiate IPsec child SA '{child_sa}': {init_res.stderr.strip() or init_res.stdout.strip()}")

    # 4. Fetch negotiated SA info
    sas_res = run_docker_cmd(["exec", CONTAINER_PEER_A, "swanctl", "--list-sas"], timeout_sec=5)

    return {
        "status": "initiated",
        "profile_id": profile_id,
        "child_sa_name": child_sa,
        "sa_details": sas_res.stdout.strip()
    }
