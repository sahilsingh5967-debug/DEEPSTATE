#!/usr/bin/env bash
# ==============================================================================
# Live Linux strongSwan IPsec Experiment Execution Script
# ==============================================================================
# Executes live IPsec tests on Docker Desktop / Linux environment.
# Generates REAL ground-truth captures in data/pcaps/real/ and extracts verified SAs.

set -euo pipefail

export PATH="/Users/shahilraj/.docker/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REAL_PCAP_DIR="${PROJECT_ROOT}/data/pcaps/real"

mkdir -p "${REAL_PCAP_DIR}"

echo "============================================================"
echo " Starting strongSwan IPsec Testbed via Docker Compose..."
echo "============================================================"

docker compose -f "${SCRIPT_DIR}/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "${SCRIPT_DIR}/docker-compose.yml" up -d

echo "Waiting for containers and strongSwan initialization (15s)..."
echo "Waiting for containers and strongSwan initialization..."
for i in {1..30}; do
  if docker exec ipsec-peer-a swanctl --list-conns &>/dev/null && docker exec ipsec-peer-b swanctl --list-conns &>/dev/null; then
    echo "Both strongSwan peers are ready."
    break
  fi
  sleep 2
done

# Ensure loopback IPs for tunnel endpoints exist
docker exec ipsec-peer-a ip addr add 10.1.0.1/24 dev lo 2>/dev/null || true
docker exec ipsec-peer-b ip addr add 10.2.0.1/24 dev lo 2>/dev/null || true

# Reload configurations explicitly
docker exec ipsec-peer-a swanctl --load-all
docker exec ipsec-peer-b swanctl --load-all

echo "[2/4] Starting packet capture on Peer A..."
docker exec -d ipsec-peer-a tcpdump -i eth0 -w /captures/TEST-001.pcap udp port 500 or udp port 4500 or ip proto 50 or ip proto 1

sleep 2

echo "[3/4] Initiating IKEv2 Tunnel (TEST-001)..."
docker exec ipsec-peer-a swanctl --initiate --child test-001-sa

echo "[4/4] Verifying negotiated Security Association (SA)..."
docker exec ipsec-peer-a swanctl --list-sas

# Trigger test ICMP traffic through tunnel (from 10.1.0.1 to 10.2.0.1)
echo "Sending test ICMP traffic through tunnel..."
docker exec ipsec-peer-a ping -I 10.1.0.1 -c 5 10.2.0.1 || true

sleep 3

# Verify SA packet counters after traffic
echo "Inspecting negotiated Security Associations after traffic..."
docker exec ipsec-peer-a swanctl --list-sas

# Stop tcpdump gracefully
docker exec ipsec-peer-a bash -c "kill -2 \$(pidof tcpdump) 2>/dev/null || kill \$(pidof tcpdump) 2>/dev/null || true"

sleep 2

echo "============================================================"
echo " Experiment TEST-001 Complete."
echo " Real PCAP saved to: data/pcaps/real/TEST-001.pcap"
echo "============================================================"
