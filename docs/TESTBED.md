# IPsec VPN Laboratory & Testbed Specification

> **Research & Laboratory Protocol Analysis Environment**

This document describes the laboratory environment and experimental workflow for capturing IPsec VPN network traffic and maintaining ground-truth metadata.

---

## 1. Ground Truth Principles & Capture Classifications

To maintain scientific integrity in security analysis, captures are strictly separated into two distinct categories:

### Category A: Real Experimental Captures (`data/pcaps/real/`)
- **Origin**: Generated exclusively from live Linux strongSwan IPsec deployments.
- **Verification**: SAs are negotiated by the Linux kernel `XFRM` subsystem and verified via `swanctl --list-sas`.
- **Ground-Truth Manifest**: Contains both `intended_configuration` and `observed_negotiated_sa`.
- **Usage**: Used as the definitive ground truth for Phase 3 (Protocol Analyzer), Phase 4 (Security Assessment), and Phase 5 (ML Traffic Classification).

### Category B: Synthetic Development Fixtures (`data/pcaps/synthetic/`)
- **Origin**: Generated via Scapy (`scripts/testbed/generate_synthetic_fixtures.py`).
- **Verification**: Not negotiated by a kernel IPsec stack.
- **Usage**: Intended **strictly for parser development and unit testing**.
- **Important**: **Synthetic fixtures MUST NEVER be represented or labeled as real experimental ground truth.**

---

## 2. Host Environment & Platform Constraints

- **Host OS**: macOS 26.3.1 (Darwin Kernel 25.3.0, ARM64 / Apple Silicon).
- **Kernel IPsec Constraint**: Native Linux kernel `XFRM` / `NETKEY` IPsec subsystem is unavailable on macOS.
- **Virtualization Availability**: Docker CLI and Linux VM runtimes (Colima, Podman, Lima) are not currently installed on this developer machine.
- **Current Status**: Live Linux strongSwan experiment execution is marked **UNEXECUTED_HOST_BLOCKED**. Complete deployment manifests are provided for execution on compatible Linux environments.

---

## 3. Laboratory Topology (Docker / Linux Environment)

When deployed on a Linux machine with Docker, the testbed establishes two peer containers connected over an isolated bridge network (`192.168.100.0/24`):

```
                   Linux Host (Docker Engine)
                               │
            ┌──────────────────┴──────────────────┐
            │   Docker Bridge Network             │
            │   192.168.100.0/24                  │
            │                                     │
    ┌───────┴────────┐                   ┌────────┴────────┐
    │  Peer A        │                   │  Peer B         │
    │  192.168.100.2 │◄═══ IKEv2 / ESP ═►│  192.168.100.3  │
    │  strongSwan    │   (UDP 500/4500)  │  strongSwan     │
    └────────────────┘                   └─────────────────┘
            │
         tcpdump
            │
            ▼
    data/pcaps/real/TEST-001.pcap
```

---

## 4. How to Execute Live IPsec Experiments on Linux

1. Transfer the project repository to a Linux system running Docker & Docker Compose.
2. Navigate to the project root:
   ```bash
   cd ipsec-vpn-analyzer
   ```
3. Run the live testbed script:
   ```bash
   ./scripts/testbed/run_live_testbed.sh
   ```
4. The script will:
   - Bring up Peer A and Peer B containers with `NET_ADMIN` capabilities.
   - Load `swanctl.conf` configurations.
   - Start `tcpdump` packet capture on interface `eth0`.
   - Initiate IKEv2 negotiation (`swanctl --initiate --child test-001-sa`).
   - Query and output negotiated Security Association state (`swanctl --list-sas`).
   - Send test ICMP ping traffic through the IPsec tunnel.
   - Stop capture and save the verified `.pcap` to `data/pcaps/real/TEST-001.pcap`.

---

## 5. Generating Synthetic Fixtures for Local Development

To generate synthetic development fixtures on macOS for parser testing:

```bash
source .venv/bin/activate
python3 scripts/testbed/generate_synthetic_fixtures.py
```

To verify generated PCAP files:

```bash
python3 scripts/testbed/verify_fixtures.py
```
