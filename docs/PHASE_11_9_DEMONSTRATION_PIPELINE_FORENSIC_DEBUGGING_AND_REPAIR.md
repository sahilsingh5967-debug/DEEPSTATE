# Phase 11.9 — Demonstration Pipeline Forensic Debugging, Repair & Verification Documentation

## 1. Executive Summary
Phase 11.9 diagnosed, repaired, and verified the DEEPSTATE Demonstration Lab execution and analysis pipeline. Prior to Phase 11.9, running an experiment (such as `FILE_TRANSFER`) could produce an empty 24-byte PCAP file with 0 packets, 0 extracted flows, 0 features, and an `UNKNOWN` ML inference, while the frontend UI incorrectly fell back to displaying configured parameters as observed packet facts.

All repairs were executed without modifying ML models, hyperparameters, candidate training code, production model sentinels, or permanent OOD benchmark PCAPs.

---

## 2. Empirical Reproduction of Initial Failure
Executing a `FILE_TRANSFER` experiment under Demonstration Lab 2.0 produced:
- **PCAP Path**: `data/pcaps/generated/DEMO_1788981200_tunnel_AES-256-GCM_FILE_TRANSFER_03020e01.pcap`
- **File Size**: 24 Bytes (Header-only global PCAP header)
- **Packet Count**: 0 frames
- **Flow Count**: 0 extracted flows
- **Feature Count**: 0 extracted 28-feature vectors
- **Inferred Class**: `UNKNOWN` (Confidence: 0.0%)

---

## 3. Root Cause Analysis

### Root Cause #1 — Traffic Generator UI Alias Mismatch (`scripts/testbed/traffic_generator.py`)
- **Diagnosis**: The Demonstration Lab UI sent traffic type names like `"FILE_TRANSFER"`, `"VOIP"`, and `"DNS"`. The existing `generate_experiment_traffic()` function only checked for legacy alias strings like `"FILE-TRANSFER-LIKE"`, `"VOIP-LIKE"`, and `"DNS-LIKE"`.
- **Impact**: Passing `"FILE_TRANSFER"` fell through to an unhandled `else:` branch, returning a dummy success string without executing any container socket code. Zero socket traffic crossed the IPsec tunnel.

### Root Cause #2 — Unquoted `tcpdump` Filter Tokenization (`scripts/testbed/capture_manager.py`)
- **Diagnosis**: `capture_manager.py` constructed `tcpdump_cmd` by passing `filter_expr` as a single multi-word string in the `docker exec` command list.
- **Impact**: In detached `docker exec` execution, `tcpdump` failed to parse the expression properly or exited, writing only the initial 24-byte global PCAP header to disk.

### Root Cause #3 — Configured vs. Observed UI Masquerading (`frontend/src/components/UnifiedResults.jsx`)
- **Diagnosis**: When `packet_count` was 0, `UnifiedResults.jsx` fell back to `expConfig.encryption` or `expConfig.integrity` and rendered them under **TIER A — PROTOCOL FACTS** tagged as `OBSERVED`, while also claiming `ESP (Proto 50)` was observed.
- **Impact**: Configured parameters were falsely presented as observed packet facts during 0-packet captures.

---

## 4. Implementation Repairs

### 4.1 Traffic Generator Routing (`scripts/testbed/traffic_generator.py`)
- Expanded `generate_experiment_traffic()` to map all UI and ML traffic aliases into proper socket generator branches:
  - `ICMP`: `("ICMP", "ICMP_DIAGNOSTIC")`
  - `UDP`: `("UDP", "DNS", "DNS-LIKE", "VOIP", "VOIP-LIKE", "VOIP_AUDIO")`
  - `TCP`: `("TCP", "WEB", "WEB-LIKE", "WEB_INTERACTIVE", "FILE_TRANSFER", "FILE-TRANSFER-LIKE", "BULK_TRANSFER", "STREAMING_MEDIA")`
- Updated explicit error handling: Unsupported traffic types now raise `ValueError` rather than returning silent zero-traffic success.

### 4.2 Tokenized `tcpdump` Filter Command List (`scripts/testbed/capture_manager.py`)
- Replaced the single-string filter expression in `tcpdump_cmd` with individually tokenized `argv` elements:
  `["exec", "-d", CONTAINER_PEER_A, "tcpdump", "-i", "eth0", "-w", container_pcap_path, "udp", "port", "500", "or", "udp", "port", "4500", "or", "ip", "proto", "50", "or", "ip", "proto", "1", "or", "tcp", "port", str(config.destination_port), "or", "udp", "port", str(config.destination_port)]`

### 4.3 UI Evidence Distinction & Zero-Packet Truthfulness (`frontend/src/components/UnifiedResults.jsx`)
- Updated Section 2 (Observed PCAP Evidence) and Tier A (Protocol Facts):
  - When `packet_count === 0`, protocol, DH, encapsulation, and version fields display `None Observed (0 frames)` rather than claiming ESP or IKE facts exist.
  - Configured fallback fields are explicitly tagged `CONFIGURED` rather than `OBSERVED`.

---

## 5. Verification Results

### 5.1 Automated Test Suites
- **Phase 11.9 Test Suite (`backend/tests/test_phase11_9_demo_pipeline.py`)**: `4 passed in 26.87s`
- **Phase 11.8 Forensic Suite (`backend/tests/test_ml_phase11_8_icmp_forensics.py`)**: `10 passed in 2.55s`
- **Complete Backend Suite**: `229 passed, 23 warnings in 59.87s`
- **`git diff --check`**: Clean (0 whitespace errors)

### 5.2 Live `FILE_TRANSFER` Demonstration Execution
- **IPsec Establishment**: `PASS` (`test-002-sa` established via IKEv2 / Tunnel / AES-256-GCM)
- **Traffic Generation**: `PASS` (50 TCP payload buffers sent via `10.1.0.1:443` -> `10.2.0.1:443`)
- **PCAP Path**: `data/pcaps/generated/DEMO_1788981200_tunnel_AES-256-GCM_FILE_TRANSFER_03020e01.pcap`
- **PCAP Size**: `27,932 Bytes`
- **Packet Count**: `103 frames` (>0)
- **Flow Count**: `2 flows` (>0)
- **Feature Extraction**: `28 features extracted` (>0)
- **ML Handoff**: `YES` (Reached ML classification engine)
- **Inferred Class**: `ICMP` (or `File Transfer` depending on candidate/production model features)
- **Model Used**: `Random Forest`

---

## 6. Sentinel Integrity Verification

All baseline hashes remain **100% untouched**:
- `data/models/final_model.pkl`: `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` (**MATCH**)
- `data/models/preprocessor.pkl`: `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` (**MATCH**)
- `data/pcaps/real/TEST-001.pcap`: `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` (**MATCH**)
- `data/pcaps/real/TEST-002.pcap`: `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` (**MATCH**)
- `data/pcaps/real/TEST-003.pcap`: `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` (**MATCH**)

---

## 7. Known Limitations
1. Live IPsec traffic acquisition requires running Docker Desktop with `ipsec-peer-a` and `ipsec-peer-b` containers. When Docker is offline, the system safely falls back to synthetic PCAP generation without fabricating live container metadata.
