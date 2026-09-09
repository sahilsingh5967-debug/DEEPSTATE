# Phase 11.2 — DEEPSTATE ML Target & Ground-Truth Specification

---

## 1. Executive Summary
This document establishes the authoritative machine learning target schema, label semantics, dataset provenance, feature leakage analysis, and ground-truth specification for the **DEEPSTATE IPsec VPN Security Intelligence Platform** prior to any model retraining or pipeline modification in Phase 11.3.

> [!IMPORTANT]
> **Phase 11.2 Specification Boundary**:
> No production code, trained models, preprocessors, API contracts, analytical logic, or frontend files were modified during Phase 11.2. This specification establishes the formal foundation for Phase 11.3 data collection and retraining.

---

## 2. Dataset Provenance Audit

### Sourcing & Provenance Analysis
- **Registered Name**: UNB ISCX-VPN2016 (VPN-nonVPN) Dataset (`dataset_registry.json`).
- **Dataset Owner/Author**: **NOT ESTABLISHED FROM REPOSITORY EVIDENCE** (The repository references Draper-Gil et al., 2016 for the academic benchmark concept, but the actual PCAP files stored on disk were programmatically generated locally).
- **Original Benchmark Name**: UNB ISCX-VPN2016.
- **Actual Local Data Origin**: `data/datasets/public/iscx_vpn2016/` (80 PCAP session capture files totaling 1,639.66 MB).
- **Acquisition Method**: Programmatically generated locally via `scripts/ml/download_dataset.py`.
- **Synthetic Generation Involved**: **YES**.
- **Evidence**:
  - `scripts/ml/download_dataset.py` lines 49–142 contain `generate_expanded_pcap_fast()`, which packs binary IP/TCP/UDP/ICMP headers and writes `os.urandom()` byte payloads to disk.
  - `data/datasets/public/iscx_vpn2016/acquisition_manifest.json` lists 80 files generated at `2026-09-08T18:05:57`.

```
PROVENANCE SUMMARY:
  Dataset Provenance: Locally generated synthetic PCAP dataset
  Author/Proprietor: NOT ESTABLISHED FROM REPOSITORY EVIDENCE
  Generation Method: struct.pack binary simulation (download_dataset.py)
  Synthetic Generation: YES (100% of files in data/datasets/public/iscx_vpn2016/)
```

---

## 3. Current Label Inventory

The table below lists all labels currently defined across repository sources:

| Source | Label | Flow Count / Frequency | Meaning | Evidence File & Line |
|---|---|---|---|---|
| PCAP Filename | `icmp` | 10 files (20 PCAPs total) | ICMP Echo request/reply session | `download_dataset.py:207` |
| PCAP Filename | `web_browsing` | 10 files (20 PCAPs total) | Web browsing HTTP/S session | `download_dataset.py:209` |
| PCAP Filename | `email` | 10 files (20 PCAPs total) | SMTP/IMAP email session | `download_dataset.py:211` |
| PCAP Filename | `chat` | 10 files (20 PCAPs total) | XMPP/IRC chat session | `download_dataset.py:213` |
| PCAP Filename | `streaming` | 10 files (20 PCAPs total) | Video streaming session | `download_dataset.py:215` |
| PCAP Filename | `file_transfer` | 10 files (20 PCAPs total) | FTP/SCP file transfer session | `download_dataset.py:217` |
| PCAP Filename | `voip` | 10 files (20 PCAPs total) | VoIP audio call session | `download_dataset.py:219` |
| PCAP Filename | `p2p` | 10 files (20 PCAPs total) | Peer-to-peer torrent session | `download_dataset.py:221` |
| Feature CSV | `ICMP` | 998 flows (9.76%) | Synthetic ICMP Ping flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `Web Browsing` | 1,017 flows (9.95%) | Synthetic Web flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `Email` | 1,036 flows (10.14%) | Synthetic Email flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `Chat` | 975 flows (9.54%) | Synthetic Chat flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `Streaming` | 2,178 flows (21.31%) | Synthetic Streaming flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `File Transfer` | 1,048 flows (10.25%) | Synthetic File Transfer flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `VoIP` | 2,042 flows (19.98%) | Synthetic VoIP flow | `iscx_vpn2016_features.csv` |
| Feature CSV | `P2P` | 926 flows (9.06%) | Synthetic P2P flow | `iscx_vpn2016_features.csv` |
| Model Metadata | 8 Target Classes | Array of 8 strings | Output categories for Random Forest | `model_metadata.json:39` |
| Training Code | `TARGET_CLASSES` | Array of 8 strings | Master target class array | `evaluator.py:19` |
| Demo Lab | `ICMP` | Scenario ID | Ping burst execution | `profile_registry.py:71` |
| Demo Lab | `UDP` | Scenario ID | Custom UDP datagram flow | `profile_registry.py:80` |
| Demo Lab | `TCP` | Scenario ID | Custom TCP stream flow | `profile_registry.py:89` |
| Demo Lab | `WEB` / `WEB-LIKE` | Scenario ID | TCP ASCII `'W'` payload flow to port 443 | `traffic_generator.py:51` |
| Demo Lab | `DNS-LIKE` | Scenario ID | UDP datagram flow to port 53 | `traffic_generator.py:36` |
| Demo Lab | `VOIP-LIKE` | Scenario ID | UDP datagram flow to port 5060 | `traffic_generator.py:36` |
| Demo Lab | `FILE-TRANSFER-LIKE` | Scenario ID | TCP ASCII `'W'` payload flow to port 443 | `traffic_generator.py:51` |

---

## 4. Real IPsec Ground Truth Specification

The project contains 3 real strongSwan IPsec captures (`data/pcaps/real/`). The table below specifies their ground-truth parameters based on protocol extractions and testbed profile configurations (`profile_registry.py`):

| PCAP Artifact | Observed Protocol Facts (Phase 3) | Known Testbed Configuration (`profile_registry.py`) | Application Ground Truth | Confidence |
|---|---|---|---|---|
| **`TEST-001.pcap`** | - IP Header: `192.168.100.2 → 192.168.100.3`<br>- UDP 500 (IKE_SA_INIT)<br>- UDP 4500 (IKE_AUTH)<br>- IP Proto 50 (ESP, SPI `0xc40d8eaf`) | Profile `TEST-001`:<br>- IKEv2 Tunnel Mode<br>- AES-128-CBC / SHA256<br>- DH Group 14 (MODP2048)<br>- Source: `10.1.0.1`, Dst: `10.2.0.1` | **ICMP Echo Ping over IPsec ESP** | **100% (High)** |
| **`TEST-002.pcap`** | - IP Header: `192.168.100.2 → 192.168.100.3`<br>- UDP 500 (IKE_SA_INIT)<br>- UDP 4500 (IKE_AUTH & ESP Encapsulation)<br>- ESP Packets: 1420-byte payload | Profile `TEST-002`:<br>- IKEv2 Tunnel Mode<br>- AES-256-GCM / ECP256 (Group 19)<br>- NAT-Traversal enabled (UDP 4500) | **Bulk File Transfer / Data Stream over ESP NAT-T** | **100% (High)** |
| **`TEST-003.pcap`** | - IP Header: `192.168.100.2 → 192.168.100.3`<br>- UDP 500 (IKE_SA_INIT)<br>- IP Proto 50 (ESP NULL Encryption / Auth Only)<br>- TCP HTTP GET request unencrypted payload | Profile `TEST-003`:<br>- IKEv2 Transport Mode<br>- AES-128-CBC / SHA256<br>- Host-to-Host encapsulation | **Web Browsing / HTTP GET over IPsec Transport Mode** | **100% (High)** |

---

## 5. Label Compatibility Analysis

The table below maps the existing 8 model classes against Demonstration Lab scenarios and real captures:

| Model Class | Demonstration Lab Scenario | Real PCAP Ground Truth | Compatibility | Reason / Technical Gap |
|---|---|---|---|---|
| `ICMP` | `ICMP` | `TEST-001.pcap` | **DIRECT** | Matches ICMP ping traffic profile. |
| `Web Browsing` | `WEB` / `WEB-LIKE` | `TEST-003.pcap` | **APPROXIMATE** | Lab sends TCP `'W'` bytes without HTTP/TLS headers. |
| `File Transfer` | `FILE-TRANSFER-LIKE` | `TEST-002.pcap` | **APPROXIMATE** | Lab sends TCP `'W'` bytes; lacks FTP/SCP protocol dynamics. |
| `VoIP` | `VOIP-LIKE` | *None* | **APPROXIMATE** | Lab sends 512B UDP; real VoIP uses ~160–240B RTP audio frames. |
| `Streaming` | *None* | *None* | **UNSUPPORTED IN LAB** | No Demonstration Lab generator exists for video streaming. |
| `Chat` | *None* | *None* | **UNSUPPORTED IN LAB** | No Demonstration Lab generator exists for chat. |
| `Email` | *None* | *None* | **UNSUPPORTED IN LAB** | No Demonstration Lab generator exists for email. |
| `P2P` | *None* | *None* | **UNSUPPORTED IN LAB** | No Demonstration Lab generator exists for P2P. |
| *Missing* | `DNS-LIKE` | *None* | **MISSING** | `DNS` class is missing from the 8 model classes. |
| *Missing* | `UDP` | *None* | **MISSING** | `Generic UDP` class is missing from model classes. |
| *Missing* | `TCP` | *None* | **MISSING** | `Generic TCP` class is missing from model classes. |

---

## 6. ML Task Definition

### Current Claim vs. Empirical Reality
- **Current Claim**: "Encrypted Application Traffic Classification" (inferring 8 fine-grained application types from encrypted payloads).
- **Empirical Reality**: Fine-grained application labels (`Web Browsing`, `Chat`, `Email`) cannot be discriminated when payloads are encrypted inside IPsec ESP tunnels unless realistic flow timing, TLS Server Name Indication (SNI) surrogates, or application burst dynamics are present.

### Supported ML Task for DEEPSTATE Phase 11
Based on repository evidence and IPsec encapsulation dynamics, the supported task is:

> **IPsec Encapsulated Traffic Behavior Classification**
> Classifying IPsec ESP packet streams into distinct behavioral traffic profiles (**Diagnostic/ICMP**, **Web/Interactive**, **Bulk/File Transfer**, **Audio/VoIP Stream**, **Video/Streaming**) based on flow volume, inter-arrival cadence, and packet size distributions adjusted for ESP header overhead.

---

## 7. Feature / Label Leakage Review

Audit of the 28 features in `backend/app/ml/features.py` against the synthetic generator (`scripts/ml/download_dataset.py`):

| Feature Group | Features Included | Synthetic Generation Risk | Status | Findings / Evidence |
|---|---|---|---|---|
| **Length Statistics** | `pkt_len_mean`, `pkt_len_std`, `pkt_len_min`, `pkt_len_max`, `pkt_len_skewness`, `fwd_pkt_len_mean`, `bwd_pkt_len_mean` | **LEAKAGE-RISK** | **CRITICAL** | `download_dataset.py` hardcoded discrete `min_len` and `max_len` bounds per class (`ICMP`: 64–128, `VoIP`: 120–260, `Streaming/File`: 600–1440, `P2P`: 300–1300, `Web/Email/Chat`: 150–1100). The model learned synthetic boundary cutoffs rather than true protocol distributions. |
| **Volumetric Features** | `flow_duration_seconds`, `total_fwd_packets`, `total_bwd_packets`, `total_packets`, `total_fwd_bytes`, `total_bwd_bytes`, `total_bytes`, `packets_per_second`, `bytes_per_second` | **LEAKAGE-RISK** | **HIGH** | `download_dataset.py` hardcoded packet counts per class (`pkts_count = random.randint(300, 500)` for Streaming/File vs `150-300` for Web/Email/Chat), introducing artificial volumetric separation. |
| **Temporal IATs** | `flow_iat_mean`, `flow_iat_std`, `flow_iat_min`, `flow_iat_max`, `fwd_iat_mean`, `bwd_iat_mean` | **QUESTIONABLE** | **MEDIUM** | Inter-arrival times were generated uniformly (`random.uniform(0.001, 0.08)`), missing real-world application pause cadences. |
| **Directional Ratios** | `fwd_bwd_packet_ratio`, `fwd_bwd_byte_ratio` | **SAFE** | **SAFE** | Computed strictly from packet flow counts. |
| **IPsec Context** | `esp_packet_count`, `has_ike`, `has_esp`, `has_udp_4500` | **SAFE / CONTEXT** | **SAFE** | Derived from Scapy protocol headers. |

---

## 8. Dataset Split Validity Findings

- **Existing Mechanism**: `split_records_flow_level` in `backend/app/ml/splitting.py` splits records based on 5-tuple `flow_id` (`proto_srcIP:srcPort<->dstIP:dstPort`).
- **Session Leakage Finding**:
  In `scripts/ml/download_dataset.py`, each session PCAP file (e.g. `vpn_web_browsing_session_1.pcap`) contains 80–120 distinct flows. Because splitting occurred at the 5-tuple `flow_id` level rather than the **Session / Capture File level**, flows originating from the **exact same PCAP session** were distributed across Train (70%), Validation (15%), and Test (15%) splits.
- **Impact**: Test set performance (85.35% accuracy) is artificially inflated due to session-level feature leakage across splits.

---

## 9. Recommended Target Schema for Phase 11.3

Based on the audit findings, the following target schema is specified for Phase 11.3 dataset collection and model training:

### PRIMARY TARGET: Behavioral Encrypted Traffic Category (`traffic_category`)
1. `ICMP_DIAGNOSTIC` (Control, Ping, Diagnostic Echo)
2. `WEB_INTERACTIVE` (HTTP/HTTPS Web Browsing, API requests)
3. `BULK_TRANSFER` (FTP, SCP, Large File Transfer, Data Backup)
4. `STREAMING_MEDIA` (Video/Audio Streaming, HLS, DASH)
5. `VOIP_AUDIO` (Real-time Audio Stream, RTP/SIP calls)

### OPTIONAL SECONDARY TARGET: Encapsulation Mode (`encapsulation_type`)
1. `NATIVE_IPSEC_ESP` (IP Proto 50 Tunnel/Transport Mode)
2. `IPSEC_NATT_UDP4500` (ESP in UDP Port 4500)
3. `NON_VPN` (Unencapsulated / Plain TLS)

### UNKNOWN / OTHER POLICY
- Any inference where `max(predict_proba) < 0.50` OR flow packet count `< 3` MUST be designated `UNKNOWN / UNCLASSIFIED`.

### UNSUPPORTED SCENARIOS
- `DNS-LIKE`, `Generic UDP`, and `Generic TCP` scenarios MUST NOT be forced into application classes; they will map to `UNKNOWN` or generic transport categories.

---

## 10. Known Limitations & Phase 11.3 Requirements

### Known Limitations
1. **ESP Length Padding Overhead**: Native IPsec ESP adds +50–70 bytes of header, IV, padding, and ICV overhead. Feature extraction pipelines must perform length normalization when `has_esp == True`.
2. **Synthetic Dataset Exclusion**: All synthetic PCAP files in `data/datasets/public/iscx_vpn2016/` MUST be excluded from Phase 11.3 training.

### Phase 11.3 Requirements
1. **Acquire Authentic Benchmark Datasets**: Download authentic, un-manipulated ISCX-VPN2016 or CIC-Darknet2020 PCAP archives.
2. **Session-Level Dataset Splitting**: Implement session-level / file-level splitting in `splitting.py` (`split_records_session_level`).
3. **Realistic Demonstration Lab Generators**: Update `scripts/testbed/traffic_generator.py` to produce realistic HTTP GET/POST and variable-length payload patterns.
