# Phase 11.5 — DEEPSTATE Real-IPsec Data Acquisition & Ground-Truth Pipeline Specification

---

## 1. Executive Summary

Phase 11.5 establishes the dataset engineering, acquisition engine, master ground-truth registry, quality audit infrastructure, and session-level split manifest for the **DEEPSTATE Real-IPsec Ground-Truth Dataset** (`REAL-IPSEC-v1`).

> [!IMPORTANT]
> **Production Model & OOD Safety Boundary**:
> 1. Production model artifacts (`data/models/final_model.pkl` and `data/models/preprocessor.pkl`) are **100% untouched and un-retrained**. SHA256 checksums and modification timestamps are verified identical before and after all Phase 11.5 operations.
> 2. Testbed captures `TEST-001.pcap`, `TEST-002.pcap`, and `TEST-003.pcap` remain strictly reserved as permanent Out-of-Distribution (OOD) benchmark captures and are **permanently excluded** from training, validation, and test split partitions.
> 3. Synthetic PCAP data (`SYNTHETIC_DEVELOPMENT`) is explicitly disclosed and **never mislabeled** as real IPsec traffic.
> 4. Ground-truth labels are assigned **independently before capture** based on experiment generator scenarios and are **never derived** from ML model predictions.

---

## 2. Dataset Architecture (`REAL-IPSEC-v1`)

The dataset is organized under `data/datasets/real_ipsec/`:

```
data/datasets/real_ipsec/
├── captures/               # Raw PCAP capture files (e.g. RIPSEC_TEST-001_ICMP_DIAGNOSTIC_A1B2C3.pcap)
├── metadata/               # Per-session JSON metadata records
├── manifests/              # Partition and audit manifests
├── real_ipsec_registry.json# Master ground-truth session registry
├── real_ipsec_features.csv# Extracted 28 predictive features matrix
├── split_manifest.json     # Leakage-safe 70/15/15 session-level split manifest (seed=42)
└── dataset_manifest.json   # REAL-IPSEC-v1 versioning and provenance manifest
```

---

## 3. Provenance & Ground-Truth Methodology

### 3.1 Pre-Capture Ground-Truth Assignment
Ground-truth labels are established from the pre-capture experiment configuration:

$$\text{Generator Scenario Configuration} \longrightarrow \text{Assigned Behavioral Label} \longrightarrow \text{Live Packet Capture} \longrightarrow \text{Registry Record}$$

- **Ground Truth Method**: `PRE_CAPTURE_EXPERIMENT_CONFIGURATION`
- **Boolean Flag**: `ground_truth_established_before_capture = true`
- **Rule**: ML model inference outputs are strictly forbidden from setting or modifying ground-truth labels.

### 3.2 Dataset Source Tagging
- Real IPsec captures acquired from the testbed are assigned `dataset_source = "REAL_IPSEC_GROUND_TRUTH"`.
- Synthetic development features (`iscx_vpn2016_features.csv`) remain tagged as `dataset_source = "SYNTHETIC_DEVELOPMENT"`.

---

## 4. Parameterized Behavioral Traffic Generators

The traffic generator module (`scripts/testbed/traffic_generator.py`) defines 5 specialized behavioral functions:

1. `generate_icmp_diagnostic()`: Controlled ping bursts with configurable payload size, interval, and burst count.
2. `generate_web_interactive()`: HTTP request/response exchanges with variable payload sizes and inter-request idle delays.
3. `generate_bulk_transfer()`: Sustained high-volume streams with configurable duration and chunk sizes.
4. `generate_streaming_media()`: Variable-rate traffic streams with burst/idle timing characteristics.
5. `generate_voip_audio()`: Periodic small payload frame datagrams at 20ms packetization intervals.

*Note: These functions represent controlled laboratory traffic approximations for dataset engineering and do not claim to mirror unconstrained public internet applications.*

---

## 5. Expanded IPsec Profile Matrix

To decouple traffic behavior from cryptographic/encapsulation shortcuts, the IPsec profile registry (`scripts/testbed/profile_registry.py`) defines a matrix across IKE versions, cipher modes, and encapsulation types:

| Profile ID | Display Name | IKE Version | Encryption Cipher | Integrity | DH Group | Encapsulation Mode | NAT Traversal |
|---|---|---|---|---|---|---|---|
| `TEST-001` | Legacy Enterprise Tunnel | IKEv2 | AES-128-CBC | SHA256 | MODP2048 | Tunnel Mode | Disabled (Native ESP) |
| `TEST-002` | Modern High-Security Tunnel | IKEv2 | AES-256-GCM | GCM-Implicit | ECP256 | Tunnel Mode | Enabled (UDP 4500) |
| `TEST-003` | Host-to-Host Transport Mode | IKEv2 | AES-128-CBC | SHA256 | MODP2048 | Transport Mode | Disabled (Native ESP) |
| `TEST-004` | Transport Mode AEAD | IKEv2 | AES-256-GCM | GCM-Implicit | ECP256 | Transport Mode | Disabled (Native ESP) |
| `TEST-005` | NAT-Traversal ESP Tunnel | IKEv2 | AES-128-CBC | SHA256 | MODP2048 | Tunnel Mode | Enabled (UDP 4500) |

---

## 6. Real-IPsec Acquisition Engine & Fail-Closed Safety Behavior

The acquisition engine (`scripts/testbed/generate_real_ipsec_dataset.py`) orchestrates live StrongSwan Docker captures:

### Fail-Closed Operational Rule
If host system Docker containers (`ipsec-peer-a`, `ipsec-peer-b`) or StrongSwan services are offline:
- The acquisition engine **fails closed** and returns `status: ACQUISITION_UNAVAILABLE`.
- It **never** creates synthetic fake PCAP files.
- It **never** mislabels synthetic traffic as `REAL_IPSEC_GROUND_TRUTH`.

---

## 7. Feature Schema & Metadata Separation

The feature extraction matrix (`data/datasets/real_ipsec/real_ipsec_features.csv`) maintains strict separation between predictive features and metadata:

- **28 Predictive Feature Vector ($X$)**:
  - Volumetric: `flow_duration_seconds`, `total_fwd_packets`, `total_bwd_packets`, `total_packets`, `total_fwd_bytes`, `total_bwd_bytes`, `total_bytes`, `packets_per_second`, `bytes_per_second`.
  - Length Statistics: `pkt_len_mean`, `pkt_len_std`, `pkt_len_min`, `pkt_len_max`, `pkt_len_skewness`, `fwd_pkt_len_mean`, `bwd_pkt_len_mean`.
  - IAT Statistics: `flow_iat_mean`, `flow_iat_std`, `flow_iat_min`, `flow_iat_max`, `fwd_iat_mean`, `bwd_iat_mean`.
  - Directional Ratios: `fwd_bwd_packet_ratio`, `fwd_bwd_byte_ratio`.
  - IPsec Context Flags: `esp_packet_count`, `has_ike`, `has_esp`, `has_udp_4500`.

- **Forbidden Predictive Identifiers (Purged from $X$)**:
  `src_ip`, `dst_ip`, `src_port`, `dst_port`, `flow_id`, `capture_id`, `session_id`, `traffic_class`, `behavioral_class`.

---

## 8. Session-Level Leakage-Safe Partitioning & Permanent OOD Exclusion

Session splitting (`data/datasets/real_ipsec/split_manifest.json`) is executed at the capture/session level (`random_seed=42`):
- **70% Train / 15% Validation / 15% Test**.
- Zero session ID overlap across splits ($\text{Train} \cap \text{Val} = \emptyset$, $\text{Train} \cap \text{Test} = \emptyset$, $\text{Val} \cap \text{Test} = \emptyset$).
- **Permanent OOD Exclusion**: `TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap` are permanently excluded from all three training/validation/test partitions and reserved exclusively under `dataset_role = "OOD"`.

---

## 9. Dataset Quality Audit & Shortcut Correlation Risk Analysis

The audit tool (`scripts/ml/audit_real_ipsec_dataset.py`) verifies:
1. Integrity Checks: Missing metadata/PCAP files, invalid labels, duplicate session IDs, duplicate PCAP SHA256 hashes.
2. Leakage Checks: Session overlap across partitions, OOD contamination.
3. Shortcut-Risk Analysis: Contingency matrix auditing correlations between `behavioral_class` and `encryption` / `nat_traversal` / `mode` / `encapsulation_type` to flag dataset design shortcuts before model training.

---

## 10. ESP Observability Policy

Outer ESP packet lengths are observed legitimately from raw captures. Inner packet payloads are encrypted using AES-CBC or AES-GCM and are **not observable** without active SA decryption keys. No artificial bytes (e.g. "-50B" or "-70B") are subtracted.

---

## 11. Production Model Safety Verification

- `data/models/final_model.pkl`: `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` (Verified Unchanged)
- `data/models/preprocessor.pkl`: `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` (Verified Unchanged)
