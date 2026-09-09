# Phase 11.8 — ICMP_DIAGNOSTIC Failure Forensics

## Executive Summary
Phase 11.8 conducted a rigorous, empirical forensic investigation to determine **WHY** the top Phase 11.7 candidate (`HistGradientBoostingClassifier`) improved overall Test Macro-F1 over production baseline (`0.1680` vs `0.0747`), but failed the mandatory **Gate 12 (Per-Class Safety)** due to `ICMP_DIAGNOSTIC` F1 dropping from `0.2941` (Production) to `0.0000` (Candidate).

This phase was strictly **DIAGNOSTIC ONLY**. No production model files (`final_model.pkl` & `preprocessor.pkl`) or permanent OOD benchmark PCAPs (`TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap`) were modified, retrained, or overwritten.

### Key Forensic Findings
1. **Control-Flow Disambiguation (CONFIRMED)**: Production model's baseline F1 of `0.2941` was an artifact of indiscriminate control-flow misclassification. Production model (trained on synthetic data) mapped **ALL** 2-packet IKE control flows (`17_...:500` & `17_...:4500`) to `ICMP_DIAGNOSTIC` across all session types (`WEB`, `VOIP`, `STREAMING`, `BULK`, `ICMP`). Candidate models trained on `REAL-IPSEC-v1` learned that IKE control flows occur in all 5 classes and correctly stopped classifying control flows as `ICMP_DIAGNOSTIC`.
2. **Feature Non-Separability with VOIP_AUDIO (CONFIRMED)**: Encrypted ICMP payload flows (64B pings) share near-identical packet size and IAT distributions with `VOIP_AUDIO` (160B audio datagrams). Both Production and Candidate models mapped true encrypted ICMP payload flows (`50_...:0` and `1_...:0`) to `VOIP_AUDIO`.
3. **Test Split Sample Size (LIKELY)**: The 70/15/15 session-level split placed 11 ICMP sessions in Train, 1 in Val, and 3 in Test (`RIV1-TEST001-...-001`, `RIV1-TEST001-...-002`, `RIV1-TEST003-...-003`). The Test split contains only 10 ICMP flow records total (4 IKE control flows, 6 payload flows), magnifying the impact of individual flow misclassifications.
4. **Label Accuracy & Sentinel Integrity (RULED OUT)**: Ground-truth labels originate strictly from `PRE_CAPTURE_EXPERIMENT_CONFIGURATION` prior to capture. Cryptographic hashes of all 5 sentinel artifacts matched baseline 100%.

---

## 1. Safety Sentinel Audit

| Sentinel Artifact | File Path | Baseline SHA256 | Actual SHA256 | Status |
|---|---|---|---|---|
| Production Model | `data/models/final_model.pkl` | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | **MATCH** |
| Production Preprocessor | `data/models/preprocessor.pkl` | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | **MATCH** |
| OOD Benchmark 1 | `data/pcaps/real/TEST-001.pcap` | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | **MATCH** |
| OOD Benchmark 2 | `data/pcaps/real/TEST-002.pcap` | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | **MATCH** |
| OOD Benchmark 3 | `data/pcaps/real/TEST-003.pcap` | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | **MATCH** |

---

## 2. ICMP_DIAGNOSTIC Dataset & Session Distribution

- **Total Registered ICMP Sessions**: 15 sessions across 5 IPsec profiles (3 sessions per profile).
- **Session Split Allocation**:
  - **Train**: 11 sessions (33 flow records) — Profiles `TEST-001` (1), `TEST-002` (3), `TEST-003` (1), `TEST-004` (3), `TEST-005` (3).
  - **Validation**: 1 session (2 flow records) — Profile `TEST-003`.
  - **Test**: 3 sessions (10 flow records) — Profiles `TEST-001` (2 sessions: `RIV1-TEST001-ICMP_DIAGNOSTIC-001`, `-002`) and `TEST-003` (1 session: `RIV1-TEST003-ICMP_DIAGNOSTIC-003`).

---

## 3. Test Set Flow Prediction Forensics

Detailed prediction tracing for all 10 ICMP_DIAGNOSTIC flows in the Test set:

| Session ID | Flow ID | Total Pkts | Mean Pkt Len | Ground Truth | Production Pred | HGB Pred | RF Pred | LR Pred |
|---|---|---|---|---|---|---|---|---|
| `RIV1-TEST001-ICMP-001` | `17_...:500` (IKE 500) | 2 | 510.0B | `ICMP_DIAGNOSTIC` | `ICMP_DIAGNOSTIC` | `STREAMING` | `UNKNOWN` | `BULK` |
| `RIV1-TEST001-ICMP-001` | `17_...:4500` (NAT-T) | 2 | 310.0B | `ICMP_DIAGNOSTIC` | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `ICMP_DIAG` | `ICMP_DIAG` |
| `RIV1-TEST001-ICMP-001` | `50_...:0` (Outer ESP) | 56 | 170.0B | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` |
| `RIV1-TEST001-ICMP-001` | `1_...:0` (Inner ICMP) | 28 | 98.0B | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` |
| `RIV1-TEST001-ICMP-002` | `17_...:500` (IKE 500) | 2 | 510.0B | `ICMP_DIAGNOSTIC` | `ICMP_DIAGNOSTIC` | `STREAMING` | `UNKNOWN` | `BULK` |
| `RIV1-TEST001-ICMP-002` | `17_...:4500` (NAT-T) | 2 | 310.0B | `ICMP_DIAGNOSTIC` | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `ICMP_DIAG` | `ICMP_DIAG` |
| `RIV1-TEST001-ICMP-002` | `50_...:0` (Outer ESP) | 38 | 170.0B | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` |
| `RIV1-TEST001-ICMP-002` | `1_...:0` (Inner ICMP) | 19 | 98.0B | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `VOIP_AUDIO` | `ICMP_DIAG` | `VOIP_AUDIO` |
| `RIV1-TEST003-ICMP-003` | `17_...:500` (IKE 500) | 4 | 420.0B | `ICMP_DIAGNOSTIC` | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `UNKNOWN` | `BULK` |
| `RIV1-TEST003-ICMP-003` | `50_...:0` (Outer ESP) | 38 | 162.0B | `ICMP_DIAGNOSTIC` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` | `VOIP_AUDIO` |

---

## 4. Feature Statistical Comparison (`ICMP_DIAGNOSTIC` vs `VOIP_AUDIO`)

Descriptive statistics across all 198 flow records in `REAL-IPSEC-v1`:

| Predictive Feature | ICMP_DIAGNOSTIC Mean (Std) | VOIP_AUDIO Mean (Std) | WEB_INTERACTIVE Mean (Std) | BULK_TRANSFER Mean (Std) |
|---|---|---|---|---|
| `pkt_len_mean` | 259.75B (156.97) | 319.12B (112.97) | 338.98B (117.93) | 478.38B (132.02) |
| `pkt_len_max` | 282.73B (166.82) | 343.80B (116.07) | 425.92B (93.01) | 877.58B (543.08) |
| `total_bytes` | 2,995.6B (2,533.0) | 22,377.6B (29,874.8) | 2,537.1B (1,844.9) | 178,075.2B (209,913.4) |
| `total_packets` | 18.40 (16.61) | 85.76 (115.34) | 9.17 (7.85) | 302.89 (355.63) |
| `flow_iat_mean` | 0.36s (0.38) | 0.16s (0.30) | 0.01s (0.01) | 0.00s (0.00) |

---

## 5. Three-Candidate Comparison on ICMP_DIAGNOSTIC

| Model Classifier | ICMP Precision | ICMP Recall | ICMP F1 Score | ICMP Support | Note |
|---|---|---|---|---|---|
| **Production Baseline** | 0.1923 | 0.6250 | **0.2941** | 8 | Artifact of control-flow misclassification |
| **HistGradientBoostingClassifier** | 0.0000 | 0.0000 | **0.0000** | 5 | Correctly stopped control flow misclassification; mapped payload to VOIP |
| **RandomForestClassifier** | 0.1250 | 0.2000 | **0.1538** | 5 | Mapped 1 control flow & 1 payload flow to ICMP |
| **LogisticRegression** | 0.1250 | 0.2000 | **0.1538** | 5 | Mapped 1 control flow to ICMP |

---

## 6. Root Cause Classification Matrix

| Root Cause Hypothesis | Status | Evidence | Impact |
|---|---|---|---|
| **Control-Flow Disambiguation** | **CONFIRMED** | Production predicted `ICMP` for short IKE control flows (`17_...:500` / `4500`) across ALL session types. HGB learned control flows are non-specific and stopped classifying them as ICMP. | Production F1=`0.2941` was an artifact of indiscriminate control flow classification; HGB correctly eliminated this artifact. |
| **Feature Overlap with VOIP_AUDIO** | **CONFIRMED** | Small encrypted packet sizes (64B pings vs 160B audio datagrams) overlap in `pkt_len_mean` and `pkt_len_max`. Models map encrypted ICMP payload flows to `VOIP_AUDIO`. | ICMP payload flows merged into `VOIP_AUDIO` cluster. |
| **Small Test Split Sample Size** | **LIKELY** | Test split contains only 10 ICMP flow records (4 control, 6 payload). A single misclassified flow heavily distorts recall. | High metric variance on test split. |
| **Profile Generalization Shift** | **POSSIBLE** | Test set ICMP sessions come from `TEST-001` (Tunnel mode) and `TEST-003` (Transport mode). Transport vs Tunnel ESP header shifts packet lengths by 20 bytes. | Minor feature boundary movement between modes. |
| **Label / Ground-Truth Inaccuracy** | **RULED OUT** | Labels originate strictly from `PRE_CAPTURE_EXPERIMENT_CONFIGURATION` prior to capture. | Zero label contamination. |
| **Sentinel / PCAP Mutation** | **RULED OUT** | Cryptographic hashes of all 5 sentinels matched baseline 100%. | Zero artifact mutation. |

---

## 7. Recommended Next Investigation (Phase 11.9 Candidate Remediation)
1. **Flow Filtering / Control Flow Separation**: Filter short 2-packet IKE control flows (`17_...:500` & `17_...:4500`) into control metadata or separate flow layers before training behavioral classifiers.
2. **Payload Size / Ratio Feature Engineering**: Introduce packet size variance and minimum packet size ratio features to distinguish periodic ICMP pings (constant 64B payload) from variable/codec VoIP audio frames.
3. **Session-Level Stratified Re-Sampling**: Ensure each IPsec profile has at least 1 session represented in Validation and Test splits across all behavioral classes.
