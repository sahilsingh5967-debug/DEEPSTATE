# Phase 11.6 — DEEPSTATE Real-IPsec Testbed Activation, Acquisition & Conditional Retraining Report

---

## 1. Executive Summary

Phase 11.6 evaluates the activation of the StrongSwan Docker testbed, preflight environment readiness, acquisition of `REAL-IPSEC-v1` traffic, evaluation of the Dataset Readiness Gate, and conditional candidate model retraining.

> [!IMPORTANT]
> **Production Model & OOD Safety Boundary**:
> 1. Production model artifacts (`data/models/final_model.pkl` and `data/models/preprocessor.pkl`) are **100% UNTOUCHED and UNMODIFIED**. SHA256 checksums match exact baseline values (`e67d90ad...` and `f66f06e2...`).
> 2. Real IPsec testbed benchmark captures (`TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap`) remain **100% UNTOUCHED** and permanently excluded from training/validation/test splits.
> 3. Strict Fail-Closed Execution: Docker Desktop daemon is not running on the macOS host (`ACQUISITION_UNAVAILABLE`). Fail-closed safety rules prevented synthetic fabrication or false labeling of PCAPs.
> 4. Retraining Verdict: **DO NOT PROMOTE** (Candidate retraining blocked due to `DATASET_INSUFFICIENT`).

---

## 2. Testbed Preflight & Environmental Evaluation

| Preflight Check Item | Environment Result | Fail-Closed Status |
| :--- | :--- | :--- |
| Docker CLI Context | Desktop Linux (`v29.7.2`) | Detected |
| Docker Daemon Connection | `Cannot connect to Docker daemon` | **OFFLINE** |
| StrongSwan Peer A (`ipsec-peer-a`) | Container Not Running | **OFFLINE** |
| StrongSwan Peer B (`ipsec-peer-b`) | Container Not Running | **OFFLINE** |
| Testbed Acquisition Readiness | Unfulfilled | `ACQUISITION_UNAVAILABLE` |

---

## 3. Ground-Truth Data Acquisition Audit

- **Registered Real IPsec Sessions**: `0`
- **Acquisition Engine Status**: `ACQUISITION_UNAVAILABLE`
- **Synthetic Fabrication Check**: **0 synthetic PCAPs created** (100% Fail-Closed Compliance)
- **Pre-Capture Ground Truth Contract**: Preserved (No model predictions used for labeling)

---

## 4. Dataset Readiness Gate Evaluation

The Dataset Readiness Gate assesses whether `REAL-IPSEC-v1` satisfies all criteria required before candidate model retraining:

| Criterion | Required Threshold | Current State | Gate Result |
| :--- | :--- | :--- | :--- |
| **Minimum Session Volume** | $\ge 50$ sessions | 0 sessions | ❌ FAILED |
| **Class Balance** | All 5 behavioral classes represented | Insufficient | ❌ FAILED |
| **Profile Diversity** | Profiles TEST-001 through TEST-005 represented | Insufficient | ❌ FAILED |
| **Integrity Audit** | 0 missing PCAPs/metadata, 0 duplicates | Clean (0 sessions) | 🟢 PASSED |
| **Session Leakage** | 0 session overlap across splits | Clean (0 sessions) | 🟢 PASSED |
| **Forbidden Identifiers** | Excluded from feature matrix $X$ | 100% Excluded | 🟢 PASSED |

**Dataset Readiness Verdict**: `DATASET_INSUFFICIENT`

---

## 5. Candidate Model Retraining & Promotion Audit

Because the Dataset Readiness Gate returned `DATASET_INSUFFICIENT`, candidate model retraining was strictly **blocked**.

### 14-Step Promotion Gate Audit

| Gate # | Promotion Safety Gate Check | Requirement | Gate Status |
| :---: | :--- | :--- | :---: |
| 1 | Session-level splitting enforced | Grouped by `session_id` / `capture_id` | 🟢 PASSED |
| 2 | Zero session overlap | Train $\cap$ Val $\cap$ Test = $\emptyset$ | 🟢 PASSED |
| 3 | Zero forbidden identifiers in $X$ | IPs, ports, IDs stripped | 🟢 PASSED |
| 4 | OOD TEST-001 evaluated | Benchmark score recorded | ❌ SKIPPED |
| 5 | OOD TEST-002 evaluated | Benchmark score recorded | ❌ SKIPPED |
| 6 | OOD TEST-003 evaluated | Benchmark score recorded | ❌ SKIPPED |
| 7 | Validation Macro-F1 threshold | $> 0.85$ on real IPsec validation set | ❌ UNFULFILLED |
| 8 | Per-class F1 threshold | $> 0.70$ on all 5 behavioral target classes | ❌ UNFULFILLED |
| 9 | Real IPsec Dataset Readiness | Real IPsec dataset ready ($\ge 50$ sessions) | ❌ **FAILED** |
| 10 | Provenance complete | Pre-capture ground truth metadata present | 🟢 PASSED |
| 11 | No ESP byte subtraction | Raw packet lengths preserved | 🟢 PASSED |
| 12 | Anti-fabrication audit | 0 synthetic PCAPs mislabeled as real | 🟢 PASSED |
| 13 | Candidate model isolated | Saved in `data/models/candidates/` | 🟢 PASSED |
| 14 | Production artifacts unmodified | `final_model.pkl` SHA256 untouched | 🟢 **PASSED** |

---

## 6. Baseline Cryptographic SHA256 Verification

| File Artifact | Target Role | Baseline SHA256 Checksum | Verification Status |
| :--- | :--- | :--- | :---: |
| `data/models/final_model.pkl` | Production ML Model | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | 🟢 **UNTOUCHED** |
| `data/models/preprocessor.pkl` | Production Preprocessor | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | 🟢 **UNTOUCHED** |
| `data/pcaps/real/TEST-001.pcap` | OOD Benchmark #1 | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | 🟢 **UNTOUCHED** |
| `data/pcaps/real/TEST-002.pcap` | OOD Benchmark #2 | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | 🟢 **UNTOUCHED** |
| `data/pcaps/real/TEST-003.pcap` | OOD Benchmark #3 | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | 🟢 **UNTOUCHED** |

---

## 7. Final Model Verdict

**FINAL VERDICT**: **`DO NOT PROMOTE`**

**Reasoning**: Live strongSwan Docker testbed containers were offline during acquisition execution (`ACQUISITION_UNAVAILABLE`). The fail-closed acquisition engine strictly prevented data fabrication. Consequently, `REAL-IPSEC-v1` contains 0 sessions (`DATASET_INSUFFICIENT`), blocking candidate model retraining. Existing production ML model artifacts remain active and 100% untouched.
