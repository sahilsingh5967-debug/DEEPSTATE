# Phase 11.6B — Real-IPsec Testbed Recovery, Live Acquisition & Candidate Model Retraining Report

## Executive Summary
Phase 11.6B successfully operationalized the StrongSwan IPsec Docker testbed (`ipsec-peer-a` and `ipsec-peer-b`), established verified IKEv2 CHILD_SAs across all 5 target research profiles (`TEST-001` through `TEST-005`), executed controlled behavioral traffic generation for all 5 target classes (`ICMP_DIAGNOSTIC`, `WEB_INTERACTIVE`, `BULK_TRANSFER`, `STREAMING_MEDIA`, `VOIP_AUDIO`), acquired **75 live real-IPsec sessions** (3 sessions per cell in a $5 \times 5$ matrix), extracted 28 predictive features (198 flow records), generated session-level split manifests (70/15/15 ratio with zero overlap), evaluated the **Dataset Readiness Gate** (`DATASET_READY`), and conducted isolated candidate model retraining into `data/models/candidates/`.

All production sentinel artifacts (`final_model.pkl` and `preprocessor.pkl`) and permanent OOD benchmark PCAPs (`TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap`) remained 100% untouched and cryptographically verified against baseline SHA256 checksums.

---

## 1. Testbed Topology & IPsec Security Associations
The testbed environment runs on Docker Desktop with Debian Linux containers:
- **Peer A (`ipsec-peer-a`)**: Virtual subnet `10.1.0.0/24`, Virtual IP `10.1.0.1`
- **Peer B (`ipsec-peer-b`)**: Virtual subnet `10.2.0.0/24`, Virtual IP `10.2.0.1`

### Negotiated IPsec Research Profiles ($5 \times 5$ Matrix)
| Profile ID | IKE Proposal | ESP Proposal | Mode | Encapsulation | NAT-T |
|---|---|---|---|---|---|
| `TEST-001` | `aes128-sha256-modp2048` | `aes128-sha256` | Tunnel | Native ESP (Proto 50) | False |
| `TEST-002` | `aes256gcm16-prfsha384-modp3072` | `aes256gcm16` | Tunnel | Native ESP (Proto 50) | False |
| `TEST-003` | `aes128-sha384-modp2048` | `aes128-sha256` | Transport | Native ESP (Proto 50) | False |
| `TEST-004` | `aes256gcm16-prfsha384-ecp384` | `aes256gcm16` | Transport | UDP/4500 Encapsulated | True |
| `TEST-005` | `aes128-sha256-modp3072` | `aes128-sha256` | Tunnel | UDP/4500 Encapsulated | True |

---

## 2. REAL-IPSEC-v1 Dataset Architecture & Acquisition Metrics

### Dataset Metrics
- **Total Acquired Sessions**: 75 (100% success rate, 0 failed sessions)
- **Total Flow Feature Records**: 198 records in `data/datasets/real_ipsec/real_ipsec_features.csv`
- **Behavioral Classes Represented**:
  - `ICMP_DIAGNOSTIC`: 15 sessions (3 per profile)
  - `WEB_INTERACTIVE`: 15 sessions (3 per profile)
  - `BULK_TRANSFER`: 15 sessions (3 per profile)
  - `STREAMING_MEDIA`: 15 sessions (3 per profile)
  - `VOIP_AUDIO`: 15 sessions (3 per profile)
- **Integrity Violations**: 0
- **Session Leakage**: PASSED (0 session overlap across train/validation/test partitions)
- **Shortcut Warnings**: 0

### Leakage-Safe Session-Level Partitioning (`split_manifest.json`)
- **Training Set (70%)**: 52 sessions (140 flow records)
- **Validation Set (15%)**: 11 sessions (24 flow records)
- **Test Set (15%)**: 12 sessions (34 flow records)
- **Random Seed**: `42`
- **Permanent Excluded OOD Captures**: `TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap`

---

## 3. Dataset Readiness Gate Evaluation
```json
{
  "total_valid_sessions": 75,
  "min_required": 50,
  "session_leakage_violations": 0,
  "duplicate_hashes": 0,
  "forbidden_identifiers_in_X": 0,
  "readiness_gate_status": "DATASET_READY"
}
```

---

## 4. Isolated Candidate Model Retraining & Evaluation

Candidate model retraining was executed on `REAL-IPSEC-v1` using `real_ipsec_features.csv` and `split_manifest.json`. All candidate artifacts were saved strictly under `data/models/candidates/`.

### Candidate Model Comparison
| Candidate Classifier | Validation Macro-F1 | Validation Accuracy | Validation Balanced Accuracy | Test Macro-F1 | Test Accuracy | Candidate Artifact Path |
|---|---|---|---|---|---|---|
| **RandomForestClassifier** | **0.5929** | **0.6250** | **0.6603** | **0.5722** | **0.5882** | `data/models/candidates/candidate_randomforestclassifier.pkl` |
| **HistGradientBoostingClassifier** | **0.5929** | **0.6250** | **0.6603** | **0.6075** | **0.6176** | `data/models/candidates/candidate_histgradientboostingclassifier.pkl` |
| **LogisticRegression** | 0.4511 | 0.4167 | 0.4802 | 0.4508 | 0.4412 | `data/models/candidates/candidate_logisticregression.pkl` |

---

## 5. Non-Negotiable Safety Verification & Sentinel Checksums

### Cryptographic Hash Auditing
| File Path | Purpose | Expected SHA256 Hash | Status |
|---|---|---|---|
| `data/models/final_model.pkl` | Production Model | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | **MATCH** |
| `data/models/preprocessor.pkl` | Production Scaler | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | **MATCH** |
| `data/pcaps/real/TEST-001.pcap` | Permanent OOD Benchmark | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | **MATCH** |
| `data/pcaps/real/TEST-002.pcap` | Permanent OOD Benchmark | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | **MATCH** |
| `data/pcaps/real/TEST-003.pcap` | Permanent OOD Benchmark | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | **MATCH** |

### Automated Test Suite Execution Results
- `backend/tests/test_ml_phase11_6b_real_ipsec_live_acquisition.py`: **20 passed** (100%)
- Full Backend Test Suite (`pytest backend/tests`): **185 passed** (100%)
- Dataset Quality Audit (`scripts/ml/audit_real_ipsec_dataset.py`): **PASSED** (0 violations)
- Frontend Production Build (`cd frontend && npm run build`): **SUCCESS** (0 errors)
- `git diff --check`: **PASSED** (0 trailing whitespace or formatting errors)
