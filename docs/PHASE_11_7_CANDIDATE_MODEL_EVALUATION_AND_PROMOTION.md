# Phase 11.7 — DEEPSTATE Candidate Model Evaluation, Production Comparison & Promotion Gate Report

## Executive Summary
Phase 11.7 executed a complete, reproducible, safety-critical evaluation of candidate ML models (`HistGradientBoostingClassifier`, `RandomForestClassifier`, `LogisticRegression`) trained on the newly acquired `REAL-IPSEC-v1` dataset against the current production model baseline (`final_model.pkl` & `preprocessor.pkl`).

All production sentinel artifacts (`final_model.pkl` & `preprocessor.pkl`) and permanent OOD benchmark PCAPs (`TEST-001.pcap`, `TEST-002.pcap`, `TEST-003.pcap`) remained 100% untouched and cryptographically verified against baseline SHA256 checksums.

Out of the 14 mandatory promotion gates:
- **13 Gates PASSED**: Production Model Integrity, Production Preprocessor Integrity, OOD Benchmark Integrity, REAL-IPSEC-v1 Dataset Integrity, Session Leakage, Forbidden Identifiers Exclusion, Feature Contract, Ground-Truth Independence, Real-IPsec Dataset Readiness, Candidate Reproducibility, Candidate Performance Improvement over Production, OOD Generalization Safety, and Production Deployment Safety.
- **1 Gate FAILED**: **Gate 12 — Per-Class Safety**. The top-performing candidate (`HistGradientBoostingClassifier`) introduced a severe per-class regression on `ICMP_DIAGNOSTIC` (Production F1: `0.2941` vs Candidate F1: `0.0000`).

### Final Promotion Verdict
```
FINAL PROMOTION STATUS: PROMOTION_REJECTED
```
> [!IMPORTANT]
> **Dataset Readiness vs Model Promotion**:
> While `REAL-IPSEC-v1` is **`DATASET_READY`**, candidate model promotion is **`PROMOTION_REJECTED`** due to Gate 12 per-class safety failure. Production model artifacts (`final_model.pkl` and `preprocessor.pkl`) remain active and 100% untouched.

---

## 1. Production Model & Sentinel Artifact Audit

| Sentinel Artifact | File Path | Baseline SHA256 | Actual SHA256 | Status |
|---|---|---|---|---|
| Production Model | `data/models/final_model.pkl` | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | `e67d90ad7317e0793a95764b83c314ebec07a1861855478084028682258e74e4` | **MATCH** |
| Production Preprocessor | `data/models/preprocessor.pkl` | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | `f66f06e21cdd20af7d42ab05175c94cef902e133a976ea98aa6ddb0f283c42a2` | **MATCH** |
| OOD Benchmark 1 | `data/pcaps/real/TEST-001.pcap` | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | `e14c3f5f7e56284218ecddd4e7b6e4119a12588559262451d4bc577b074fd813` | **MATCH** |
| OOD Benchmark 2 | `data/pcaps/real/TEST-002.pcap` | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | `cd4b28e09d007422c899f955a04c285671e06f6a2b4bca3ca25ae7d5cc8ef78c` | **MATCH** |
| OOD Benchmark 3 | `data/pcaps/real/TEST-003.pcap` | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | `719d15cfc3cf2cd3d50ab6a7e961cd92ead2cea62611b1446d34a78d22eff229` | **MATCH** |

---

## 2. REAL-IPSEC-v1 Dataset Architecture & Split Integrity
- **Dataset ID**: `REAL-IPSEC-v1`
- **Total Sessions**: 75 registered sessions (198 flow records)
- **Predictive Feature Schema**: Exactly 28 predictive features (`ML_FEATURE_COLUMNS`)
- **Metadata Separation**: IPs, Ports, Session/Capture IDs strictly excluded from matrix `X`
- **Ground-Truth Source**: `PRE_CAPTURE_EXPERIMENT_CONFIGURATION`
- **Session-Level Partitions**:
  - Train: 52 sessions (140 flow records)
  - Validation: 11 sessions (24 flow records)
  - Test: 12 sessions (34 flow records)
  - Zero session overlap across partitions (`Train ∩ Val = ∅`, `Train ∩ Test = ∅`, `Val ∩ Test = ∅`).

---

## 3. Production Baseline vs Candidate Model Evaluation

Models were evaluated on the held-out `REAL-IPSEC-v1` validation and test partitions:

| Classifier Model | Validation Macro-F1 | Validation Accuracy | Validation Balanced Acc | Test Macro-F1 | Test Accuracy | Test Balanced Acc | Status |
|---|---|---|---|---|---|---|---|
| **Production Baseline** (`final_model.pkl`) | 0.0185 | 0.2083 | 0.2000 | 0.0747 | 0.1765 | 0.1600 | Baseline |
| **HistGradientBoostingClassifier** | **0.1593** | **0.3750** | **0.3429** | **0.1680** | **0.3235** | **0.2900** | Top Candidate |
| **LogisticRegression** | 0.0948 | 0.2500 | 0.2286 | 0.1195 | 0.2647 | 0.2300 | Evaluated |
| **RandomForestClassifier** | 0.0000 | 0.1667 | 0.2000 | 0.0662 | 0.2059 | 0.1700 | Evaluated |

---

## 4. Per-Class Performance Breakdown (Test Split)

| Behavioral Target Class | Production Baseline F1 | HistGradientBoosting F1 | Delta (Candidate - Prod) | Per-Class Safety Status |
|---|---|---|---|---|
| `ICMP_DIAGNOSTIC` | **0.2941** | **0.0000** | **-0.2941** | **REGRESSION (FAIL)** |
| `WEB_INTERACTIVE` | 0.0000 | 0.1538 | +0.1538 | PASS |
| `BULK_TRANSFER` | 0.0000 | 0.0000 | 0.0000 | PASS |
| `STREAMING_MEDIA` | 0.0000 | 0.5000 | +0.5000 | PASS |
| `VOIP_AUDIO` | 0.0769 | 0.1875 | +0.1106 | PASS |

> [!WARNING]
> **Per-Class Regression Analysis**:
> While `HistGradientBoostingClassifier` achieved an overall Test Macro-F1 improvement (`0.1680` vs `0.0747`), its F1 score for `ICMP_DIAGNOSTIC` dropped from `0.2941` to `0.0000`, violating Gate 12 (Per-Class Safety).

---

## 5. 14 Mandatory Promotion Gates Summary

| Gate ID | Gate Name | Status | Measured Value / Evidence |
|---|---|---|---|
| **Gate 1** | Production Model Integrity | **PASS** | `final_model.pkl` SHA256 matches baseline |
| **Gate 2** | Production Preprocessor Integrity | **PASS** | `preprocessor.pkl` SHA256 matches baseline |
| **Gate 3** | OOD Benchmark Integrity | **PASS** | `TEST-001/002/003.pcap` SHA256 hashes match baseline |
| **Gate 4** | REAL-IPSEC-v1 Dataset Integrity | **PASS** | 75 sessions, 198 records, 0 integrity violations |
| **Gate 5** | Session-Level Zero Leakage | **PASS** | 0 session overlap across train/val/test splits |
| **Gate 6** | Forbidden Identifier Exclusion | **PASS** | IPs, Ports, IDs absent from X |
| **Gate 7** | Feature Contract | **PASS** | Exactly 28 predictive features schema enforced |
| **Gate 8** | Ground-Truth Independence | **PASS** | `PRE_CAPTURE_EXPERIMENT_CONFIGURATION` |
| **Gate 9** | Real-IPsec Dataset Readiness | **PASS** | Dataset status: `DATASET_READY` |
| **Gate 10** | Candidate Reproducibility | **PASS** | Seed 42 deterministic reproduction |
| **Gate 11** | Candidate Performance Improvement | **PASS** | Test Macro-F1: Candidate `0.1680` > Production `0.0747` |
| **Gate 12** | Per-Class Safety | **FAIL** | Severe regression on `ICMP_DIAGNOSTIC` (F1 `0.2941` -> `0.0`) |
| **Gate 13** | OOD Generalization Safety | **PASS** | OOD benchmark execution intact |
| **Gate 14** | Production Deployment Safety | **PASS** | Candidate isolated in `candidates/phase11_7/`, no auto-overwrite |

---

## 6. Automated Quality & Verification Results
- **Phase 11.7 Automated Test Suite**: `test_ml_phase11_7_candidate_promotion.py` — **30 passed** (100%)
- **Full Backend Test Suite**: `pytest backend/tests` — **215 passed** (100%)
- **Dataset Quality Audit**: `scripts/ml/audit_real_ipsec_dataset.py` — **PASSED** (0 violations)
- **Frontend Production Build**: `cd frontend && npm run build` — **SUCCESS** (0 errors)
- **Git Whitespace Check**: `git diff --check` — **PASSED** (0 formatting errors)

---

## 7. Next Actions & Policy Guidance
1. **Maintain Production Artifacts**: Production model files `data/models/final_model.pkl` and `data/models/preprocessor.pkl` remain the active inference engine.
2. **Future Dataset Augmentation**: Address `ICMP_DIAGNOSTIC` class representation in future data acquisition iterations (Phase 11.8+) to resolve per-class safety regressions before evaluating subsequent candidate models for production promotion.
