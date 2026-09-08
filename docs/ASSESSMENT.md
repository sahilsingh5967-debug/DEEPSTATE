# IPsec Security Assessment Engine Specification

> **Phase 4 Security Assessment Subsystem Documentation**

The **Security Assessment Engine** is a deterministic, explainable Python subsystem that ingests structured protocol observations (`AnalysisResult`) from Phase 3, evaluates them against a centralized security policy, applies strict unknown-handling rules, and outputs a comprehensive `SecurityAssessment` model containing a security score (0–100), coverage metric, risk status, threat matrix, detailed findings, and actionable recommendations.

---

## 1. Subsystem Architecture

The assessment engine is organized under `backend/app/assessment/`:

```
backend/app/assessment/
├── __init__.py
├── policies.py         # Centralized security policy & algorithm definitions
├── crypto_rules.py     # Encryption, integrity, and cipher suite rules
├── protocol_rules.py   # IKE version & protocol rules
├── sa_rules.py         # DH group, PFS, SA, replay & lifetime rules
├── metadata_rules.py   # Observable metadata exposure rules
├── scoring.py          # Deterministic score & coverage calculation
└── engine.py           # Main SecurityAssessmentEngine orchestrator
```

---

## 2. Input / Output Contract

```
   Phase 3 Protocol Analyzer
             │
      AnalysisResult
             │
             ▼
SecurityAssessmentEngine.assess()
             │
             ▼
     SecurityAssessment
     ├── security_score (0.0 to 100.0)
     ├── score_confidence (0.0 to 1.0)
     ├── assessment_coverage (0.0 to 1.0)
     ├── overall_status (SECURE / LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL_RISK / LIMITED_ASSESSMENT)
     ├── findings[] (List of SecurityFinding models)
     ├── passed_checks, failed_checks, warning_checks, unknown_checks
     ├── category_summary
     ├── threat_matrix
     └── recommendations_summary[]
```

---

## 3. Finding Status Semantics

Every finding uses a strict state model:

| Status | Meaning | Score Impact |
| :--- | :--- | :--- |
| **`PASS`** | Evidence confirms configuration satisfies security policy | No penalty |
| **`FAIL`** | Evidence confirms a security weakness or deprecated algorithm | Penalty subtracted based on severity |
| **`WARNING`** | Configuration is usable but represents a legacy choice (e.g. CBC mode) | Half-penalty subtracted |
| **`UNKNOWN`** | Parameter is unobservable in capture bytes (incomplete evidence) | **No penalty** (Reduces coverage metric) |
| **`NOT_OBSERVED`** | Parameter/check not present or applicable in capture | **No penalty** |

---

## 4. Strict Unknown-Handling Rule

Unobservable parameters **MUST NOT** be automatically treated as insecure or failed.

- **Missing Encryption Algorithm**: Status `UNKNOWN` (*"Encryption algorithm could not be determined"*), NOT `FAIL`.
- **Missing DH Group**: Status `UNKNOWN` (*"Diffie-Hellman group could not be determined"*), NOT `FAIL`.
- **Unknown PFS Status**: Status `UNKNOWN` (*"PFS status could not be determined"*), NOT `FAIL`.

Incomplete captures (such as synthetic fixtures) reduce the `assessment_coverage` metric rather than manufacturing artificial security penalties.

---

## 5. Scoring & Coverage Formula

### Assessment Coverage Calculation
$$\text{Coverage} = \frac{\text{Evaluated Checks (PASS + FAIL + WARNING)}}{\text{Total Applicable Checks (Evaluated + UNKNOWN)}}$$

### Security Score Calculation (0 – 100)
$$\text{Base Score} = 100.0$$
$$\text{Total Penalties} = \sum \text{Severity Weight}(\text{FAIL}) + \sum 0.5 \times \text{Severity Weight}(\text{WARNING})$$
$$\text{Security Score} = \max\left(0.0, 100.0 - \text{Total Penalties}\right)$$

#### Severity Penalty Weights:
- **`CRITICAL`**: -25.0 points
- **`HIGH`**: -15.0 points
- **`MEDIUM`**: -10.0 points
- **`LOW`**: -5.0 points
- **`INFO`**: 0.0 points

---

## 6. End-to-End Synthetic PCAP Flow Example

When `data/pcaps/synthetic/SYNTH-TEST-001.pcap` is evaluated:
1. **Phase 3 Analyzer** extracts observed fields (IKEv2 header, ESP SPI `0x0a0b0c0d`, 10 ESP packets) and reports unobservable proposal algorithms as `empty`/`null`.
2. **Phase 4 Assessment Engine** evaluates the `AnalysisResult`:
   - `SEC-PROTO-IKEv2-PASS`: `PASS` (IKEv2 observed)
   - `SEC-CRYPTO-ENC-UNKNOWN`: `UNKNOWN` (Encryption algorithm unobservable)
   - `SEC-KEYEX-DH-UNKNOWN`: `UNKNOWN` (DH group unobservable)
   - `SEC-PFS-STATUS-UNKNOWN`: `UNKNOWN` (PFS status unobservable)
   - `SEC-META-ENDPOINT-EXPOSURE`: `PASS` (Outer IP endpoints visible)
3. **Assessment Output**:
   - `security_score`: 100.0 (No confirmed security failures)
   - `assessment_coverage`: 0.40 (40% coverage due to unobservable cryptographic parameters)
   - `unknown_checks`: 3
   - `overall_status`: "SECURE" (High quality on evaluated checks, with low coverage warning)

---

## 7. Phase 5 Readiness

Phase 5 (Dataset & ML Traffic Classification Engine) will consume:
1. `AnalysisResult.esp` (ESP packet count, sequence progression, payload length distributions).
2. `SecurityAssessment.security_score` & `findings` (for security correlation).
