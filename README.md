# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

> **Smart India Hackathon (SIH) Project**

An intelligent cybersecurity platform designed to analyze IPsec VPN deployments from captured network traffic (PCAP) and live traffic streams, evaluate cryptographic strength, classify encrypted traffic via statistical ML, and provide actionable security recommendations through an interactive dashboard.

---

## Current Development Status

- **Phase 1 — Foundation + Architecture Baseline**: COMPLETE
- **Phase 2 — IPsec VPN Testbed**: COMPLETE (Containerized strongSwan testbed & real IPsec PCAPs)
- **Phase 3 — IPsec PCAP Protocol Analyzer**: COMPLETE (Deterministic protocol analyzer & CLI)
- **Phase 4 — Security Assessment Engine**: COMPLETE (Deterministic policy-based security evaluator, scoring & coverage engine)
- **Phase 5 — Dataset & ML Traffic Classification Engine**: COMPLETE (1.64 GB expanded ISCX-VPN2016 dataset, 28 numerical features, Random Forest classifier, 81.47% Test F1, OOD evaluation)
- **Phase 6 — System Integration & End-to-End Validation**: COMPLETE (Unified REST API `/api/v1/analyze`, React Vite frontend dashboard, 3-tier results presentation, 97/97 tests passing)
- **Phase 7 — DEEPSTATE SOC Intelligence Dashboard**: COMPLETE (SOC-style UI, 4 KPI cards, 3-tier report rendering)
- **Phase 8 — System Verification, Hardening & Demonstration**: COMPLETE (CLI demonstration runner, JSON report export, 101/101 tests passing)
- **Phase 9A-1 — DEEPSTATE Demonstration Lab / IPsec Testbed**: COMPLETE
  - User-selectable IPsec profiles
  - StrongSwan live testbed with synthetic fallback
  - ICMP/UDP/TCP traffic generation
  - PCAP capture and handoff to the existing /api/v1/analyze pipeline
  - 107/107 backend tests passing
- **Phase 9A-2 — DEEPSTATE Demonstration Lab 2.0**: COMPLETE
  - Operator-controlled IPsec experiment configuration
  - IKE/encryption/integrity/DH/mode controls
  - ICMP/UDP/TCP/WEB/DNS-LIKE/VOIP-LIKE/FILE-TRANSFER-LIKE traffic profiles
  - Experiment validation, execution and persistent history
  - One-click DEEPSTATE analysis handoff
  - 111/111 backend tests passing
  - Frontend production build passing

---

## High-Level System Architecture

```
                  RAW PCAP FILE
                        │
                        ▼
      Phase 3: Deterministic PCAP Protocol Analyzer
      (IP, UDP 500/4500, ESP Proto 50, IKE, Mode Inference)
                        │
                        ▼
      Phase 4: Security Assessment Engine
      (Crypto rules, SA policies, Risk Score, Threat Matrix)
                        │
                        ▼
      Phase 5: Bidirectional Flow & Feature Extraction
      (28 numerical features, StandardScaler preprocessor)
                        │
                        ▼
      Phase 5: ML Traffic Classifier Inference
      (Trained Random Forest model -> 8 class probabilities)
                        │
                        ▼
            UNIFIED ANALYSIS RESULT (`AnalysisResult`)
      ├── protocol_identification (Observed facts)
      ├── ike & esp details (Observed facts)
      ├── ipsec_parameters (Observed facts)
      ├── security_assessment (Phase 4 Security Score & Findings)
      └── traffic_classification (Phase 5 Inferred Class & Probabilities)
```

---

## Technology Stack

- **Backend**: Python 3.9+, FastAPI, Pydantic v2, Uvicorn, Pytest, Scapy, Cryptography
- **Frontend**: React 18, Vite 5, Lucide Icons, CSS3
- **Data / ML (Planned)**: pandas, numpy, scikit-learn

---

## Project Structure

```
ipsec-vpn-analyzer/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       └── router.py         # REST API endpoints (/health)
│   │   ├── analyzers/                # Phase 3 Protocol Analyzer
│   │   │   ├── pcap_reader.py
│   │   │   ├── packet_classifier.py
│   │   │   ├── ike_analyzer.py
│   │   │   ├── esp_analyzer.py
│   │   │   ├── mode_detector.py
│   │   │   ├── traffic_analyzer.py
│   │   │   └── protocol_analyzer.py
│   │   ├── assessment/               # Phase 4 Security Assessment Engine
│   │   │   ├── policies.py           # Centralized security policy
│   │   │   ├── crypto_rules.py       # Encryption & integrity rules
│   │   │   ├── protocol_rules.py     # IKE protocol rules
│   │   │   ├── sa_rules.py           # DH groups, PFS & SA rules
│   │   │   ├── metadata_rules.py     # Metadata exposure rules
│   │   │   ├── scoring.py            # Score (0-100) & coverage formula
│   │   │   └── engine.py             # Main SecurityAssessmentEngine
│   │   ├── ml/                       # ML classification engine module (Phase 5)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── schemas.py            # Pydantic v2 Data Contracts
│   │   ├── services/                 # Business logic services
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   └── config.py             # Application settings & CORS
│   │   └── main.py                   # FastAPI entry point
│   ├── tests/                        # Comprehensive Pytest test suite
│   │   ├── test_health.py
│   │   ├── test_schemas.py
│   │   ├── test_imports.py
│   │   ├── test_pcap_reader.py
│   │   ├── test_protocol_analyzer.py
│   │   └── test_assessment_engine.py # Phase 4 assessment engine tests
│   └── requirements.txt              # Authoritative backend Python dependencies
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── client.js             # HTTP API client for backend /health
│   │   ├── components/
│   │   │   ├── Header.jsx
│   │   │   ├── Sidebar.jsx
│   │   │   └── StatusCard.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── data/                             # Data storage placeholders
│   ├── pcaps/
│   │   ├── real/                     # Live strongSwan captures
│   │   └── synthetic/                # Synthetic development fixtures
│   ├── datasets/
│   └── samples/
├── docs/
│   ├── ARCHITECTURE.md               # Detailed architectural specification
│   ├── TESTBED.md                    # Lab & testbed documentation
│   ├── ANALYZER.md                   # Phase 3 Protocol Analyzer documentation
│   └── ASSESSMENT.md                 # Phase 4 Security Assessment documentation
├── scripts/                          # Testbed & utility scripts
├── .gitignore                        # Git ignore rules
└── README.md                         # Project documentation
```

---

## How to Run & Verify

### 1. Run Complete Test Suite (Phase 1 + Phase 3 + Phase 4)

```bash
source .venv/bin/activate
PYTHONPATH=. pytest backend/tests
```

### 2. Run Protocol Analyzer & Security Assessment Pipeline

```bash
source .venv/bin/activate
python3 -m backend.app.analyzers.protocol_analyzer data/pcaps/synthetic/SYNTH-TEST-001.pcap --json
```

### 3. Run FastAPI Backend Server

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify health:
```bash
curl -s http://127.0.0.1:8000/health
```

---

## System Status Summary

All core phases (Phase 1 through Phase 9A-2) are **COMPLETE and FULLY VERIFIED**.
- 111 / 111 Pytest Backend Unit & Integration Tests Passing
- Frontend Production Build Passing
- 3-Tier Analysis Pipeline (Protocol Facts + Security Assessment + ML Classification) Fully Operational
