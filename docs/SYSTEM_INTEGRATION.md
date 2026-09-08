# Phase 6 — System Integration & End-to-End Validation Specification

## 1. Overview & Objective
Phase 6 completes full system integration across all analytical tiers of the **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**. It connects the React/Vite frontend dashboard with the FastAPI backend, orchestrating deterministic protocol parsing (Phase 3), policy-based security assessment (Phase 4), and statistical ML traffic classification inference (Phase 5) into one unified workflow.

---

## 2. End-to-End System Architecture

```
PCAP FILE (User Preset / Custom Path)
   │
   ▼
React + Vite Frontend Dashboard (http://127.0.0.1:5173)
   │
   ▼  HTTP POST /api/v1/analyze (JSON payload)
FastAPI REST API Backend (http://127.0.0.1:8000)
   │
   ├─► 1. Phase 3: Deterministic PCAP Protocol Analyzer
   │      (IP, UDP 500/4500, ESP Proto 50, IKE, Mode Inference)
   │
   ├─► 2. Phase 4: Security Assessment Engine
   │      (Policy Evaluation, Crypto Scoring, Threat Matrix)
   │
   └─► 3. Phase 5: ML Traffic Classification Inference Pipeline
          (Flow/Feature Extraction, StandardScaler, Random Forest)
   │
   ▼
Unified AnalysisResult Response Object
   │
   ▼  HTTP 200 OK
Frontend Interactive 3-Tier Results Presentation
   ├── Tier A: Observed Protocol Facts (Phase 3)
   ├── Tier B: Security Assessment Engine (Phase 4 Score & Findings)
   └── Tier C: ML Traffic Classification Inference (Phase 5 + Mandatory Disclaimer)
```

---

## 3. Strict Analytical Layer Separation Policy

| Analytical Tier | Source Component | Output Type | Representation Rules |
| :--- | :--- | :--- | :--- |
| **Tier A: Protocol Observations** | Phase 3 Scapy Analyzer | **Observed Facts** | Header parameters (`ESP`, `IKEv2`, `SPI: 0x...`, `AES-CBC-128`, `Group 5`). Labeled as **OBSERVED PROTOCOL FACTS**. |
| **Tier B: Security Assessment** | Phase 4 Security Engine | **Deterministic Assessment** | Policy evaluation score (`90.0/100`), risk status (`MEDIUM_RISK`), passed/failed checks, category summary. |
| **Tier C: ML Traffic Classification** | Phase 5 Classifier | **Probabilistic Inference** | Statistical predictions (`VoIP`, `ICMP`, confidence `0.4225`, 8-class probabilities). Labeled as **ML PROBABILISTIC INFERENCE**. |

> [!CAUTION]
> **Mandatory ML Disclaimer**:
> *"This classification is an ML model inference based on encrypted flow statistics and is NOT an observed protocol fact."*

---

## 4. API Endpoints Registry

### 1. `GET /health`
- **Description**: Machine-readable operational health status.
- **Response**: `{"status": "ok", "version": "0.1.0", "timestamp": "..."}`

### 2. `GET /api/v1/pcaps`
- **Description**: Returns list of available preset PCAPs in `data/pcaps/real/` and `data/pcaps/synthetic/`.
- **Response**: Array of PCAP objects with `id`, `name`, `category`, `file_path`, `size_bytes`.

### 3. `POST /api/v1/analyze`
- **Description**: Executes complete unified IPsec analysis pipeline.
- **Request Body**: `{"source_type": "pcap_file", "file_path": "data/pcaps/real/TEST-001.pcap"}`
- **Response Model**: `AnalysisResult` containing `protocol_identification`, `ike`, `esp`, `ipsec_parameters`, `mode_inference`, `security_assessment`, and `traffic_classification`.

---

## 5. Fault Tolerance & Error Handling Verification

| Failure Scenario | Protocol Analyzer | Security Engine | ML Classification | API Response |
| :--- | :--- | :--- | :--- | :--- |
| **Model Artifact Missing** (`final_model.pkl`) | **PASS** (Normal facts) | **PASS** (Normal score) | `status: "unavailable"`, `reason: "Model missing"` | **HTTP 200 OK** |
| **No Active Flows Extracted** | **PASS** (Normal facts) | **PASS** (Normal score) | `status: "no_flows"`, zeroed probabilities | **HTTP 200 OK** |
| **Invalid PCAP Path** | N/A | N/A | N/A | **HTTP 404 Not Found** |
| **Empty File / Parsing Exception** | `status: "failed"` | `status: "LIMITED_ASSESSMENT"` | `status: "unavailable"` | **HTTP 200 OK** |

---

## 6. Execution & Verification Commands

```bash
# 1. Activate Virtual Environment
source .venv/bin/activate

# 2. Launch FastAPI Backend Server
PYTHONPATH=. ./.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# 3. Launch React/Vite Frontend Server (in second terminal)
cd frontend && npm run dev

# 4. Execute Full Automated Test Suite (97 Tests)
PYTHONPATH=. ./.venv/bin/python -m pytest backend/tests -v
```
