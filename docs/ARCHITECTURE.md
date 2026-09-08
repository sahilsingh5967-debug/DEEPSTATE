# System Architecture & Component Design

## 1. High-Level Architecture

The **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** is designed with a decoupled, modular architecture. Each major subsystem operates independently, communicating via well-defined data contracts over REST APIs.

```
                    ┌──────────────────────┐
                    │   IPsec Testbed      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ PCAP / Live Traffic  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Protocol Analyzer   │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
          ┌─────────────────┐   ┌─────────────────┐
          │ Security Engine │   │   ML Engine     │
          └────────┬────────┘   └────────┬────────┘
                   │                     │
                   └──────────┬──────────┘
                              ▼
                    ┌──────────────────────┐
                    │     Backend/API      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Interactive Dashboard │
                    └──────────┬───────────┘
                               │
                       ┌───────┴────────┐
                       ▼                ▼
                   Reports         AI Explanation
```

## 2. Component Separation & Responsibilities

1. **PCAP Ingestion & Protocol Analyzer (`backend/app/analyzers/`)**:
   - Ingests raw PCAP packet captures or live network traffic streams.
   - Extracts IKEv1/IKEv2 headers, Security Associations (SA), Diffie-Hellman groups, encryption & integrity algorithms, and encapsulation modes (Tunnel vs Transport).
   - Produces populated `IPsecParameters` schema objects.

2. **Security Assessment Engine (`backend/app/assessment/`)**:
   - Evaluates extracted `IPsecParameters` against deterministic security rules, cryptographic standards (NIST/RFC recommendations), and deprecation criteria.
   - Computes a security score (0.0 to 100.0) and risk level.
   - Generates structured `SecurityFinding` list and actionable recommendations.
   - Produces populated `SecurityAssessment` schema objects.

3. **ML Traffic Classification Engine (`backend/app/ml/`)**:
   - Extracts statistical traffic metadata (packet size distributions, inter-arrival times, flow duration) from encrypted ESP flows.
   - Applies trained machine learning classifiers (pandas, scikit-learn) to predict underlying traffic types (VOIP, HTTPS, Bulk, Streaming).
   - Produces populated `TrafficClassification` schema objects.

4. **Backend REST API (`backend/app/api/`)**:
   - Built on FastAPI.
   - Provides asynchronous REST endpoints for analysis jobs, status queries, and health verification.
   - Strictly enforces input validation using Pydantic v2 schemas.

5. **Interactive Dashboard (`frontend/`)**:
   - Modern React + Vite application.
   - Communicates with backend REST API.
   - Presents security scores, threat matrices, protocol breakdown, and ML predictions visually.

## 3. Data Contracts Summary

All subsystem boundaries communicate using preliminary schemas defined in `backend/app/models/schemas.py`:

- **`AnalysisRequest`**: Ingestion request parameters.
- **`IPsecParameters`**: Protocol parameters extracted from traffic.
- **`SecurityFinding`**: Individual cryptographic/configuration weakness finding.
- **`SecurityAssessment`**: Aggregated security score, risk level, threat matrix, and recommendations.
- **`TrafficClassification`**: ML predicted traffic class, confidence, and probability distribution.
- **`AnalysisResult`**: Top-level API response bundling protocol parameters, security assessment, and ML classification.

## 4. Architectural Principles & Rules

- **Decoupling**: Security evaluation rules MUST NOT reside inside ML models.
- **Deterministic Security**: Cryptographic strength and RFC compliance are evaluated deterministically by the Security Assessment Engine, not by an LLM or probabilistic model.
- **Modularity**: Subsystems can be updated, tested, or replaced independently without breaking REST API contracts.
