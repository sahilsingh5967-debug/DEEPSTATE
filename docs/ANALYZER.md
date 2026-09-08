# IPsec PCAP Protocol Analyzer Documentation

> **Phase 3 Protocol Analysis Subsystem Specification**

The **IPsec PCAP Protocol Analyzer** is a deterministic, offline Python subsystem that ingests network packet captures (PCAP), classifies protocol layers, parses observable IKE/ESP/AH parameters, infers VPN mode (Tunnel vs Transport) with explicit confidence scores, and outputs a structured `AnalysisResult` Pydantic v2 object.

---

## 1. Subsystem Architecture

The analyzer is organized under `backend/app/analyzers/` with strict separation of responsibilities:

```
backend/app/analyzers/
├── __init__.py
├── pcap_reader.py         # PCAP file loading & metadata extraction
├── packet_classifier.py   # Layer 3/4 & IPsec protocol identification
├── ike_analyzer.py        # IKEv1/v2 header, exchange type, SPI & proposal parsing
├── esp_analyzer.py        # ESP SPI, sequence number, packet count & encapsulation
├── mode_detector.py       # Deterministic Tunnel vs Transport mode inference
├── traffic_analyzer.py    # Unencrypted layer analysis & payload encryption detection
└── protocol_analyzer.py   # Main orchestrator & CLI entry point
```

---

## 2. Observed vs. Inferred Methodology

To maintain scientific rigor in cybersecurity research, the analyzer enforces a strict boundary between directly observed protocol facts and derived inferences:

| Category | Description | Examples | Representation |
| :--- | :--- | :--- | :--- |
| **Observed** | Facts directly present in packet header bytes | UDP port 500, ESP proto 50, IKEv2 version byte `0x20`, Initiator SPI `0x1a2b...`, ESP SPI `0x0a0b0c0d` | Explicit values or `null`/`None` if absent |
| **Inferred** | Derived conclusions based on observable heuristics | Tunnel vs Transport mode, traffic category | `InferredValue(value, confidence, evidence)` |

---

## 3. Confidence Model & Heuristics

Derived inferences require explicit numeric confidence scores (0.0 to 1.0) and an observational evidence list:

- **Mode Inference Heuristics (`mode_detector.py`)**:
  - **Confidence = 0.95**: Unencrypted IKE SA proposal payload explicitly contains Tunnel/Transport mode attribute (Attribute 1 or 2).
  - **Confidence = 0.90**: Outer IP header (e.g. `192.168.100.x`) encapsulates an inner IP header (e.g. `10.1.0.x`).
  - **Confidence = 0.0 (`Unknown`)**: Only encrypted ESP packets (Proto 50) observed without IKE SA proposals or unencrypted inner IP headers.

- **Traffic Analysis Heuristics (`traffic_analyzer.py`)**:
  - **Confidence = 0.95**: Unencrypted ICMP/TCP/UDP packet layers directly observed.
  - **Confidence = 0.0 (`Encrypted ESP Payload`)**: Traffic payload is encapsulated and encrypted inside ESP (IP Proto 50).

---

## 4. CLI Usage

Run the protocol analyzer from the project root:

### Terminal Human-Readable Report
```bash
python3 -m backend.app.analyzers.protocol_analyzer data/pcaps/synthetic/SYNTH-TEST-001.pcap
```

### JSON Serialization Output
```bash
python3 -m backend.app.analyzers.protocol_analyzer data/pcaps/synthetic/SYNTH-TEST-001.pcap --json
```

---

## 5. Synthetic Fixture Analysis & Limitations

Synthetic development fixtures (`data/pcaps/synthetic/`) are generated for parser testing. When analyzed:
- **Observed**: IKEv2 header version (`IKEv2`), Exchange Type (`IKE_SA_INIT`), Initiator SPI, ESP SPI (`0x0a0b0c0d`), ESP packet count (10 packets), Direct-ESP encapsulation.
- **Null / Unknown**: Detailed cryptographic proposals (encryption/integrity algorithms, DH groups) remain `null`/`empty` when synthetic fixtures do not include full unencrypted IKE SA proposal payload bytes.
- **Warnings**: The analyzer explicitly records analysis warnings (e.g. `"No explicit unencrypted SA proposal transforms observed..."` and `"Insufficient observable evidence in PCAP to verify Tunnel vs Transport mode"`).
