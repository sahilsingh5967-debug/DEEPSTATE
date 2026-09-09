"""
Experiment Model, Supported Options Registry, and Educational Knowledge Base for Demonstration Lab 2.0.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class PeerConfig(BaseModel):
    id: str = Field("peer-a", description="Peer container hostname or identifier")
    subnet: str = Field("10.1.0.0/24", description="Traffic subnet selector")
    traffic_ip: str = Field("10.1.0.1", description="Assigned traffic IP address")


class ExperimentConfig(BaseModel):
    name: str = Field("Custom Experiment", description="Operator experiment label")
    peer_a: PeerConfig = Field(default_factory=lambda: PeerConfig(id="peer-a", subnet="10.1.0.0/24", traffic_ip="10.1.0.1"))
    peer_b: PeerConfig = Field(default_factory=lambda: PeerConfig(id="peer-b", subnet="10.2.0.0/24", traffic_ip="10.2.0.1"))
    ike_version: str = Field("IKEv2", description="IKE protocol version ('IKEv2')")
    mode: str = Field("tunnel", description="IPsec mode ('tunnel', 'transport')")
    encryption: str = Field("AES-256-GCM", description="Encryption algorithm ('AES-128-CBC', 'AES-256-CBC', 'AES-256-GCM')")
    integrity: str = Field("NONE", description="Integrity algorithm ('SHA256', 'SHA384', 'NONE')")
    dh_group: str = Field("ECP256", description="Diffie-Hellman group ('MODP2048', 'ECP256', 'ECP384')")
    traffic_type: str = Field("UDP", description="Traffic pattern ('ICMP', 'UDP', 'TCP', 'WEB', 'DNS-LIKE', 'VOIP-LIKE', 'FILE-TRANSFER-LIKE')")
    destination_port: int = Field(5060, ge=1, le=65535, description="Destination port")
    packet_count: int = Field(50, ge=1, le=500, description="Total packet count to generate")
    packet_rate: int = Field(20, ge=1, le=100, description="Target packet rate per second")
    payload_size: int = Field(512, ge=32, le=1400, description="Payload size in bytes per packet")
    duration: int = Field(5, ge=1, le=60, description="Traffic duration in seconds")
    execution_mode: str = Field("auto", description="Execution mode ('auto', 'live', 'synthetic')")
    notes: Optional[str] = Field(None, description="Operator experiment notes")


CONFIG_OPTIONS: Dict[str, Any] = {
    "ike_versions": ["IKEv2"],
    "modes": [
        {"id": "tunnel", "label": "Tunnel Mode", "description": "Encapsulates full IP packet inside new IPsec IP header"},
        {"id": "transport", "label": "Transport Mode", "description": "Encrypts IP payload only, preserving original IP header"}
    ],
    "encryptions": [
        {"id": "AES-128-CBC", "label": "AES-128-CBC", "type": "CBC", "key_bits": 128, "security_level": "SECURE_STANDARD"},
        {"id": "AES-256-CBC", "label": "AES-256-CBC", "type": "CBC", "key_bits": 256, "security_level": "SECURE_STANDARD"},
        {"id": "AES-256-GCM", "label": "AES-256-GCM", "type": "AEAD", "key_bits": 256, "security_level": "HIGH_SECURITY"}
    ],
    "integrities": [
        {"id": "SHA256", "label": "HMAC-SHA-256", "bits": 256},
        {"id": "SHA384", "label": "HMAC-SHA-384", "bits": 384},
        {"id": "NONE", "label": "None (AEAD Implicit)", "bits": 0}
    ],
    "dh_groups": [
        {"id": "MODP2048", "label": "Group 14 (MODP2048)", "bits": 2048, "type": "MODP"},
        {"id": "ECP256", "label": "Group 19 (ECP256)", "bits": 256, "type": "Elliptic Curve"},
        {"id": "ECP384", "label": "Group 20 (ECP384)", "bits": 384, "type": "Elliptic Curve"}
    ],
    "traffic_types": [
        {"id": "ICMP", "label": "ICMP Echo", "default_port": None, "category": "Network Management"},
        {"id": "UDP", "label": "UDP Burst", "default_port": 5001, "category": "Transport Layer"},
        {"id": "TCP", "label": "TCP Stream", "default_port": 8080, "category": "Transport Layer"},
        {"id": "WEB", "label": "Web (HTTPS/HTTP)", "default_port": 443, "category": "Application Simulation"},
        {"id": "DNS-LIKE", "label": "DNS Query Stream", "default_port": 53, "category": "Application Simulation"},
        {"id": "VOIP-LIKE", "label": "VoIP / RTP Audio", "default_port": 5060, "category": "Application Simulation"},
        {"id": "FILE-TRANSFER-LIKE", "label": "Bulk File Transfer", "default_port": 443, "category": "Application Simulation"}
    ]
}


EDUCATIONAL_KNOWLEDGE_BASE: Dict[str, Dict[str, str]] = {
    "IKEv2": {
        "title": "Internet Key Exchange v2 (IKEv2)",
        "rfc": "RFC 7296",
        "explanation": "IKEv2 handles peer authentication, Diffie-Hellman key exchange, and Security Association (SA) negotiation over UDP ports 500/4500.",
        "observable_facts": "DEEPSTATE extracts observed Initiator/Responder SPIs, exchange types (IKE_SA_INIT, IKE_AUTH), and cipher proposals.",
        "limitations": "Payloads after IKE_SA_INIT are encrypted with negotiated IKE keys and cannot be read without private key material."
    },
    "AES-256-GCM": {
        "title": "AES-256 Galois/Counter Mode (GCM)",
        "rfc": "RFC 4106 / RFC 5288",
        "explanation": "AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher providing high confidentiality and integrity simultaneously.",
        "observable_facts": "Tier B Security Engine awards maximum security score (100/100) for AEAD GCM proposals.",
        "limitations": "ESP packet payloads remain strictly encrypted. DEEPSTATE relies on statistical flow dynamics for ML traffic classification."
    },
    "AES-128-CBC": {
        "title": "AES-128 Cipher Block Chaining (CBC)",
        "rfc": "RFC 3602",
        "explanation": "Standard block cipher encryption. Requires an explicit HMAC integrity algorithm (e.g. SHA-256) to ensure packet authenticity.",
        "observable_facts": "Observed in legacy enterprise IPsec deployments. Tier B checks for paired integrity algorithms.",
        "limitations": "Subject to padding oracle attacks if integrity verification is missing or misconfigured."
    },
    "Tunnel": {
        "title": "IPsec Tunnel Mode",
        "rfc": "RFC 4301",
        "explanation": "Encapsulates the entire original IP datagram inside a outer IP header and ESP header. Commonly used for gateway-to-gateway VPNs.",
        "observable_facts": "Outer IP headers show peer addresses (e.g., 192.168.100.2 -> 192.168.100.3). Original inner subnets (10.1.0.0/24) are hidden.",
        "limitations": "Mode inference uses packet length delta heuristics when raw negotiation payloads are encrypted."
    },
    "Transport": {
        "title": "IPsec Transport Mode",
        "rfc": "RFC 4301",
        "explanation": "Encrypts only the IP payload (L4+), keeping the original IP header intact. Ideal for host-to-host direct communications.",
        "observable_facts": "Preserves original endpoint IP addresses without adding an outer IP header overhead.",
        "limitations": "Exposes host endpoint identities to intermediate network observers."
    },
    "VOIP-LIKE": {
        "title": "VoIP / RTP Audio Traffic Simulation",
        "rfc": "RFC 3550 / RFC 3261",
        "explanation": "Simulates real-time voice traffic over UDP/5060. Characterized by uniform packet sizes (~160-200 bytes) and strict periodic timing.",
        "observable_facts": "Tier C ML Flow Extractor computes packet inter-arrival time variance and length standard deviation to classify VoIP flows.",
        "limitations": "Classification is a statistical inference based on encrypted flow dynamics, NOT observed unencrypted SIP headers."
    },
    "WEB": {
        "title": "Web (HTTPS) Traffic Simulation",
        "rfc": "RFC 9110",
        "explanation": "Simulates web request/response patterns over TCP/443. Characterized by small client requests followed by multi-packet burst responses.",
        "observable_facts": "Extracted statistical flow features capture asymmetric byte ratios and burstiness.",
        "limitations": "Payload content remains encrypted inside ESP. Classification provides flow-level traffic inference."
    }
}


EXPERIMENT_PRESETS: Dict[str, Dict[str, Any]] = {
    "SECURE_ENTERPRISE": {
        "preset_id": "SECURE_ENTERPRISE",
        "name": "Secure Enterprise VPN",
        "description": "High-security modern enterprise configuration using AES-256-GCM AEAD encryption and Elliptic Curve DH.",
        "config": {
            "name": "Secure Enterprise VPN",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-256-GCM",
            "integrity": "NONE",
            "dh_group": "ECP256",
            "traffic_type": "WEB",
            "destination_port": 443,
            "packet_count": 50,
            "packet_rate": 20,
            "payload_size": 512,
            "duration": 5,
            "execution_mode": "auto"
        }
    },
    "LEGACY_VPN": {
        "preset_id": "LEGACY_VPN",
        "name": "Legacy Enterprise VPN",
        "description": "Legacy site-to-site VPN profile using AES-128-CBC encryption and MODP2048 Diffie-Hellman exchange.",
        "config": {
            "name": "Legacy Enterprise VPN",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-128-CBC",
            "integrity": "SHA256",
            "dh_group": "MODP2048",
            "traffic_type": "ICMP",
            "destination_port": 5001,
            "packet_count": 20,
            "packet_rate": 10,
            "payload_size": 64,
            "duration": 3,
            "execution_mode": "auto"
        }
    },
    "TRANSPORT_MODE": {
        "preset_id": "TRANSPORT_MODE",
        "name": "Host-to-Host Transport Mode",
        "description": "Direct host encapsulation protecting host-to-host communications without tunnel header overhead.",
        "config": {
            "name": "Host-to-Host Transport Mode",
            "ike_version": "IKEv2",
            "mode": "transport",
            "encryption": "AES-128-CBC",
            "integrity": "SHA256",
            "dh_group": "MODP2048",
            "traffic_type": "ICMP",
            "destination_port": 5001,
            "packet_count": 20,
            "packet_rate": 10,
            "payload_size": 64,
            "duration": 3,
            "execution_mode": "auto"
        }
    },
    "HIGH_VOLUME_UDP": {
        "preset_id": "HIGH_VOLUME_UDP",
        "name": "High-Volume UDP Traffic",
        "description": "Sustained high-throughput UDP packet burst to evaluate ML feature extraction under heavy volume.",
        "config": {
            "name": "High-Volume UDP Traffic",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-256-GCM",
            "integrity": "NONE",
            "dh_group": "ECP256",
            "traffic_type": "UDP",
            "destination_port": 5001,
            "packet_count": 150,
            "packet_rate": 50,
            "payload_size": 1024,
            "duration": 5,
            "execution_mode": "auto"
        }
    },
    "VOIP_LIKE": {
        "preset_id": "VOIP_LIKE",
        "name": "VoIP / SIP Audio Simulation",
        "description": "Periodic small UDP packets targeting SIP/RTP port 5060 to test VoIP ML traffic classification.",
        "config": {
            "name": "VoIP / SIP Audio Simulation",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-256-GCM",
            "integrity": "NONE",
            "dh_group": "ECP256",
            "traffic_type": "VOIP-LIKE",
            "destination_port": 5060,
            "packet_count": 60,
            "packet_rate": 20,
            "payload_size": 160,
            "duration": 5,
            "execution_mode": "auto"
        }
    },
    "WEB_LIKE": {
        "preset_id": "WEB_LIKE",
        "name": "Web HTTPS Traffic Simulation",
        "description": "Asymmetric TCP/443 request-response pattern to demonstrate encrypted web traffic inference.",
        "config": {
            "name": "Web HTTPS Traffic Simulation",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-256-GCM",
            "integrity": "NONE",
            "dh_group": "ECP256",
            "traffic_type": "WEB",
            "destination_port": 443,
            "packet_count": 40,
            "packet_rate": 15,
            "payload_size": 800,
            "duration": 4,
            "execution_mode": "auto"
        }
    },
    "CUSTOM_EXPERIMENT": {
        "preset_id": "CUSTOM_EXPERIMENT",
        "name": "Custom Operator Experiment",
        "description": "Fully operator-configured experiment allowing arbitrary parameter customization.",
        "config": {
            "name": "Custom Operator Experiment",
            "ike_version": "IKEv2",
            "mode": "tunnel",
            "encryption": "AES-256-GCM",
            "integrity": "NONE",
            "dh_group": "ECP256",
            "traffic_type": "UDP",
            "destination_port": 5001,
            "packet_count": 50,
            "packet_rate": 20,
            "payload_size": 512,
            "duration": 5,
            "execution_mode": "auto"
        }
    }
}


def validate_experiment_config(config: ExperimentConfig) -> Dict[str, Any]:
    """Validates experiment parameters for security, syntax, and execution feasibility."""
    errors = []
    warnings = []

    # Cipher validation
    if config.encryption == "AES-256-GCM" and config.integrity != "NONE":
        warnings.append("AES-256-GCM is an AEAD cipher; explicit integrity algorithm is redundant and set to AEAD-Implicit.")

    if config.encryption in ("AES-128-CBC", "AES-256-CBC") and config.integrity == "NONE":
        errors.append(f"CBC cipher '{config.encryption}' requires an explicit integrity algorithm (e.g. SHA256 or SHA384).")

    # Mode validation
    if config.mode not in ("tunnel", "transport"):
        errors.append(f"Invalid mode '{config.mode}'. Supported modes: 'tunnel', 'transport'.")

    # Traffic validation
    if config.traffic_type in ("WEB", "FILE-TRANSFER-LIKE") and config.destination_port not in (443, 80, 8080):
        warnings.append(f"Non-standard port {config.destination_port} for {config.traffic_type} simulation.")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "sanitized_config": config.model_dump()
    }
