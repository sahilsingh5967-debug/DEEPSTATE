"""
IPsec & Traffic Profile Registry for DEEPSTATE Demonstration Lab.
Defines available IPsec configuration profiles and traffic generation models.
"""

from typing import Dict, Any, List, Optional


IPSEC_PROFILES: Dict[str, Dict[str, Any]] = {
    "TEST-001": {
        "profile_id": "TEST-001",
        "display_name": "Legacy Enterprise Tunnel (AES-128-CBC / SHA256)",
        "description": "Standard IKEv2 site-to-site IPsec tunnel utilizing AES-128-CBC encryption and SHA-256 integrity.",
        "ike_version": 2,
        "encryption": "AES-128-CBC",
        "integrity": "SHA256",
        "dh_group": "MODP2048",
        "mode": "tunnel",
        "peer_a": "192.168.100.2",
        "peer_b": "192.168.100.3",
        "traffic_selector_a": "10.1.0.0/24",
        "traffic_selector_b": "10.2.0.0/24",
        "source_ip": "10.1.0.1",
        "destination_ip": "10.2.0.1",
        "child_sa_name": "test-001-sa",
        "demonstration_purpose": "Inspect and evaluate legacy CBC cipher mode and MODP2048 DH key exchange.",
        "safety_classification": "SECURE_STANDARD"
    },
    "TEST-002": {
        "profile_id": "TEST-002",
        "display_name": "Modern High-Security Tunnel (AES-256-GCM / ECP256)",
        "description": "High-security IKEv2 tunnel employing AEAD AES-256-GCM encryption and ECP256 Elliptic Curve DH.",
        "ike_version": 2,
        "encryption": "AES-256-GCM",
        "integrity": "GCM-Implicit",
        "dh_group": "ECP256",
        "mode": "tunnel",
        "peer_a": "192.168.100.2",
        "peer_b": "192.168.100.3",
        "traffic_selector_a": "10.1.0.0/24",
        "traffic_selector_b": "10.2.0.0/24",
        "source_ip": "10.1.0.1",
        "destination_ip": "10.2.0.1",
        "child_sa_name": "test-002-sa",
        "demonstration_purpose": "Demonstrate modern AEAD GCM cipher performance and Elliptic Curve key exchange.",
        "safety_classification": "HIGH_SECURITY"
    },
    "TEST-003": {
        "profile_id": "TEST-003",
        "display_name": "Transport Mode Host-to-Host (AES-128-CBC)",
        "description": "Direct host-to-host ESP transport mode encapsulation protecting communications between peer endpoints.",
        "ike_version": 2,
        "encryption": "AES-128-CBC",
        "integrity": "SHA256",
        "dh_group": "MODP2048",
        "mode": "transport",
        "peer_a": "192.168.100.2",
        "peer_b": "192.168.100.3",
        "traffic_selector_a": "192.168.100.2/32",
        "traffic_selector_b": "192.168.100.3/32",
        "source_ip": "192.168.100.2",
        "destination_ip": "192.168.100.3",
        "child_sa_name": "test-003-sa",
        "demonstration_purpose": "Evaluate IPsec Transport mode packet structures without tunnel IP header overhead.",
        "safety_classification": "SECURE_STANDARD"
    }
}


TRAFFIC_PROFILES: Dict[str, Dict[str, Any]] = {
    "ICMP": {
        "traffic_profile_id": "ICMP",
        "display_name": "ICMP Echo Request / Reply",
        "description": "Generates ICMP ping packet bursts across the established IPsec SA.",
        "default_packet_count": 5,
        "default_duration_seconds": 3,
        "default_port": None,
        "supports_custom_port": False
    },
    "UDP": {
        "traffic_profile_id": "UDP",
        "display_name": "UDP Datagram Burst",
        "description": "Generates synthetic UDP datagram traffic targeting a designated destination port.",
        "default_packet_count": 20,
        "default_duration_seconds": 5,
        "default_port": 5001,
        "supports_custom_port": True
    },
    "TCP": {
        "traffic_profile_id": "TCP",
        "display_name": "TCP Stream Connection",
        "description": "Establishes TCP connections or stream data packets across the established IPsec SA.",
        "default_packet_count": 15,
        "default_duration_seconds": 5,
        "default_port": 8080,
        "supports_custom_port": True
    }
}


def get_all_profiles() -> List[Dict[str, Any]]:
    """Returns a list of all registered IPsec profiles."""
    return list(IPSEC_PROFILES.values())


def get_profile(profile_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single IPsec profile by ID."""
    return IPSEC_PROFILES.get(profile_id)


def get_all_traffic_profiles() -> List[Dict[str, Any]]:
    """Returns a list of all registered traffic profiles."""
    return list(TRAFFIC_PROFILES.values())


def get_traffic_profile(traffic_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single traffic profile by ID."""
    return TRAFFIC_PROFILES.get(traffic_id.upper())
