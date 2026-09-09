"""
Centralized Target Schema, Ground Truth Registry & Inference Policy Module.
Phase 11.3 — AI-Powered IPsec VPN Protocol Analyzer.

Defines:
1. Behavioral Target Schema for Phase 11 (ICMP_DIAGNOSTIC, WEB_INTERACTIVE, BULK_TRANSFER, STREAMING_MEDIA, VOIP_AUDIO, UNKNOWN_UNCLASSIFIED).
2. Encapsulation Types (NATIVE_IPSEC_ESP, IPSEC_NATT_UDP4500, NON_VPN).
3. Dataset Source Types (SYNTHETIC_DEVELOPMENT, REAL_IPSEC_GROUND_TRUTH, EXTERNAL_PUBLIC_BENCHMARK).
4. Real IPsec Ground Truth Registry for data/pcaps/real/ (TEST-001, TEST-002, TEST-003).
5. Centralized UNKNOWN_UNCLASSIFIED Policy & Evidence Mapping Functions.
"""

from typing import Dict, Any, List, Tuple, Optional

# --- Phase 11 Behavioral Target Classes ---
CLASS_ICMP_DIAGNOSTIC = "ICMP_DIAGNOSTIC"
CLASS_WEB_INTERACTIVE = "WEB_INTERACTIVE"
CLASS_BULK_TRANSFER = "BULK_TRANSFER"
CLASS_STREAMING_MEDIA = "STREAMING_MEDIA"
CLASS_VOIP_AUDIO = "VOIP_AUDIO"
CLASS_UNKNOWN_UNCLASSIFIED = "UNKNOWN_UNCLASSIFIED"

BEHAVIORAL_TARGET_CLASSES = [
    CLASS_ICMP_DIAGNOSTIC,
    CLASS_WEB_INTERACTIVE,
    CLASS_BULK_TRANSFER,
    CLASS_STREAMING_MEDIA,
    CLASS_VOIP_AUDIO
]

ALL_TARGET_CLASSES = BEHAVIORAL_TARGET_CLASSES + [CLASS_UNKNOWN_UNCLASSIFIED]

# --- Encapsulation Types ---
ENCAP_NATIVE_IPSEC_ESP = "NATIVE_IPSEC_ESP"
ENCAP_IPSEC_NATT_UDP4500 = "IPSEC_NATT_UDP4500"
ENCAP_NON_VPN = "NON_VPN"

ENCAPSULATION_TYPES = [
    ENCAP_NATIVE_IPSEC_ESP,
    ENCAP_IPSEC_NATT_UDP4500,
    ENCAP_NON_VPN
]

# --- Dataset Source Types ---
SOURCE_SYNTHETIC_DEVELOPMENT = "SYNTHETIC_DEVELOPMENT"
SOURCE_REAL_IPSEC_GROUND_TRUTH = "REAL_IPSEC_GROUND_TRUTH"
SOURCE_EXTERNAL_PUBLIC_BENCHMARK = "EXTERNAL_PUBLIC_BENCHMARK"

DATASET_SOURCE_TYPES = [
    SOURCE_SYNTHETIC_DEVELOPMENT,
    SOURCE_REAL_IPSEC_GROUND_TRUTH,
    SOURCE_EXTERNAL_PUBLIC_BENCHMARK
]

# --- Real IPsec PCAP Ground Truth Registry ---
REAL_IPSEC_GROUND_TRUTH_REGISTRY: Dict[str, Dict[str, Any]] = {
    "TEST-001.pcap": {
        "pcap_file": "TEST-001.pcap",
        "ground_truth_behavioral_class": CLASS_ICMP_DIAGNOSTIC,
        "ground_truth_encapsulation": ENCAP_NATIVE_IPSEC_ESP,
        "traffic_description": "ICMP Echo ping burst over IKEv2/IPsec AES-128-CBC + HMAC-SHA256 ESP tunnel",
        "confidence": 1.0,
        "source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
        "established_by": "strongSwan testbed profile TEST-001"
    },
    "TEST-002.pcap": {
        "pcap_file": "TEST-002.pcap",
        "ground_truth_behavioral_class": CLASS_BULK_TRANSFER,
        "ground_truth_encapsulation": ENCAP_IPSEC_NATT_UDP4500,
        "traffic_description": "Bulk data transfer stream over IKEv2/IPsec AES-256-GCM ESP NAT-T (UDP 4500)",
        "confidence": 1.0,
        "source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
        "established_by": "strongSwan testbed profile TEST-002"
    },
    "TEST-003.pcap": {
        "pcap_file": "TEST-003.pcap",
        "ground_truth_behavioral_class": CLASS_WEB_INTERACTIVE,
        "ground_truth_encapsulation": ENCAP_NATIVE_IPSEC_ESP,
        "traffic_description": "HTTP Web browsing GET request/reply over IKEv2/IPsec ESP NULL encryption transport mode",
        "confidence": 1.0,
        "source": SOURCE_REAL_IPSEC_GROUND_TRUTH,
        "established_by": "strongSwan testbed profile TEST-003"
    }
}


def map_legacy_class_to_behavioral(legacy_class: Optional[str]) -> str:
    """
    Maps legacy 8-class labels to Phase 11 behavioral schema based on evidence.
    Returns UNKNOWN_UNCLASSIFIED for labels without distinct behavioral evidence.
    """
    if not legacy_class:
        return CLASS_UNKNOWN_UNCLASSIFIED

    raw = str(legacy_class).strip()
    norm = raw.upper().replace(" ", "_").replace("-", "_")

    if norm == "ICMP":
        return CLASS_ICMP_DIAGNOSTIC
    elif norm in ("WEB_BROWSING", "WEB", "HTTP", "HTTPS"):
        return CLASS_WEB_INTERACTIVE
    elif norm in ("FILE_TRANSFER", "TRANSFER", "BULK"):
        return CLASS_BULK_TRANSFER
    elif norm in ("STREAMING", "VIDEO", "AUDIO_STREAM"):
        return CLASS_STREAMING_MEDIA
    elif norm in ("VOIP", "VOIP_AUDIO"):
        return CLASS_VOIP_AUDIO
    else:
        # Chat, Email, P2P, Unknown do not map cleanly due to dataset length overlap
        return CLASS_UNKNOWN_UNCLASSIFIED


def map_lab_scenario_to_behavioral(scenario: Optional[str]) -> Tuple[str, bool]:
    """
    Maps Demonstration Lab scenario IDs to Phase 11 behavioral classes.
    Returns (behavioral_class, is_supported).
    Arbitrary UDP, TCP, and DNS-LIKE scenarios return (UNKNOWN_UNCLASSIFIED, False).
    """
    if not scenario:
        return CLASS_UNKNOWN_UNCLASSIFIED, False

    norm = str(scenario).strip().upper().replace(" ", "_").replace("-", "_")

    if norm == "ICMP":
        return CLASS_ICMP_DIAGNOSTIC, True
    elif norm in ("WEB", "WEB_LIKE", "HTTP", "HTTPS"):
        return CLASS_WEB_INTERACTIVE, True
    elif norm in ("FILE_TRANSFER", "FILE_TRANSFER_LIKE", "BULK"):
        return CLASS_BULK_TRANSFER, True
    elif norm in ("VOIP", "VOIP_LIKE"):
        return CLASS_VOIP_AUDIO, True
    elif norm in ("STREAMING", "STREAMING_LIKE"):
        return CLASS_STREAMING_MEDIA, True
    else:
        # Generic UDP, TCP, DNS-LIKE are unsupported for fine-grained application classification
        return CLASS_UNKNOWN_UNCLASSIFIED, False


def apply_unknown_inference_policy(
    predicted_class: str,
    confidence: float,
    packet_count: int,
    confidence_threshold: float = 0.50,
    min_packet_threshold: int = 3
) -> Tuple[str, float, str]:
    """
    Applies centralized UNKNOWN_UNCLASSIFIED policy.
    Triggers UNKNOWN_UNCLASSIFIED when:
    - packet count < min_packet_threshold (3)
    - max probability / confidence < confidence_threshold (0.50)

    Returns: (effective_class, effective_confidence, reason_text)
    """
    if packet_count < min_packet_threshold:
        return (
            CLASS_UNKNOWN_UNCLASSIFIED,
            round(confidence, 4),
            f"Insufficient packet count ({packet_count} packets < {min_packet_threshold} min threshold)"
        )

    if confidence < confidence_threshold:
        return (
            CLASS_UNKNOWN_UNCLASSIFIED,
            round(confidence, 4),
            f"Classification confidence ({confidence * 100:.1f}%) below {confidence_threshold * 100:.0f}% threshold"
        )

    return (
        predicted_class,
        round(confidence, 4),
        "Classification meets confidence and packet volume thresholds"
    )
