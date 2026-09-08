from typing import Dict, List
from pydantic import BaseModel, Field


class AssessmentPolicy(BaseModel):
    """
    Centralized Security Assessment Policy.
    Defines approved, acceptable, legacy, and weak cryptographic algorithms,
    IKE protocol expectations, DH key exchange parameters, and severity penalty weights.
    """
    policy_name: str = "SIH IPsec VPN Baseline Security Policy 2026"
    version: str = "1.0.0"

    # Protocol Versions
    minimum_ike_version: str = "IKEv2"

    # Cryptographic Algorithms
    strong_encryption: List[str] = Field(
        default_factory=lambda: [
            "AES-GCM-128", "AES-GCM-192", "AES-GCM-256",
            "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
            "CHACHA20-POLY1305"
        ]
    )
    acceptable_encryption: List[str] = Field(
        default_factory=lambda: [
            "AES-CBC-128", "AES-CBC-192", "AES-CBC-256",
            "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "AES-128"
        ]
    )
    weak_encryption: List[str] = Field(
        default_factory=lambda: [
            "3DES-CBC", "DES-CBC", "RC4", "NULL", "3DES", "DES"
        ]
    )

    strong_integrity: List[str] = Field(
        default_factory=lambda: [
            "HMAC-SHA2-256-128", "HMAC-SHA2-384-192", "HMAC-SHA2-512-256",
            "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
        ]
    )
    weak_integrity: List[str] = Field(
        default_factory=lambda: [
            "HMAC-MD5-96", "HMAC-SHA1-96", "HMAC-MD5", "HMAC-SHA1", "NULL"
        ]
    )

    strong_prf: List[str] = Field(
        default_factory=lambda: [
            "PRF-HMAC-SHA2-256", "PRF-HMAC-SHA2-384", "PRF-HMAC-SHA2-512",
            "PRF-HMAC-SHA256", "PRF-HMAC-SHA384", "PRF-HMAC-SHA512"
        ]
    )
    weak_prf: List[str] = Field(
        default_factory=lambda: [
            "PRF-HMAC-MD5", "PRF-HMAC-SHA1"
        ]
    )

    # Key Exchange / DH Groups
    strong_dh_groups: List[str] = Field(
        default_factory=lambda: [
            "group 14", "group 15", "group 16", "group 17", "group 18",
            "group 19", "group 20", "group 21", "2048", "3072", "4096",
            "modp2048", "modp3072", "modp4096", "ecp256", "ecp384", "ecp521"
        ]
    )
    weak_dh_groups: List[str] = Field(
        default_factory=lambda: [
            "group 1 ", "group 1 (", "group 2", "group 5", "768", "1024", "1536",
            "modp768", "modp1024", "modp1536"
        ]
    )

    pfs_required: bool = True

    # Severity Penalty Weights for Score Calculation
    severity_penalties: Dict[str, float] = Field(
        default_factory=lambda: {
            "CRITICAL": 25.0,
            "HIGH": 15.0,
            "MEDIUM": 10.0,
            "LOW": 5.0,
            "INFO": 0.0,
        }
    )


default_policy = AssessmentPolicy()
