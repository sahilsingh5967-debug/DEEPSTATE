from typing import Any, Dict, List, Tuple
from scapy.all import Packet, UDP
from scapy.layers.isakmp import ISAKMP
from backend.app.models.schemas import IKEAnalysisDetail


# IKE Exchange Type mappings
IKE_EXCHANGE_TYPES = {
    2: "Identity Protection (Main Mode / IKEv1)",
    4: "Aggressive Mode (IKEv1)",
    5: "Quick Mode (IKEv1)",
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

# Transform Mappings (RFC 7296 / IANA IKEv2 Parameters)
ENCRYPTION_TRANSFORMS = {
    2: "3DES-CBC",
    12: "AES-CBC-128",
    13: "AES-CBC-192",
    14: "AES-CBC-256",
    18: "AES-GCM-128",
    19: "AES-GCM-192",
    20: "AES-GCM-256",
}

INTEGRITY_TRANSFORMS = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

PRF_TRANSFORMS = {
    1: "PRF-HMAC-MD5",
    2: "PRF-HMAC-SHA1",
    5: "PRF-HMAC-SHA2-256",
    6: "PRF-HMAC-SHA2-384",
    7: "PRF-HMAC-SHA2-512",
}

DH_GROUP_TRANSFORMS = {
    1: "Group 1 (768-bit)",
    2: "Group 2 (1024-bit)",
    5: "Group 5 (1536-bit)",
    14: "Group 14 (2048-bit)",
    15: "Group 15 (3072-bit)",
    16: "Group 16 (4096-bit)",
    19: "Group 19 (ECP-256)",
    20: "Group 20 (ECP-384)",
    21: "Group 21 (ECP-521)",
}


def analyze_ike(packets: List[Packet]) -> Tuple[IKEAnalysisDetail, List[str]]:
    """
    Parses observable IKE protocol fields from UDP 500/4500 packets.
    Extracts IKE version, exchange types, Initiator/Responder SPIs, message IDs,
    and proposal transforms (encryption, integrity, PRF, DH groups) when present.

    Returns:
        Tuple of (IKEAnalysisDetail, warnings_list)
    """
    warnings: List[str] = []
    ike_packets = []

    for pkt in packets:
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if sport in (500, 4500) or dport in (500, 4500):
                ike_packets.append(pkt)

    if not ike_packets:
        return IKEAnalysisDetail(detected=False), warnings

    versions = set()
    exchange_types = set()
    initiator_spis = set()
    responder_spis = set()
    message_ids = set()

    enc_algos = set()
    integ_algos = set()
    prf_algos = set()
    dh_groups = set()
    proposals_extracted = []

    for idx, pkt in enumerate(ike_packets):
        try:
            if pkt.haslayer(ISAKMP):
                isakmp = pkt[ISAKMP]

                # 1. Initiator and Responder SPIs
                if hasattr(isakmp, "init_cookie") and isakmp.init_cookie:
                    initiator_spis.add(f"0x{isakmp.init_cookie.hex()}")
                if hasattr(isakmp, "resp_cookie") and isakmp.resp_cookie:
                    resp_hex = isakmp.resp_cookie.hex()
                    if resp_hex != "0" * len(resp_hex):
                        responder_spis.add(f"0x{resp_hex}")

                # 2. Version determination
                # ISAKMP version byte: high nibble = major, low nibble = minor (0x20 = 2.0)
                ver_val = getattr(isakmp, "version", None)
                if ver_val is not None:
                    major = (ver_val >> 4) & 0x0F
                    if major == 2:
                        versions.add("IKEv2")
                    elif major == 1:
                        versions.add("IKEv1")

                # 3. Exchange type
                exch_val = getattr(isakmp, "exch_type", getattr(isakmp, "exch", None))
                if exch_val is not None:
                    exch_name = IKE_EXCHANGE_TYPES.get(exch_val, f"Unknown Exchange ({exch_val})")
                    exchange_types.add(exch_name)

                # 4. Message ID
                msg_id = getattr(isakmp, "id", None)
                if msg_id is not None:
                    message_ids.add(msg_id)

                # 5. Extract SA Proposal Payloads if unencrypted payload layers exist
                payload = isakmp.payload
                while payload and not isinstance(payload, bytes):
                    # Check for proposal or transform layer bytes
                    p_bytes = bytes(payload)
                    # Inspect transform types if proposal bytes exist
                    if len(p_bytes) >= 8:
                        # Attempt heuristic scanning of transform attribute tuples
                        # Transform format: Type (2 bytes), Transform ID (2 bytes)
                        for offset in range(0, len(p_bytes) - 4, 4):
                            t_type = int.from_bytes(p_bytes[offset:offset+2], 'big')
                            t_id = int.from_bytes(p_bytes[offset+2:offset+4], 'big')

                            if t_type == 1 and t_id in ENCRYPTION_TRANSFORMS:
                                enc_algos.add(ENCRYPTION_TRANSFORMS[t_id])
                            elif t_type == 2 and t_id in PRF_TRANSFORMS:
                                prf_algos.add(PRF_TRANSFORMS[t_id])
                            elif t_type == 3 and t_id in INTEGRITY_TRANSFORMS:
                                integ_algos.add(INTEGRITY_TRANSFORMS[t_id])
                            elif t_type == 4 and t_id in DH_GROUP_TRANSFORMS:
                                dh_groups.add(DH_GROUP_TRANSFORMS[t_id])

                    payload = getattr(payload, "payload", None)

        except Exception as e:
            warnings.append(f"IKE packet parsing error: {str(e)}")

    observed_version = sorted(list(versions))[0] if versions else None
    init_spi_str = sorted(list(initiator_spis))[0] if initiator_spis else None
    resp_spi_str = sorted(list(responder_spis))[0] if responder_spis else None

    if not enc_algos:
        warnings.append("No explicit unencrypted SA proposal transforms observed in IKE packets (payloads encrypted or synthetic fixture).")

    ike_detail = IKEAnalysisDetail(
        detected=True,
        version=observed_version,
        exchange_types=sorted(list(exchange_types)),
        initiator_spi=init_spi_str,
        responder_spi=resp_spi_str,
        message_ids=sorted(list(message_ids)),
        proposals=proposals_extracted,
        dh_groups=sorted(list(dh_groups)),
        encryption_algorithms=sorted(list(enc_algos)),
        integrity_algorithms=sorted(list(integ_algos)),
        prf_algorithms=sorted(list(prf_algos)),
    )

    return ike_detail, warnings
