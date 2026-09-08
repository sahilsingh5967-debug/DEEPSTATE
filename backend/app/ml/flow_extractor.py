"""
Flow Extractor Module.
Phase 5.2 — AI-Powered IPsec VPN Protocol Analyzer.

Extracts bidirectional 5-tuple flows from raw PCAP files using Scapy.
Organizes packet sequences, timestamps, directionality, and payload statistics.
"""

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from scapy.all import rdpcap, Packet, IP, IPv6, TCP, UDP, ICMP


@dataclass
class FlowPacket:
    timestamp: float
    length: int
    is_forward: bool
    protocol: int
    payload_len: int
    has_esp: bool = False
    has_ike: bool = False


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: List[FlowPacket] = field(default_factory=list)
    traffic_class: str = "UNKNOWN"
    pcap_source: str = ""

    @property
    def duration_seconds(self) -> float:
        if not self.packets:
            return 0.0
        return max(0.0, self.packets[-1].timestamp - self.packets[0].timestamp)

    @property
    def fwd_packets(self) -> List[FlowPacket]:
        return [p for p in self.packets if p.is_forward]

    @property
    def bwd_packets(self) -> List[FlowPacket]:
        return [p for p in self.packets if not p.is_forward]


def normalize_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> Tuple[str, Tuple[str, int], Tuple[str, int], bool]:
    """
    Normalizes 5-tuple so both directions map to the same flow key.
    Returns: (canonical_flow_id, endpoint1, endpoint2, is_forward)
    """
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 <= ep2:
        flow_id = f"{proto}_{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
        return flow_id, ep1, ep2, True
    else:
        flow_id = f"{proto}_{dst_ip}:{dst_port}<->{src_ip}:{src_port}"
        return flow_id, ep2, ep1, False


def extract_flows_from_pcap(pcap_path: str, traffic_class: str = "UNKNOWN") -> List[Flow]:
    """
    Reads a PCAP file and aggregates packets into bidirectional Flow objects.
    Uses ultra-fast binary struct parsing for standard PCAPs, with Scapy fallback.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    import struct
    import socket

    flows_dict: Dict[str, Flow] = {}

    try:
        with open(path, "rb") as f:
            ghdr = f.read(24)
            if len(ghdr) == 24:
                magic, ver_maj, ver_min, tz, sig, snaplen, linktype = struct.unpack("<IHHIIII", ghdr)
                if magic in (0xa1b2c3d4, 0xd4c3b2a1):
                    endian = "<" if magic == 0xa1b2c3d4 else ">"

                    while True:
                        phdr = f.read(16)
                        if len(phdr) < 16:
                            break
                        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
                        pdata = f.read(incl_len)
                        if len(pdata) < incl_len:
                            break

                        ts = ts_sec + (ts_usec / 1e6)
                        if linktype == 1:  # DLT_EN10MB
                            if len(pdata) < 14 + 20:
                                continue
                            eth_type = struct.unpack("!H", pdata[12:14])[0]
                            if eth_type != 0x0800:
                                continue
                            ip_data = pdata[14:]
                        else:
                            ip_data = pdata

                        if len(ip_data) < 20:
                            continue
                        ip_ver = ip_data[0] >> 4
                        if ip_ver != 4:
                            continue

                        ihl = (ip_data[0] & 0x0F) * 4
                        proto = ip_data[9]
                        src_ip = socket.inet_ntoa(ip_data[12:16])
                        dst_ip = socket.inet_ntoa(ip_data[16:20])

                        trans_data = ip_data[ihl:]
                        src_port = 0
                        dst_port = 0
                        payload_len = 0
                        has_esp = proto == 50
                        has_ike = False

                        if proto == 6 and len(trans_data) >= 20:  # TCP
                            src_port, dst_port = struct.unpack("!HH", trans_data[:4])
                            tcp_hdr_len = ((trans_data[12] >> 4) & 0x0F) * 4
                            payload_len = max(0, len(trans_data) - tcp_hdr_len)
                        elif proto == 17 and len(trans_data) >= 8:  # UDP
                            src_port, dst_port, udp_len = struct.unpack("!HHH", trans_data[:6])
                            payload_len = max(0, udp_len - 8)
                            if src_port in (500, 4500) or dst_port in (500, 4500):
                                has_ike = True

                        flow_id, ep1, ep2, is_fwd = normalize_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

                        if flow_id not in flows_dict:
                            flows_dict[flow_id] = Flow(
                                flow_id=flow_id,
                                src_ip=ep1[0],
                                dst_ip=ep2[0],
                                src_port=ep1[1],
                                dst_port=ep2[1],
                                protocol=proto,
                                traffic_class=traffic_class,
                                pcap_source=path.name
                            )

                        flow_pkt = FlowPacket(
                            timestamp=ts,
                            length=len(pdata),
                            is_forward=is_fwd,
                            protocol=proto,
                            payload_len=payload_len,
                            has_esp=has_esp,
                            has_ike=has_ike
                        )
                        flows_dict[flow_id].packets.append(flow_pkt)

                    return list(flows_dict.values())
    except Exception:
        pass

    # Scapy Fallback
    from scapy.utils import PcapReader
    flows_dict.clear()
    try:
        with PcapReader(str(path)) as pcap_reader:
            for pkt in pcap_reader:
                pkt_time = float(getattr(pkt, "time", 0.0))
                pkt_len = len(pkt)
                ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if not ip_layer:
                    continue

                src_ip = getattr(ip_layer, "src", "0.0.0.0")
                dst_ip = getattr(ip_layer, "dst", "0.0.0.0")
                proto = int(getattr(ip_layer, "proto", getattr(ip_layer, "nh", 0)))
                src_port, dst_port, payload_len = 0, 0, 0
                has_esp = proto == 50
                has_ike = False

                tcp_layer = pkt.getlayer(TCP)
                udp_layer = pkt.getlayer(UDP)

                if tcp_layer:
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    payload_len = len(tcp_layer.payload) if tcp_layer.payload else 0
                elif udp_layer:
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                    payload_len = len(udp_layer.payload) if udp_layer.payload else 0
                    if src_port in (500, 4500) or dst_port in (500, 4500):
                        has_ike = True

                flow_id, ep1, ep2, is_fwd = normalize_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
                if flow_id not in flows_dict:
                    flows_dict[flow_id] = Flow(
                        flow_id=flow_id,
                        src_ip=ep1[0],
                        dst_ip=ep2[0],
                        src_port=ep1[1],
                        dst_port=ep2[1],
                        protocol=proto,
                        traffic_class=traffic_class,
                        pcap_source=path.name
                    )

                flow_pkt = FlowPacket(
                    timestamp=pkt_time,
                    length=pkt_len,
                    is_forward=is_fwd,
                    protocol=proto,
                    payload_len=payload_len,
                    has_esp=has_esp,
                    has_ike=has_ike
                )
                flows_dict[flow_id].packets.append(flow_pkt)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return []

    return list(flows_dict.values())


if __name__ == "__main__":
    import sys
    test_pcap = "data/pcaps/real/TEST-001.pcap"
    if Path(test_pcap).exists():
        flows = extract_flows_from_pcap(test_pcap, traffic_class="ICMP")
        print(f"Extracted {len(flows)} flows from {test_pcap}:")
        for f in flows:
            print(f" Flow ID: {f.flow_id} | Packets: {len(f.packets)} | Duration: {f.duration_seconds:.4f}s")
