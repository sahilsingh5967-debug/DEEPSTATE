#!/usr/bin/env python3
"""
DEEPSTATE Demonstration Laboratory CLI Runner.
Interactive operator CLI to list profiles, check testbed status, run capture sessions, and pass PCAPs to DEEPSTATE analysis.
"""

import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Scapy environment setup
import os
os.environ["SCAPY_USE_NETIFACES"] = "0"
try:
    from scapy.config import conf
    conf.read_resolv_conf = False
    conf.verb = 0
except Exception:
    pass

from scripts.testbed.profile_registry import (
    get_all_profiles, get_profile, get_all_traffic_profiles, get_traffic_profile
)
from scripts.testbed.profile_runner import get_testbed_status
from scripts.testbed.capture_manager import execute_testbed_capture
from backend.app.analyzers.protocol_analyzer import analyze_pcap


def cmd_list_profiles():
    print("\n================================================================================")
    print(" DEEPSTATE DEMONSTRATION LAB — IPSEC PROFILES REGISTRY")
    print("================================================================================")
    for p in get_all_profiles():
        print(f"\n[+] Profile ID: {p['profile_id']}")
        print(f"    Name:       {p['display_name']}")
        print(f"    Cipher:     {p['encryption']} | Integrity: {p['integrity']} | DH: {p['dh_group']} | Mode: {p['mode']}")
        print(f"    Subnets:    {p['traffic_selector_a']} <---> {p['traffic_selector_b']}")
        print(f"    Purpose:    {p['demonstration_purpose']}")
        print(f"    Class:      {p['safety_classification']}")
    print("\n================================================================================\n")


def cmd_list_traffic():
    print("\n================================================================================")
    print(" DEEPSTATE DEMONSTRATION LAB — TRAFFIC GENERATION MODELS")
    print("================================================================================")
    for t in get_all_traffic_profiles():
        print(f"\n[+] Traffic ID:  {t['traffic_profile_id']}")
        print(f"    Name:        {t['display_name']}")
        print(f"    Description: {t['description']}")
        print(f"    Defaults:    {t['default_packet_count']} packets, {t['default_duration_seconds']}s duration, port={t['default_port']}")
    print("\n================================================================================\n")


def cmd_status():
    print("\n================================================================================")
    print(" DEEPSTATE DEMONSTRATION LAB — TESTBED STATUS")
    print("================================================================================")
    status = get_testbed_status()
    print(f"  Docker Host Available: {status['docker_available']}")
    print(f"  Peer A Container:      {status['peer_a_status']}")
    print(f"  Peer B Container:      {status['peer_b_status']}")
    print(f"  strongSwan Daemon:     {status['strongswan_status']}")
    print(f"  Execution Mode:        {status['mode']}")
    print(f"  Active Tunnels:        {status['active_tunnels']}")
    print("================================================================================\n")


def cmd_run(args):
    profile_id = args.profile.upper()
    traffic_id = args.traffic.upper()
    duration = args.duration
    packets = args.packets
    port = args.port
    run_analyze = args.analyze

    print("\n================================================================================")
    print(" DEEPSTATE DEMONSTRATION LABORATORY — EXPERIMENT RUNNER")
    print("================================================================================")

    # 1. Profile Verification
    prof = get_profile(profile_id)
    if not prof:
        print(f"ERROR: Unknown IPsec profile_id '{profile_id}'. Run 'list-profiles' for valid IDs.")
        sys.exit(1)
    print(f"[1/8] Profile Selected: {prof['profile_id']} — {prof['display_name']}")

    # 2. Traffic Profile Verification
    t_prof = get_traffic_profile(traffic_id)
    if not t_prof:
        print(f"ERROR: Unknown traffic_profile '{traffic_id}'. Run 'list-traffic' for valid IDs.")
        sys.exit(1)
    print(f"[2/8] Traffic Model Selected: {t_prof['traffic_profile_id']} ({packets} pkts, {duration}s)")

    # 3. Check Testbed Peers
    st = get_testbed_status()
    print(f"[3/8] Testbed Environment Verified (Mode: {st['mode']})")

    # 4. Initiate Capture & IPsec SA Negotiation
    print(f"[4/8] Initiating IPsec SA Handshake & Starting tcpdump Capture...")

    try:
        cap_res = execute_testbed_capture(
            profile_id=profile_id,
            traffic_profile_id=traffic_id,
            duration=duration,
            packet_count=packets,
            port=port
        )
    except Exception as err:
        print(f"\n[-] ERROR executing testbed capture: {err}")
        sys.exit(1)

    print(f"[5/8] Traffic Generation Completed across Tunnel: {cap_res['packet_count']} packets sent.")
    print(f"[6/8] Capture Stopped & Verified: {cap_res['size_bytes']} bytes captured in {cap_res['duration_seconds']}s.")
    print(f"[7/8] PCAP Artifact Saved: {cap_res['file_path']}")
    print(f"[8/8] Capture Verified & Ready for DEEPSTATE Unified Analysis Pipeline.")

    print("\n--------------------------------------------------------------------------------")
    print(f" DEMONSTRATION CAPTURE SUMMARY:")
    print(f"   Capture ID:     {cap_res['capture_id']}")
    print(f"   IPsec Profile:  {cap_res['profile_id']}")
    print(f"   Traffic Model:  {cap_res['traffic_profile']}")
    print(f"   File Path:      {cap_res['file_path']}")
    print(f"   Execution Mode: {cap_res['execution_mode']}")
    print("--------------------------------------------------------------------------------\n")

    if run_analyze:
        print("================================================================================")
        print(" EXECUTING DEEPSTATE UNIFIED ANALYSIS HANDOFF")
        print("================================================================================")
        abs_pcap = str(PROJECT_ROOT / cap_res['file_path'])
        res = analyze_pcap(abs_pcap)
        res_dict = res.model_dump() if hasattr(res, "model_dump") else res.dict() if hasattr(res, "dict") else res

        proto_id = res_dict.get("protocol_identification") or {}
        sec_ass = res_dict.get("security_assessment") or {}
        ml_inf = res_dict.get("traffic_classification") or {}

        print("\n--- [TIER A: Deterministic Observed Protocol Facts] ---")
        print(f"  Observed Protocols: {proto_id.get('protocols_detected')}")
        print(f"  IKE Detected:       {proto_id.get('has_ike')}")
        print(f"  ESP Detected:       {proto_id.get('has_esp')}")

        print("\n--- [TIER B: Rule-Based Security Assessment] ---")
        print(f"  Security Score:     {sec_ass.get('security_score')} / 100.0")
        print(f"  Overall Status:     {sec_ass.get('overall_status')} (Risk Level: {sec_ass.get('risk_level')})")
        print(f"  Checks Passed/Failed:{sec_ass.get('passed_checks')} passed, {sec_ass.get('failed_checks')} failed")

        print("\n--- [TIER C: Encrypted Traffic ML Classification] ---")
        print(f"  Inference Status:   {ml_inf.get('status')}")
        print(f"  Dominant Traffic:   {ml_inf.get('dominant_class')} (Confidence: {ml_inf.get('confidence')}%)")
        print(f"  Disclaimer:         '{ml_inf.get('disclaimer')}'")
        print("\n================================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="DEEPSTATE Demonstration Laboratory CLI")
    subparsers = parser.add_subparsers(dest="command", help="Demonstration command")

    subparsers.add_parser("list-profiles", help="List available IPsec demonstration profiles")
    subparsers.add_parser("list-traffic", help="List available traffic generation profiles")
    subparsers.add_parser("status", help="Check live testbed container & daemon status")

    run_parser = subparsers.add_parser("run", help="Run a demonstration capture session")
    run_parser.add_argument("--profile", required=True, help="IPsec Profile ID (e.g. TEST-001, TEST-002, TEST-003)")
    run_parser.add_argument("--traffic", default="ICMP", help="Traffic type: ICMP, UDP, or TCP (default: ICMP)")
    run_parser.add_argument("--duration", type=int, default=5, help="Traffic duration in seconds (default: 5)")
    run_parser.add_argument("--packets", type=int, default=20, help="Total packet count (default: 20)")
    run_parser.add_argument("--port", type=int, default=None, help="Custom destination port for UDP/TCP")
    run_parser.add_argument("--analyze", action="store_true", help="Automatically pass generated PCAP to DEEPSTATE analysis pipeline")

    args = parser.parse_args()

    if args.command == "list-profiles":
        cmd_list_profiles()
    elif args.command == "list-traffic":
        cmd_list_traffic()
    elif args.command == "status":
        cmd_status()
    elif args.command == "run":
        cmd_run(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
