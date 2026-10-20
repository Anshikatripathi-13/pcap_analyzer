"""
samples/generate_sample_pcap.py
Generates a realistic synthetic PCAP capture file containing both benign traffic
and security artifacts (port scanning, C2 beaconing, DNS tunneling, and plaintext credentials).
Enables evaluators and analysts to test the PCAP Forensic Analyzer without needing
external capture files.

Usage:
    python samples/generate_sample_pcap.py [output_file.pcap]
"""

from __future__ import annotations

import math
import random
import string
import sys
import time
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_synthetic_pcap(output_path: str = "samples/synthetic_investigation.pcap") -> str:
    packets = []
    base_time = 1710000000.0  # Stable baseline timestamp
    client_ip = "192.168.1.105"
    gateway_ip = "192.168.1.1"
    server_ip = "10.0.0.50"
    attacker_ip = "198.51.100.42"
    c2_ip = "203.0.113.88"
    dns_server = "8.8.8.8"

    # 1. Benign Web & DNS Traffic (Normal Baseline)
    for i in range(25):
        t = base_time + (i * 0.4)
        # DNS Query
        dns_pkt = (
            Ether()
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"api{i % 3}.company.internal"))
        )
        dns_pkt.time = t
        packets.append(dns_pkt)

        # HTTP/TLS Traffic
        tcp_pkt = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=49152 + i, dport=443, flags="PA")
            / Raw(load=b"\x16\x03\x01\x00\xa0" + b"TLS_DUMMY_HANDSHAKE_DATA" * 4)
        )
        tcp_pkt.time = t + 0.05
        packets.append(tcp_pkt)

    # 2. Port Scan Attack (Attacker scanning server on 15+ distinct ports)
    scan_start = base_time + 15.0
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
    for idx, port in enumerate(scan_ports):
        t = scan_start + (idx * 0.08)
        syn_pkt = (
            Ether()
            / IP(src=attacker_ip, dst=server_ip)
            / TCP(sport=40000 + idx, dport=port, flags="S")
        )
        syn_pkt.time = t
        packets.append(syn_pkt)

    # 3. C2 Beaconing Activity (Periodic traffic at 5.0s fixed intervals)
    beacon_start = base_time + 2.0
    for b in range(12):
        t = beacon_start + (b * 5.0)  # Strict 5.0-second interval
        beacon_pkt = (
            Ether()
            / IP(src=client_ip, dst=c2_ip)
            / TCP(sport=51000 + b, dport=8443, flags="PA")
            / Raw(load=b"HEARTBEAT_CHECKIN_ID=" + str(b).encode())
        )
        beacon_pkt.time = t
        packets.append(beacon_pkt)

    # 4. DNS Tunneling Exfiltration (High entropy subdomains)
    dns_start = base_time + 8.0
    root_domain = "tunnel-exfil.biz"
    for d in range(22):
        t = dns_start + (d * 0.25)
        # Generate high-entropy hex/base64 encoded label
        random_payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=38))
        query_name = f"{random_payload}.{root_domain}"
        tunnel_pkt = (
            Ether()
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=55000 + d, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query_name))
        )
        tunnel_pkt.time = t
        packets.append(tunnel_pkt)

    # 5. Plaintext Credential Exposure (HTTP POST and FTP Auth)
    cred_time = base_time + 20.0
    http_payload = (
        b"POST /api/v1/login HTTP/1.1\r\n"
        b"Host: auth.internal.corp\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 48\r\n\r\n"
        b"username=admin&password=SuperSecretPassword2026!"
    )
    http_cred_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=49990, dport=80, flags="PA")
        / Raw(load=http_payload)
    )
    http_cred_pkt.time = cred_time
    packets.append(http_cred_pkt)

    # FTP Plaintext Auth
    ftp_user_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=49991, dport=21, flags="PA")
        / Raw(load=b"USER backup_service\r\n")
    )
    ftp_user_pkt.time = cred_time + 1.0
    packets.append(ftp_user_pkt)

    ftp_pass_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=49991, dport=21, flags="PA")
        / Raw(load=b"PASS ServiceP@ss1234!\r\n")
    )
    ftp_pass_pkt.time = cred_time + 1.5
    packets.append(ftp_pass_pkt)

    # Sort packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    # Ensure parent directory exists
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    wrpcap(str(out_file), packets)
    print(f"Synthetic PCAP successfully generated: {out_file.resolve()}")
    print(f"Total Packets: {len(packets)}")
    print(f"Time Span: {packets[-1].time - packets[0].time:.2f} seconds")
    print("Scenarios included:")
    print("  - Benign DNS/HTTP/TLS web traffic")
    print(f"  - SYN Port Scan from {attacker_ip} against {server_ip} (16 ports)")
    print(f"  - Periodic C2 Beaconing from {client_ip} to {c2_ip} (5.0s interval)")
    print(f"  - High-Entropy DNS Tunneling ({root_domain})")
    print("  - Plaintext Credentials (HTTP POST form & FTP auth)")

    return str(out_file)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/synthetic_investigation.pcap"
    generate_synthetic_pcap(target)
