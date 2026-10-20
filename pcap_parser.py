"""
pcap_parser.py
Parses a .pcap/.pcapng file into a clean, structured list of packet records
that the rest of the tool (detectors, IOC extractor, report generator) can
work with, instead of every module re-parsing raw scapy objects.
"""

from __future__ import annotations
from typing import Optional
import re

from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest  # requires scapy's http layer

from models import PacketRecord

try:
    from scapy.packet import Raw
except ImportError:  # pragma: no cover
    Raw = None


def format_hex_ascii(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Renders raw packet payload bytes into a standard Wireshark / hexdump format.
    Example:
        0000  45 00 00 3c 1a 2b 40 00  40 06 b2 c5 c0 a8 01 02  |E..<.+@.@.......|
    """
    if not data:
        return ""
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        hex_parts = [f"{b:02x}" for b in chunk]
        if bytes_per_line == 16:
            hex_left = " ".join(hex_parts[:8])
            hex_right = " ".join(hex_parts[8:])
            hex_str = f"{hex_left:<23}  {hex_right:<23}"
        else:
            hex_str = " ".join(hex_parts)
        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_str}  |{ascii_str}|")
    return "\n".join(lines)


def _proto_name(pkt: Packet) -> str:
    """
    Identifies the primary application or transport layer protocol for a packet.
    Checks upper layer protocols first (DNS, HTTP, TLS) before falling back to transport
    and network layer protocols (TCP, UDP, ICMP, ARP, IPv6, IP).
    """
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(HTTPRequest):
        return "HTTP"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.dport in (443, 8443) or tcp.sport in (443, 8443):
            return "TLS/HTTPS"
        if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
            return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    return "OTHER"


def parse_pcap(path: str, max_packets: Optional[int] = None) -> list[PacketRecord]:
    """
    Reads a pcap file and returns a list of PacketRecord objects.
    max_packets caps how many packets are parsed (useful for huge captures
    during development/testing).
    """
    packets = rdpcap(path)
    records: list[PacketRecord] = []

    for i, pkt in enumerate(packets):
        if max_packets and i >= max_packets:
            break

        rec = PacketRecord(
            index=i,
            timestamp=float(pkt.time),
            length=len(pkt),
            protocol=_proto_name(pkt),
        )

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            rec.src_ip = ip_layer.src
            rec.dst_ip = ip_layer.dst
        elif pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            rec.src_ip = ip6_layer.src
            rec.dst_ip = ip6_layer.dst
        elif pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            rec.src_ip = arp_layer.psrc
            rec.dst_ip = arp_layer.pdst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.tcp_flags = str(tcp.flags)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                rec.dns_query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                pass

        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            rec.http_host = http.Host.decode(errors="ignore") if http.Host else None
            rec.http_path = http.Path.decode(errors="ignore") if http.Path else None

        if Raw is not None and pkt.haslayer(Raw):
            try:
                raw_bytes = bytes(pkt[Raw].load)
                rec.raw_payload = raw_bytes[:256]
                # keep a small printable snippet with line boundaries preserved (\r, \n, \t)
                snippet = re.sub(rb"[^\x20-\x7e\r\n\t]", b".", raw_bytes[:256])
                rec.payload_snippet = snippet.decode(errors="ignore")
            except Exception:
                pass

        records.append(rec)

    return records
