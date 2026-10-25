"""
detectors/port_scan.py
Flags a source IP as a likely port scanner if it contacts many distinct
destination ports (optionally across many destination IPs) within a short
time window. This is the classic Wireshark pain point: you'd normally build
this by hand with Statistics > Conversations + eyeballing patterns.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict

from models import PacketRecord

DEFAULT_PORT_THRESHOLD = 15   # distinct dst ports from one src to trigger alert
DEFAULT_WINDOW_SECONDS = 10   # sliding window size


@dataclass
class PortScanAlert:
    src_ip: str
    distinct_ports: int
    window_start: float
    window_end: float
    dst_ips: set[str]
    severity: str = "MEDIUM"

    def summary(self) -> str:
        return (f"Possible port scan from {self.src_ip}: "
                f"{self.distinct_ports} distinct ports hit within "
                f"{self.window_end - self.window_start:.1f}s "
                f"across {len(self.dst_ips)} target(s).")


def _is_tcp_syn_candidate(r: PacketRecord) -> bool:
    """
    Checks if a packet record qualifies as a TCP SYN scan probe candidate.
    - Excludes non-TCP protocols (UDP, DNS, ICMP, ARP).
    - When TCP flag metadata is available, strictly requires the SYN flag and
      excludes packets with ACK (eliminating established sessions and server replies).
    - When tcp_flags is None (e.g. synthetic test fixtures), gracefully allows
      records with protocol TCP, HTTP, TLS/HTTPS, or default OTHER.
    """
    if not r.src_ip or r.dst_port is None:
        return False
    if r.protocol in ("UDP", "DNS", "ICMP", "ARP"):
        return False
    if r.tcp_flags is not None:
        flags = r.tcp_flags.upper()
        return ("S" in flags) and ("A" not in flags)
    return r.protocol in ("TCP", "OTHER", "HTTP", "TLS/HTTPS")


def detect_port_scans(
    records: list[PacketRecord],
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[PortScanAlert]:
    tcp_syn_like = [r for r in records if _is_tcp_syn_candidate(r)]
    tcp_syn_like.sort(key=lambda r: r.timestamp)

    alerts: list[PortScanAlert] = []
    seen_src_windows: set[tuple] = set()

    # sliding window per source IP
    by_src: dict[str, list[PacketRecord]] = defaultdict(list)
    for r in tcp_syn_like:
        by_src[r.src_ip].append(r)

    for src_ip, recs in by_src.items():
        recs.sort(key=lambda r: r.timestamp)
        start_idx = 0
        for end_idx in range(len(recs)):
            while recs[end_idx].timestamp - recs[start_idx].timestamp > window_seconds:
                start_idx += 1
            window = recs[start_idx:end_idx + 1]
            ports = {r.dst_port for r in window}
            if len(ports) >= port_threshold:
                key = (src_ip, round(window[0].timestamp))
                if key in seen_src_windows:
                    continue
                seen_src_windows.add(key)
                alerts.append(PortScanAlert(
                    src_ip=src_ip,
                    distinct_ports=len(ports),
                    window_start=window[0].timestamp,
                    window_end=window[-1].timestamp,
                    dst_ips={r.dst_ip for r in window if r.dst_ip},
                    severity="HIGH" if len(ports) >= port_threshold * 2 else "MEDIUM",
                ))

    return alerts
