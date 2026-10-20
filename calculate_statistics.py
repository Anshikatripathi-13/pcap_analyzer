"""
calculate_statistics.py
Calculates summary statistics, protocol distributions, conversations,
and top talkers from parsed PacketRecord objects. Contains no UI code and
is reused across the dashboard, reports, and CLI/API interfaces.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from models import PacketRecord


@dataclass
class CaptureStatistics:
    total_packets: int
    capture_duration: float
    total_bytes: int
    unique_ips: int
    sessions: int
    protocol_count: int


def calculate_statistics(records: list[PacketRecord]) -> CaptureStatistics:
    """Calculates high-level capture metrics across a list of PacketRecord objects."""
    if not records:
        return CaptureStatistics(
            total_packets=0,
            capture_duration=0.0,
            total_bytes=0,
            unique_ips=0,
            sessions=0,
            protocol_count=0,
        )

    total_packets = len(records)
    start_time = min(r.timestamp for r in records)
    end_time = max(r.timestamp for r in records)
    capture_duration = max(0.0, end_time - start_time)

    total_bytes = sum(r.length for r in records)

    unique_ips = {
        ip
        for r in records
        for ip in (r.src_ip, r.dst_ip)
        if ip
    }

    sessions = {
        tuple(sorted([r.src_ip, r.dst_ip]))
        for r in records
        if r.src_ip and r.dst_ip
    }

    protocols = {
        r.protocol
        for r in records
        if r.protocol
    }

    return CaptureStatistics(
        total_packets=total_packets,
        capture_duration=capture_duration,
        total_bytes=total_bytes,
        unique_ips=len(unique_ips),
        sessions=len(sessions),
        protocol_count=len(protocols),
    )


def filter_records_by_time(
    records: list[PacketRecord],
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
) -> list[PacketRecord]:
    """
    Filters packet records by an inclusive timestamp boundary [start_ts, end_ts].
    Preserves original timestamps and chronological ordering.
    """
    if not records:
        return []
    filtered = records
    if start_ts is not None:
        filtered = [r for r in filtered if r.timestamp >= start_ts]
    if end_ts is not None:
        filtered = [r for r in filtered if r.timestamp <= end_ts]
    return filtered


def calculate_protocol_distribution(records: list[PacketRecord]) -> list[dict]:
    """
    Returns exact counts, percentages, and byte volume for every protocol
    detected in the active records list without hiding categories.
    """
    if not records:
        return []

    total_pkts = len(records)
    total_bytes = sum(r.length for r in records)
    by_proto: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "bytes": 0})

    for r in records:
        proto = r.protocol or "OTHER"
        by_proto[proto]["count"] += 1
        by_proto[proto]["bytes"] += r.length

    result = []
    for proto, data in sorted(by_proto.items(), key=lambda x: x[1]["count"], reverse=True):
        pkt_pct = (data["count"] / total_pkts * 100.0) if total_pkts else 0.0
        byte_pct = (data["bytes"] / total_bytes * 100.0) if total_bytes else 0.0
        result.append({
            "Protocol": proto,
            "Packets": data["count"],
            "Packet %": round(pkt_pct, 2),
            "Bytes": data["bytes"],
            "Byte %": round(byte_pct, 2),
        })

    return result


def calculate_top_conversations(records: list[PacketRecord], top_n: int = 10) -> list[dict]:
    """
    Calculates bi-directional communication conversations between host pairs.
    """
    if not records:
        return []

    convos: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "protocols": set()}
    )

    for r in records:
        if not r.src_ip or not r.dst_ip:
            continue
        key = tuple(sorted([r.src_ip, r.dst_ip]))
        convos[key]["packets"] += 1
        convos[key]["bytes"] += r.length
        if r.protocol:
            convos[key]["protocols"].add(r.protocol)

    result = []
    for (host_a, host_b), data in sorted(
        convos.items(), key=lambda x: x[1]["packets"], reverse=True
    )[:top_n]:
        result.append({
            "Host A": host_a,
            "Host B": host_b,
            "Packets": data["packets"],
            "Bytes": data["bytes"],
            "Protocols": ", ".join(sorted(data["protocols"])),
        })

    return result


def calculate_top_talkers(records: list[PacketRecord], top_n: int = 10) -> list[dict]:
    """
    Calculates top endpoint hosts by sent, received, and total packet/byte volume.
    """
    if not records:
        return []

    hosts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"sent_pkts": 0, "rcvd_pkts": 0, "total_bytes": 0}
    )

    for r in records:
        if r.src_ip:
            hosts[r.src_ip]["sent_pkts"] += 1
            hosts[r.src_ip]["total_bytes"] += r.length
        if r.dst_ip:
            hosts[r.dst_ip]["rcvd_pkts"] += 1
            hosts[r.dst_ip]["total_bytes"] += r.length

    result = []
    for ip, data in sorted(
        hosts.items(), key=lambda x: (x[1]["sent_pkts"] + x[1]["rcvd_pkts"]), reverse=True
    )[:top_n]:
        total_pkts = data["sent_pkts"] + data["rcvd_pkts"]
        result.append({
            "IP Address": ip,
            "Sent Packets": data["sent_pkts"],
            "Received Packets": data["rcvd_pkts"],
            "Total Packets": total_pkts,
            "Total Bytes": data["total_bytes"],
        })

    return result