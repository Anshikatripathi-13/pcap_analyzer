"""
detectors/beaconing.py
Flags src->dst pairs that communicate at suspiciously regular intervals --
a classic sign of malware "beaconing" home to a C2 server. Wireshark has no
built-in equivalent; you'd need to export IO graphs and eyeball them.

Approach: for each (src_ip, dst_ip) pair, look at the gaps between
successive connections. If there are enough samples and the gaps are very
consistent (low coefficient of variation), flag it.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import statistics

from models import PacketRecord

MIN_CONNECTIONS = 6          # need at least this many contacts to judge regularity
MAX_COEFF_VARIATION = 0.15   # lower = stricter "regularity" requirement
DEFAULT_BURST_GAP_SECONDS = 1.0  # min quiet period between distinct communication bursts


@dataclass
class BeaconAlert:
    src_ip: str
    dst_ip: str
    connection_count: int
    avg_interval_seconds: float
    coeff_variation: float
    severity: str = "MEDIUM"

    def summary(self) -> str:
        return (f"Possible beaconing: {self.src_ip} -> {self.dst_ip}, "
                f"{self.connection_count} connections, avg interval "
                f"{self.avg_interval_seconds:.1f}s, "
                f"regularity score {self.coeff_variation:.2f} (lower = more regular).")


def _extract_connection_times(recs: list[PacketRecord], burst_gap: float) -> list[float]:
    """
    Extracts distinct connection event timestamps from a list of packet records.
    - If TCP SYN packets (connection attempts) are present, uses their timestamps
      (deduplicating retransmissions within the burst gap).
    - Otherwise (e.g. UDP traffic, captures without handshakes, or synthetic records
      lacking TCP flag metadata), clusters packets into distinct communication
      bursts separated by at least burst_gap seconds of inactivity.
    """
    recs_sorted = sorted(recs, key=lambda r: r.timestamp)

    # 1. Check for TCP SYN packets (SYN set, ACK unset)
    syn_times: list[float] = []
    last_syn: float | None = None
    for r in recs_sorted:
        if r.tcp_flags:
            flags = r.tcp_flags.upper()
            if "S" in flags and "A" not in flags:
                if last_syn is None or (r.timestamp - last_syn) >= burst_gap:
                    syn_times.append(r.timestamp)
                    last_syn = r.timestamp

    if len(syn_times) >= MIN_CONNECTIONS:
        return syn_times

    # 2. Fallback: deduplicate communication bursts by inactivity gap
    burst_times: list[float] = []
    last_pkt_time: float | None = None
    for r in recs_sorted:
        t = r.timestamp
        if last_pkt_time is None or (t - last_pkt_time) >= burst_gap:
            burst_times.append(t)
        last_pkt_time = t

    return burst_times


def detect_beaconing(
    records: list[PacketRecord],
    burst_gap_seconds: float = DEFAULT_BURST_GAP_SECONDS,
) -> list[BeaconAlert]:
    pairs: dict[tuple[str, str], list[PacketRecord]] = defaultdict(list)

    for r in records:
        if r.src_ip and r.dst_ip and r.dst_port:
            pairs[(r.src_ip, r.dst_ip)].append(r)

    alerts: list[BeaconAlert] = []
    for (src, dst), recs in pairs.items():
        times = _extract_connection_times(recs, burst_gap_seconds)
        if len(times) < MIN_CONNECTIONS:
            continue

        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 - t1 > 0]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue

        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            continue
        stdev = statistics.pstdev(intervals)
        coeff_var = stdev / mean_interval

        if coeff_var <= MAX_COEFF_VARIATION:
            alerts.append(BeaconAlert(
                src_ip=src,
                dst_ip=dst,
                connection_count=len(times),
                avg_interval_seconds=mean_interval,
                coeff_variation=coeff_var,
                severity="HIGH" if coeff_var <= 0.05 else "MEDIUM",
            ))

    return alerts
