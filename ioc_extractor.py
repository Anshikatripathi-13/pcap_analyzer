"""
ioc_extractor.py
Pulls a clean, de-duplicated list of Indicators of Compromise (IOCs) out of
parsed packet records: IPs, domains, and full URLs. This is the thing
Wireshark makes you do by hand with Statistics > Endpoints + manual copy/paste.
"""

from __future__ import annotations
from dataclasses import dataclass, field

from models import PacketRecord

import ipaddress

# RFC 1918 private IPv4 networks:
# - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
# - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
# - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# Additional local/non-routable IPv4 ranges that are not external threat IOCs:
# - Loopback: 127.0.0.0/8
# - Link-local: 169.254.0.0/16
_LOCAL_NON_ROUTABLE_NETWORKS = (
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)


def is_rfc1918(ip: str) -> bool:
    """
    Explicitly checks whether an IP address belongs to an RFC 1918 private IPv4 block:
    10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16.
    Returns False for other ranges (such as carrier-grade NAT 100.64.0.0/10,
    loopback, link-local, public IPs, or invalid strings).
    """
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address) and any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    """
    Determines if an IP address is internal (RFC 1918, loopback, or link-local)
    rather than an external Indicator of Compromise (IOC).
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in (_RFC1918_NETWORKS + _LOCAL_NON_ROUTABLE_NETWORKS))
        return addr.is_loopback or addr.is_link_local or addr.is_private
    except ValueError:
        return False


@dataclass
class IOCReport:
    external_ips: set[str] = field(default_factory=set)
    internal_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "external_ips": sorted(self.external_ips),
            "internal_ips": sorted(self.internal_ips),
            "domains": sorted(self.domains),
            "urls": sorted(self.urls),
        }


def extract_iocs(records: list[PacketRecord]) -> IOCReport:
    report = IOCReport()

    for r in records:
        for ip in (r.src_ip, r.dst_ip):
            if not ip:
                continue
            if _is_private(ip):
                report.internal_ips.add(ip)
            else:
                report.external_ips.add(ip)

        if r.dns_query:
            report.domains.add(r.dns_query)

        if r.http_host:
            report.domains.add(r.http_host)
            if r.http_path:
                report.urls.add(f"http://{r.http_host}{r.http_path}")

    return report
