"""
detectors/dns_tunneling.py
Flags possible DNS tunneling: data smuggled inside DNS queries. Signs we
check for, per queried root domain:
  1. Abnormally high query volume to the same domain (tunneling needs many
     queries to move data).
  2. High average subdomain length (encoded data makes labels long).
  3. High character entropy in subdomains (base32/64-encoded data looks
     "random" compared to normal hostnames).
Wireshark shows raw DNS queries but does none of this correlation for you.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import math

from models import PacketRecord

MIN_QUERIES_TO_DOMAIN = 20     # volume threshold
MIN_AVG_SUBDOMAIN_LEN = 25     # chars
MIN_ENTROPY = 3.5              # bits/char, typical English text is ~2.5-3.0

# Curated set of prevalent multi-level country-code second-level domains (ccSLDs).
# DESIGN & OPERATIONAL LIMITATIONS:
#   This static list covers the most common global registry suffixes where the second
#   level is not registrable by end users (e.g., .co.uk, .gov.in, .com.au, .co.jp).
#   Limitations:
#     1. Multi-part private suffixes (e.g. .s3.amazonaws.com, .github.io) and rare or
#        newly registered ccSLDs outside this set fall back to the standard 2-label split.
#     2. For full dynamic coverage of all global ICANN and private domains, an external
#        library like python-tldextract (backed by the Mozilla Public Suffix List) would
#        be required, which is avoided here to maintain a zero-external-dependency core.
COMMON_TWO_LEVEL_TLDS: frozenset[str] = frozenset({
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "mil.uk", "mod.uk", "police.uk", "nhs.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "gov.in", "ac.in", "edu.in", "res.in",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "edu.nz", "geek.nz", "school.nz",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "lg.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "edu.za",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    # Canada
    "gc.ca",
    # Mexico
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    # Israel
    "co.il", "org.il", "gov.il", "ac.il", "muni.il",
    # South Korea
    "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr", "re.kr",
})


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _root_domain(fqdn: str) -> str:
    """
    Extracts the registrable root domain from an FQDN.
    Handles standard single-part TLDs (e.g., example.com -> example.com)
    and prevalent multi-level country-code second-level domains (ccSLDs)
    (e.g., evil.co.uk -> evil.co.uk, portal.gov.in -> portal.gov.in).
    """
    if not fqdn:
        return ""
    clean = fqdn.strip().rstrip(".").lower()
    parts = clean.split(".")
    if len(parts) <= 2:
        return clean

    suffix = f"{parts[-2]}.{parts[-1]}"
    if suffix in COMMON_TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


@dataclass
class DNSTunnelAlert:
    root_domain: str
    query_count: int
    avg_subdomain_length: float
    avg_entropy: float
    severity: str = "MEDIUM"

    def summary(self) -> str:
        return (f"Possible DNS tunneling via {self.root_domain}: "
                f"{self.query_count} queries, avg subdomain length "
                f"{self.avg_subdomain_length:.1f} chars, avg entropy "
                f"{self.avg_entropy:.2f} bits/char.")


def detect_dns_tunneling(records: list[PacketRecord]) -> list[DNSTunnelAlert]:
    by_domain: dict[str, list[str]] = defaultdict(list)

    for r in records:
        if not r.dns_query:
            continue
        root = _root_domain(r.dns_query)
        by_domain[root].append(r.dns_query)

    alerts: list[DNSTunnelAlert] = []
    for root, queries in by_domain.items():
        if len(queries) < MIN_QUERIES_TO_DOMAIN:
            continue

        subdomains = []
        for q in queries:
            prefix = q[: -len(root)].strip(".") if q.lower().endswith(root.lower()) else q
            subdomains.append(prefix)

        avg_len = sum(len(s) for s in subdomains) / len(subdomains)
        avg_ent = sum(_entropy(s) for s in subdomains) / len(subdomains)

        if avg_len >= MIN_AVG_SUBDOMAIN_LEN and avg_ent >= MIN_ENTROPY:
            alerts.append(DNSTunnelAlert(
                root_domain=root,
                query_count=len(queries),
                avg_subdomain_length=avg_len,
                avg_entropy=avg_ent,
                severity="HIGH" if avg_ent >= 4.0 else "MEDIUM",
            ))

    return alerts
