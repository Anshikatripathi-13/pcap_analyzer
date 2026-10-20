"""
tests/test_dashboard_improvements.py
Unit tests verifying the dashboard improvements:
1. Wireshark-style Hex/ASCII payload formatting.
2. Timeline filtering (inclusive boundaries, ordering, empty results).
3. Protocol distribution calculation (accurate counts, percentages, bytes, no hidden categories).
4. Top Conversations (bidirectional grouping, packet & byte aggregation).
5. Top Talkers (sent, received, total metrics).
6. PacketRecord data model enhancements (TCP flags and raw payload).
"""

from __future__ import annotations

import pytest
from models import PacketRecord
from pcap_parser import format_hex_ascii
from calculate_statistics import (
    filter_records_by_time,
    calculate_protocol_distribution,
    calculate_top_conversations,
    calculate_top_talkers,
)


class TestHexAsciiFormatter:
    """Tests Wireshark/hexdump style hex/ascii payload rendering."""

    def test_empty_payload(self):
        assert format_hex_ascii(b"") == ""
        assert format_hex_ascii(None) == ""

    def test_single_line_ascii(self):
        data = b"Hello, World!"
        result = format_hex_ascii(data)
        assert result.startswith("0000  ")
        assert "48 65 6c 6c 6f 2c 20 57" in result
        assert "|Hello, World!|" in result

    def test_exact_16_bytes(self):
        data = bytes(range(16))
        result = format_hex_ascii(data)
        lines = result.split("\n")
        assert len(lines) == 1
        assert lines[0].startswith("0000  ")
        assert "00 01 02 03 04 05 06 07" in lines[0]
        assert "08 09 0a 0b 0c 0d 0e 0f" in lines[0]

    def test_multi_line_and_non_printable_bytes(self):
        data = b"GET /admin HTTP/1.1\r\nHost: test.com\r\n\x00\xff"
        result = format_hex_ascii(data)
        lines = result.split("\n")
        assert len(lines) == 3
        assert lines[0].startswith("0000  ")
        assert lines[1].startswith("0010  ")
        assert lines[2].startswith("0020  ")
        assert lines[0].endswith("|")
        assert lines[2].endswith("|")
        assert ".." in lines[2]


class TestTimelineFilter:
    """Tests timeline window filtering of PacketRecord collections."""

    @pytest.fixture
    def sample_packets(self):
        return [
            PacketRecord(index=0, timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", length=60, protocol="TCP"),
            PacketRecord(index=1, timestamp=105.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", length=120, protocol="HTTP"),
            PacketRecord(index=2, timestamp=110.0, src_ip="10.0.0.2", dst_ip="10.0.0.1", length=80, protocol="HTTP"),
            PacketRecord(index=3, timestamp=115.0, src_ip="10.0.0.3", dst_ip="8.8.8.8", length=70, protocol="DNS"),
            PacketRecord(index=4, timestamp=120.0, src_ip="8.8.8.8", dst_ip="10.0.0.3", length=150, protocol="DNS"),
        ]

    def test_empty_list_returns_empty(self):
        assert filter_records_by_time([], start_ts=100.0, end_ts=200.0) == []

    def test_inclusive_boundaries(self, sample_packets):
        filtered = filter_records_by_time(sample_packets, start_ts=105.0, end_ts=115.0)
        assert len(filtered) == 3
        assert [p.index for p in filtered] == [1, 2, 3]

    def test_exact_single_boundary(self, sample_packets):
        filtered = filter_records_by_time(sample_packets, start_ts=110.0, end_ts=110.0)
        assert len(filtered) == 1
        assert filtered[0].index == 2

    def test_out_of_bounds_empty_result(self, sample_packets):
        filtered = filter_records_by_time(sample_packets, start_ts=200.0, end_ts=300.0)
        assert len(filtered) == 0

    def test_unbounded_filters(self, sample_packets):
        assert len(filter_records_by_time(sample_packets, start_ts=None, end_ts=None)) == 5
        assert len(filter_records_by_time(sample_packets, start_ts=115.0, end_ts=None)) == 2
        assert len(filter_records_by_time(sample_packets, start_ts=None, end_ts=105.0)) == 2

    def test_chronological_ordering_preserved(self, sample_packets):
        filtered = filter_records_by_time(sample_packets, start_ts=100.0, end_ts=120.0)
        timestamps = [p.timestamp for p in filtered]
        assert timestamps == sorted(timestamps)


class TestProtocolDistribution:
    """Tests protocol classification and percentage calculations."""

    def test_empty_records(self):
        assert calculate_protocol_distribution([]) == []

    def test_all_detected_protocols_shown_without_hidden_categories(self):
        records = [
            PacketRecord(index=0, timestamp=1.0, length=100, protocol="TCP"),
            PacketRecord(index=1, timestamp=2.0, length=200, protocol="UDP"),
            PacketRecord(index=2, timestamp=3.0, length=300, protocol="DNS"),
            PacketRecord(index=3, timestamp=4.0, length=400, protocol="TLS/HTTPS"),
            PacketRecord(index=4, timestamp=5.0, length=500, protocol="HTTP"),
        ]
        dist = calculate_protocol_distribution(records)
        assert len(dist) == 5
        protocols = {d["Protocol"] for d in dist}
        assert protocols == {"TCP", "UDP", "DNS", "TLS/HTTPS", "HTTP"}

        total_pkt_pct = sum(d["Packet %"] for d in dist)
        assert 99.9 <= total_pkt_pct <= 100.1

        total_byte_pct = sum(d["Byte %"] for d in dist)
        assert 99.9 <= total_byte_pct <= 100.1

        counts = [d["Packets"] for d in dist]
        assert counts == sorted(counts, reverse=True)


class TestConversationsAndTalkers:
    """Tests bi-directional conversations and endpoint talker statistics."""

    @pytest.fixture
    def traffic_records(self):
        return [
            # Host 10.0.0.1 <-> 10.0.0.2 (Total: 3 pkts, 300 bytes)
            PacketRecord(index=0, timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, protocol="TCP"),
            PacketRecord(index=1, timestamp=2.0, src_ip="10.0.0.2", dst_ip="10.0.0.1", length=100, protocol="TCP"),
            PacketRecord(index=2, timestamp=3.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, protocol="HTTP"),
            # Host 10.0.0.1 <-> 8.8.8.8 (Total: 1 pkt, 50 bytes)
            PacketRecord(index=3, timestamp=4.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", length=50, protocol="DNS"),
            # Missing IP record (should be ignored gracefully)
            PacketRecord(index=4, timestamp=5.0, src_ip=None, dst_ip="10.0.0.2", length=60, protocol="OTHER"),
        ]

    def test_top_conversations_bidirectional_aggregation(self, traffic_records):
        convs = calculate_top_conversations(traffic_records, top_n=5)
        assert len(convs) == 2

        top_conv = convs[0]
        assert top_conv["Host A"] == "10.0.0.1"
        assert top_conv["Host B"] == "10.0.0.2"
        assert top_conv["Packets"] == 3
        assert top_conv["Bytes"] == 300
        assert "HTTP" in top_conv["Protocols"]
        assert "TCP" in top_conv["Protocols"]

    def test_top_talkers_volume(self, traffic_records):
        talkers = calculate_top_talkers(traffic_records, top_n=5)
        assert len(talkers) >= 2

        talker_map = {t["IP Address"]: t for t in talkers}
        assert "10.0.0.1" in talker_map
        t1 = talker_map["10.0.0.1"]
        assert t1["Sent Packets"] == 3
        assert t1["Received Packets"] == 1
        assert t1["Total Packets"] == 4
        assert t1["Total Bytes"] == 350


class TestPacketRecordExtensions:
    """Verifies new PacketRecord attributes for TCP flags and raw payload."""

    def test_packet_record_attributes(self):
        rec = PacketRecord(
            index=0,
            timestamp=123456789.0,
            src_ip="192.168.1.5",
            dst_ip="192.168.1.1",
            src_port=54321,
            dst_port=443,
            protocol="TLS/HTTPS",
            length=128,
            tcp_flags="PA",
            raw_payload=b"\x16\x03\x01\x00\x7b",
        )
        assert rec.tcp_flags == "PA"
        assert rec.raw_payload == b"\x16\x03\x01\x00\x7b"
