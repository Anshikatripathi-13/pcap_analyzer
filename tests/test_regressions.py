"""
tests/test_regressions.py
Regression test suite for the three high-priority bug fixes:
1. PDF report crash on alert models lacking a timestamp field.
2. Payload sanitization preserving line boundaries for multiline regex matching.
3. IP classification distinguishing RFC 1918 IPv4 ranges from public addresses using ipaddress.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from calculate_statistics import CaptureStatistics
from detectors.beaconing import BeaconAlert
from detectors.dns_tunneling import DNSTunnelAlert
from detectors.plaintext_creds import CredAlert, detect_plaintext_creds
from detectors.port_scan import PortScanAlert
from ioc_extractor import IOCReport, _is_private, extract_iocs, is_rfc1918
from models import PacketRecord
from password_detector import CredentialFinding, detect_credentials
from pdf_report import CaseInfo, generate_pdf_report
from report_integrity import verify_report_integrity
from ui_components import render_case_banner, render_hero_banner, render_metric_card, render_status_chip


# ===========================================================================
# 1. REGRESSION TESTS: Bug 1 — PDF Report Generation & Timeline Handling
# ===========================================================================

def _make_dummy_stats() -> CaptureStatistics:
    return CaptureStatistics(
        total_packets=10,
        capture_duration=15.0,
        total_bytes=1500,
        unique_ips=4,
        sessions=2,
        protocol_count=2,
    )


def _make_dummy_records() -> list[PacketRecord]:
    return [
        PacketRecord(index=0, timestamp=1000.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol="DNS", length=60),
        PacketRecord(index=1, timestamp=1005.0, src_ip="10.0.0.1", dst_ip="1.1.1.1", protocol="TCP", length=120),
    ]


def test_pdf_report_handles_port_scan_alert_without_timestamp():
    """PortScanAlert defines window_start/window_end but lacks a 'timestamp' attribute."""
    ps_alert = PortScanAlert(
        src_ip="10.0.0.5",
        distinct_ports=20,
        window_start=1700000000.0,
        window_end=1700000010.0,
        dst_ips={"192.168.1.1"},
        severity="HIGH",
    )

    with tempfile.TemporaryDirectory() as td:
        pdf_out = str(Path(td) / "test_ps.pdf")
        pdf_path, sidecar_path, report_id = generate_pdf_report(
            output_path=pdf_out,
            pcap_name="test_ps.pcap",
            file_size_bytes=1024,
            hashes={"MD5": "abc", "SHA1": "def", "SHA256": "123"},
            records=_make_dummy_records(),
            stats=_make_dummy_stats(),
            iocs=IOCReport(),
            port_scan_alerts=[ps_alert],
            beacon_alerts=[],
            dns_alerts=[],
            cred_alerts=[],
            credential_findings=[],
            case_info=CaseInfo(case_number="CASE-001"),
        )
        assert Path(pdf_path).exists()
        assert Path(pdf_path).stat().st_size > 0
        v = verify_report_integrity(pdf_path, sidecar_path)
        assert v.verified is True


def test_pdf_report_handles_beacon_and_dns_alerts_lacking_timestamp():
    """BeaconAlert and DNSTunnelAlert do not define timestamp attributes."""
    b_alert = BeaconAlert(
        src_ip="10.0.0.2",
        dst_ip="198.51.100.4",
        connection_count=12,
        avg_interval_seconds=60.0,
        coeff_variation=0.02,
        severity="HIGH",
    )
    d_alert = DNSTunnelAlert(
        root_domain="tunnel-c2.net",
        query_count=50,
        avg_subdomain_length=35.0,
        avg_entropy=4.2,
        severity="HIGH",
    )

    with tempfile.TemporaryDirectory() as td:
        pdf_out = str(Path(td) / "test_b_d.pdf")
        pdf_path, sidecar_path, _ = generate_pdf_report(
            output_path=pdf_out,
            pcap_name="test_b_d.pcap",
            file_size_bytes=2048,
            hashes={"MD5": "abc", "SHA1": "def", "SHA256": "123"},
            records=_make_dummy_records(),
            stats=_make_dummy_stats(),
            iocs=IOCReport(),
            port_scan_alerts=[],
            beacon_alerts=[b_alert],
            dns_alerts=[d_alert],
            cred_alerts=[],
            credential_findings=[],
            case_info=CaseInfo(),
        )
        assert Path(pdf_path).exists()
        assert Path(pdf_path).stat().st_size > 0


def test_pdf_report_mixed_alerts_and_chronological_ordering():
    """Mixes all 5 alert types, including ones with timestamps, window_start, and None."""
    ps = PortScanAlert("10.0.0.5", 25, 1700000010.0, 1700000020.0, {"1.2.3.4"}, "HIGH")
    b = BeaconAlert("10.0.0.2", "8.8.8.8", 10, 30.0, 0.05, "MEDIUM")
    d = DNSTunnelAlert("c2.org", 40, 28.0, 3.9, "MEDIUM")
    c = CredAlert(0, 1700000005.0, "10.0.0.2", "1.2.3.4", "ftp_user", "USER admin", "HIGH")
    f = CredentialFinding(
        packet_index=1,
        timestamp=1700000008.0,
        src_ip="10.0.0.2",
        dst_ip="1.2.3.4",
        dst_port=21,
        protocol="TCP",
        field_type="ftp_pass",
        field_name=None,
        value="secret123",
        severity="HIGH",
    )

    with tempfile.TemporaryDirectory() as td:
        pdf_out = str(Path(td) / "test_mixed.pdf")
        pdf_path, sidecar_path, _ = generate_pdf_report(
            output_path=pdf_out,
            pcap_name="mixed.pcap",
            file_size_bytes=4096,
            hashes={"MD5": "1", "SHA1": "2", "SHA256": "3"},
            records=_make_dummy_records(),
            stats=_make_dummy_stats(),
            iocs=IOCReport(),
            port_scan_alerts=[ps],
            beacon_alerts=[b],
            dns_alerts=[d],
            cred_alerts=[c],
            credential_findings=[f],
        )
        assert Path(pdf_path).stat().st_size > 0


# ===========================================================================
# 2. REGRESSION TESTS: Bug 2 — Payload Sanitization & Multiline Regex Matching
# ===========================================================================

def test_sanitization_preserves_crlf_and_lf():
    """Tests that newline boundaries are retained and binary non-printables are replaced."""
    raw = b"\x00\x01USER alice\r\nPASS secret123\n\x00QUIT\r\n\xff"
    sanitized = re.sub(rb"[^\x20-\x7e\r\n\t]", b".", raw[:256]).decode(errors="ignore")

    assert "\r\n" in sanitized
    assert "\n" in sanitized
    assert "..\r\n" not in sanitized or sanitized.startswith("..USER")
    assert "USER alice" in sanitized
    assert "PASS secret123" in sanitized


def test_multiline_ftp_credentials_detected_after_sanitization():
    """FTP commands separated by CRLF on line 2 must match multiline (?m)^PASS."""
    raw = b"220 Service ready\r\nUSER bob\r\nPASS hunter2\r\n"
    snippet = re.sub(rb"[^\x20-\x7e\r\n\t]", b".", raw[:256]).decode(errors="ignore")

    # 1. Test legacy detector
    r = PacketRecord(index=0, timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", payload_snippet=snippet)
    alerts = detect_plaintext_creds([r])
    kinds = [a.kind for a in alerts]
    assert "ftp_user" in kinds
    assert "ftp_pass" in kinds

    # 2. Test password_detector
    r2 = PacketRecord(index=0, timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=21, payload_snippet=snippet)
    findings = detect_credentials([r2])
    field_types = {f.field_type: f.value for f in findings}
    assert "ftp_user" in field_types and field_types["ftp_user"] == "bob"
    assert "ftp_pass" in field_types and field_types["ftp_pass"] == "hunter2"


def test_sanitization_binary_only_edge_case():
    """A purely binary packet should be sanitized to dots without error or fake credentials."""
    raw = bytes([0x00, 0x01, 0x02, 0x1f, 0x80, 0xff] * 20)
    snippet = re.sub(rb"[^\x20-\x7e\r\n\t]", b".", raw[:256]).decode(errors="ignore")
    assert all(ch == "." for ch in snippet)
    r = PacketRecord(index=0, timestamp=1.0, payload_snippet=snippet)
    assert detect_plaintext_creds([r]) == []
    assert detect_credentials([r]) == []


# ===========================================================================
# 3. REGRESSION TESTS: Bug 3 — IP Classification & RFC 1918 Distinction
# ===========================================================================

def test_explicit_rfc1918_ranges():
    """Verifies that all three RFC 1918 ranges are recognized as RFC 1918."""
    rfc1918_ips = [
        "10.0.0.1",
        "10.123.45.67",
        "10.255.255.254",
        "172.16.0.1",
        "172.20.10.5",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.1.254",
        "192.168.254.254",
    ]
    for ip in rfc1918_ips:
        assert is_rfc1918(ip) is True, f"Expected {ip} to be RFC 1918"
        assert _is_private(ip) is True, f"Expected {ip} to be internal private"


def test_public_and_boundary_ips_are_not_rfc1918():
    """Verifies boundary IPv4 ranges and public IPs (including Google 172.217.x.x) are not RFC 1918."""
    public_ips = [
        "172.15.255.255",  # Right below 172.16.0.0/12
        "172.32.0.1",      # Right above 172.31.255.255
        "172.217.16.14",   # Google public IP (previously misclassified due to '172.2' prefix)
        "172.200.1.1",     # Public 172.2xx IP
        "8.8.8.8",         # Google Public DNS
        "1.1.1.1",         # Cloudflare DNS
        "192.169.1.1",     # Right above 192.168.0.0/16
        "9.255.255.255",   # Right below 10.0.0.0/8
        "11.0.0.1",        # Right above 10.255.255.255
        "100.64.0.1",      # Carrier-Grade NAT (RFC 6598, NOT RFC 1918)
    ]
    for ip in public_ips:
        assert is_rfc1918(ip) is False, f"Expected {ip} NOT to be RFC 1918"
        assert _is_private(ip) is False, f"Expected {ip} NOT to be classified as internal"


def test_local_non_routable_ranges_not_rfc1918_but_internal():
    """Loopback and link-local are not RFC 1918, but must be treated as internal (not external IOCs)."""
    assert is_rfc1918("127.0.0.1") is False
    assert _is_private("127.0.0.1") is True

    assert is_rfc1918("169.254.1.1") is False
    assert _is_private("169.254.1.1") is True


def test_ip_classification_edge_cases():
    """Handles malformed strings safely without exceptions."""
    malformed = ["", "invalid", "999.999.999.999", "10.0.0.", "::ghij"]
    for bad in malformed:
        assert is_rfc1918(bad) is False
        assert _is_private(bad) is False


def test_extract_iocs_separates_public_and_private_accurately():
    """Integration test: extract_iocs accurately segregates external IOCs from internal IPs."""
    records = [
        PacketRecord(index=0, timestamp=1.0, src_ip="192.168.1.50", dst_ip="172.217.16.14"),
        PacketRecord(index=1, timestamp=2.0, src_ip="10.0.0.5", dst_ip="8.8.8.8"),
        PacketRecord(index=2, timestamp=3.0, src_ip="127.0.0.1", dst_ip="172.16.10.1"),
    ]
    report = extract_iocs(records)

    # 172.217.16.14 (Google) and 8.8.8.8 must be external IOCs
    assert "172.217.16.14" in report.external_ips
    assert "8.8.8.8" in report.external_ips

    # RFC 1918 and loopback must be internal
    assert "192.168.1.50" in report.internal_ips
    assert "10.0.0.5" in report.internal_ips
    assert "172.16.10.1" in report.internal_ips
    assert "127.0.0.1" in report.internal_ips

    # Ensure no leakage
    assert "172.217.16.14" not in report.internal_ips
    assert "10.0.0.5" not in report.external_ips


# ===========================================================================
# 4. REGRESSION TESTS: Bug 4 — Metric Cards & HTML Component Rendering Integrity
# ===========================================================================

def test_metric_card_no_indented_code_blocks_or_blank_lines(monkeypatch):
    """
    Regression test: render_metric_card must NOT emit multi-line strings with
    4-space indentation or internal blank lines that cause Markdown parsers to
    render HTML tags inside <pre><code> boxes.
    """
    captured = []
    monkeypatch.setattr("streamlit.markdown", lambda content, unsafe_allow_html=False: captured.append((content, unsafe_allow_html)))

    render_metric_card(None, "Total Packets", "1,234")
    assert len(captured) == 1
    content, allow_html = captured[0]

    assert allow_html is True
    # Must not contain lines indented by 4+ spaces
    for line in content.split("\n"):
        assert not line.startswith("    "), f"Line has 4-space indentation which triggers markdown code block: {line!r}"
    # Must not have blank lines inside the HTML
    assert "\n\n" not in content
    # Check expected CSS classes and values
    assert '<div class="soc-metric-card">' in content
    assert '<div class="soc-metric-label">Total Packets</div>' in content
    assert '<div class="soc-metric-value">1,234</div>' in content
    # Icon div must be cleanly omitted when icon is None
    assert "soc-metric-icon" not in content


def test_metric_card_with_icon(monkeypatch):
    """Verifies icon rendering and layout when an icon is provided."""
    captured = []
    monkeypatch.setattr("streamlit.markdown", lambda content, unsafe_allow_html=False: captured.append((content, unsafe_allow_html)))

    render_metric_card("🔍", "Sessions", "42")
    assert len(captured) == 1
    content, allow_html = captured[0]
    assert allow_html is True
    assert '<div class="soc-metric-icon">🔍</div>' in content
    assert '<div class="soc-metric-label">Sessions</div>' in content
    assert '<div class="soc-metric-value">42</div>' in content


def test_metric_card_escapes_unsafe_html(monkeypatch):
    """Verifies that malicious or user-derived strings are HTML escaped."""
    captured = []
    monkeypatch.setattr("streamlit.markdown", lambda content, unsafe_allow_html=False: captured.append((content, unsafe_allow_html)))

    render_metric_card(None, "<script>alert(1)</script>", "<b>bold</b>")
    assert len(captured) == 1
    content, _ = captured[0]
    assert "<script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "<b>" not in content
    assert "&lt;b&gt;bold&lt;/b&gt;" in content


def test_case_banner_escapes_user_uploaded_content(monkeypatch):
    """Verifies that case banner safely escapes user-uploaded filename and details."""
    captured = []
    monkeypatch.setattr("streamlit.markdown", lambda content, unsafe_allow_html=False: captured.append((content, unsafe_allow_html)))

    render_case_banner(
        case_number="CASE<1>",
        evidence_number="EVD&1",
        filename="<malicious_upload>.pcap",
        packet_count=100,
        duration_str="10s",
        sha256_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        investigator="<analyst>",
    )
    assert len(captured) == 1
    content, allow_html = captured[0]
    assert allow_html is True
    assert "<malicious_upload>" not in content
    assert "&lt;malicious_upload&gt;.pcap" in content
    assert "&lt;analyst&gt;" in content
    assert "&lt;1&gt;" in content
    for line in content.split("\n"):
        assert not line.startswith("    ")


def test_metric_cards_via_apptest():
    """Verifies render_metric_card executed in Streamlit runtime has no code blocks."""
    from streamlit.testing.v1 import AppTest

    script = """
import streamlit as st
from ui_components import render_metric_card
render_metric_card(None, "Total Packets", "100")
render_metric_card("📦", "Alerts", "5")
"""
    at = AppTest.from_string(script).run()
    assert not at.exception
    assert len(at.markdown) == 2
    for m in at.markdown:
        # None of the markdown elements should contain code blocks
        assert not m.value.startswith("```")
        assert "<pre>" not in m.value
        assert "\n\n" not in m.value
        assert "soc-metric-card" in m.value


def test_app_dashboard_overview_metrics_with_pcap():
    """
    End-to-end integration test: runs app.py with a sample PCAP and verifies
    that all 6 Dashboard Overview metric cards are rendered as valid HTML cards
    with calculated numeric values and no literal HTML or markdown code blocks.
    """
    from streamlit.testing.v1 import AppTest

    pcap_path = Path(__file__).parent.parent / "samples" / "synthetic_investigation.pcap"
    assert pcap_path.exists()

    at = AppTest.from_file(str(Path(__file__).parent.parent / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception

    at.file_uploader[0].upload("synthetic_investigation.pcap", pcap_path.read_bytes())
    at.run()
    assert not at.exception

    # Filter markdown elements for metric cards
    metric_elements = [m for m in at.markdown if "soc-metric-card" in m.value]
    assert len(metric_elements) >= 6

    # Verify each overview metric card
    labels = ["Total Packets", "Unique IPs", "Sessions", "Protocols", "Traffic", "Alerts"]
    for label in labels:
        matching = [m for m in metric_elements if f'<div class="soc-metric-label">{label}</div>' in m.value]
        assert len(matching) == 1, f"Expected exactly 1 metric card for {label}"
        val = matching[0].value
        assert not val.startswith("```")
        assert "<pre>" not in val
        assert "\n\n" not in val
        assert matching[0].allow_html is True

    # Check that actual values are present and not empty/placeholder
    pkt_card = [m for m in metric_elements if "Total Packets" in m.value][0].value
    assert '<div class="soc-metric-value">103</div>' in pkt_card

    bytes_card = [m for m in metric_elements if "Traffic" in m.value][0].value
    assert "Bytes</div>" in bytes_card


# ===========================================================================
# 5. REGRESSION TESTS: Bug 5 — Frontend Color System & Theme Consistency
# ===========================================================================

def test_dark_theme_color_tokens_and_variables():
    """Verifies that dark theme meets design requirements: navy #0B1120, slate #141D2E."""
    from design_system import COLORS, css_variables_block

    assert COLORS.bg_primary.upper() == "#0B1120"
    assert COLORS.bg_secondary.upper() == "#141D2E"
    assert COLORS.bg_surface.upper() == "#141D2E"
    assert "rgba" not in COLORS.bg_surface.lower()  # solid, not translucent
    assert COLORS.accent_solid.upper() == "#06B6D4"

    css = css_variables_block()
    assert "--bg-primary: #0B1120" in css
    assert "--bg-secondary: #141D2E" in css
    assert "--bg-surface: #141D2E" in css
    assert "--input-bg: #0E1726" in css
    assert "--input-text: #f8fafc" in css
    assert "--card-shadow:" in css
    assert "--alert-error-bg:" in css
    assert "--alert-success-bg:" in css


def test_light_theme_color_tokens_and_variables():
    """Verifies that light theme meets design requirements: solid off-white #F4F7FB, white cards #FFFFFF."""
    from ui_styles import LIGHT_COLORS, light_css_variables_block

    assert LIGHT_COLORS.bg_primary.upper() == "#F4F7FB"
    assert LIGHT_COLORS.bg_secondary.upper() == "#FFFFFF"
    assert LIGHT_COLORS.bg_surface.upper() == "#FFFFFF"
    assert "rgba" not in LIGHT_COLORS.bg_surface.lower()  # solid, not translucent
    assert LIGHT_COLORS.text_primary.upper() == "#0F172A"
    assert LIGHT_COLORS.input_bg.upper() == "#FFFFFF"
    assert LIGHT_COLORS.input_text.upper() == "#0F172A"

    css = light_css_variables_block()
    assert "--bg-primary: #F4F7FB" in css
    assert "--bg-surface: #FFFFFF" in css
    assert "--input-bg: #FFFFFF" in css
    assert "--input-text: #0f172a" in css

    # Must NOT contain geometric background mesh
    assert ".stApp::before" not in css
    assert "linear-gradient(30deg" not in css
    assert "linear-gradient(150deg" not in css


def test_theme_css_has_input_styles_and_no_hardcoded_bg():
    """Verifies assets/theme.css references CSS variables for inputs, cards, and app background."""
    theme_css_path = Path(__file__).parent.parent / "assets" / "theme.css"
    content = theme_css_path.read_text(encoding="utf-8")

    # App background must reference var(--bg-primary) without hardcoded #0d1320
    assert "var(--bg-primary)" in content
    assert "#0d1320" not in content

    # Input controls must be styled with variables
    assert 'div[data-baseweb="input"]' in content
    assert "var(--input-bg)" in content
    assert "var(--input-text)" in content
    assert "var(--card-shadow)" in content

    # Alert banners must be styled with variables
    assert 'div[data-testid="stAlert"]' in content
    assert "var(--alert-error-bg)" in content
    assert "var(--alert-success-bg)" in content


def test_plotly_theme_templates():
    """Verifies plotly dark and light templates generate valid layouts."""
    import plotly.graph_objects as go
    from design_system import plotly_dark_template
    from ui_styles import plotly_light_template
    from ui_components import style_plotly_figure

    dark_tpl = plotly_dark_template()
    light_tpl = plotly_light_template()

    assert dark_tpl["layout"]["font"]["color"] == "#f8fafc"
    assert light_tpl["layout"]["font"]["color"] == "#0f172a"
    assert len(dark_tpl["layout"]["colorway"]) >= 5
    assert len(light_tpl["layout"]["colorway"]) >= 5

    fig = go.Figure()
    styled = style_plotly_figure(fig)
    assert styled is not None

    # Hoverlabel must be configured for legible tooltips in both themes
    assert "hoverlabel" in dark_tpl["layout"]
    assert "hoverlabel" in light_tpl["layout"]
    assert dark_tpl["layout"]["hoverlabel"]["bgcolor"] == "#141D2E"
    assert light_tpl["layout"]["hoverlabel"]["bgcolor"] == "#FFFFFF"

    # Colorway should use the coordinated blue/cyan cybersecurity palette
    assert dark_tpl["layout"]["colorway"][0] == "#06b6d4"
    assert light_tpl["layout"]["colorway"][0] == "#0284c7"


# ===========================================================================
# 6. REGRESSION TESTS: Bug 6 — Table Themes, Uploader & Visual Consistency
# ===========================================================================

def test_table_theme_tokens_and_variables():
    """Verifies table header background variables are defined for both themes."""
    from design_system import COLORS, css_variables_block
    from ui_styles import LIGHT_COLORS, light_css_variables_block

    assert COLORS.table_header_bg.upper() == "#1A2438"
    assert LIGHT_COLORS.table_header_bg.upper() == "#F8FAFC"

    dark_css = css_variables_block()
    light_css = light_css_variables_block()

    assert "--table-header-bg: #1A2438" in dark_css
    assert "--table-header-bg: #F8FAFC" in light_css


def test_render_data_table_escapes_content_and_structures_html(monkeypatch):
    """
    Verifies that render_data_table generates accessible HTML table markup,
    wraps it in .soc-table-container, and safely escapes unsafe characters.
    """
    import pandas as pd
    from ui_components import render_data_table

    captured = []

    def mock_markdown(content, unsafe_allow_html=False):
        captured.append((content, unsafe_allow_html))

    monkeypatch.setattr("streamlit.markdown", mock_markdown)

    # 1. Valid data
    df = pd.DataFrame([
        {"Protocol": "<script>alert('xss')</script>", "Packets": 42, "Bytes": 1024}
    ])
    render_data_table(df)

    assert len(captured) == 1
    html_content, allow_html = captured[0]
    assert allow_html is True
    assert '<div class="soc-table-container"' in html_content
    assert '<table class="dataframe soc-table">' in html_content
    # XSS content must be escaped
    assert "<script>" not in html_content
    assert "&lt;script&gt;alert('xss')&lt;/script&gt;" in html_content
    assert "42" in html_content

    # 2. List of dicts input
    captured.clear()
    render_data_table([{"Host": "192.168.1.1", "Alerts": 3}])
    assert len(captured) == 1
    assert "192.168.1.1" in captured[0][0]

    # 3. None and empty input do not crash
    info_captured = []
    monkeypatch.setattr("streamlit.info", lambda msg: info_captured.append(msg))
    render_data_table(None)
    render_data_table([])
    render_data_table(pd.DataFrame())
    assert len(info_captured) == 3


def test_theme_css_uploader_and_table_rules():
    """Verifies assets/theme.css contains refined rules for uploader and tables."""
    theme_css_path = Path(__file__).parent.parent / "assets" / "theme.css"
    content = theme_css_path.read_text(encoding="utf-8")

    # File uploader dropzone and browse button
    assert '[data-testid="stFileUploaderDropzone"]' in content
    assert '[data-testid="stFileUploaderDropzone"] button' in content
    assert "var(--bg-surface)" in content
    assert "var(--accent-solid)" in content

    # SOC data tables
    assert ".soc-table-container" in content
    assert ".soc-table" in content
    assert "var(--table-header-bg)" in content
    assert 'div[data-testid="stTable"]' in content


