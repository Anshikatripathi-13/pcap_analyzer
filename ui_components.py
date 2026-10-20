"""
ui_components.py
Reusable, presentation-only Streamlit components for the SOC-style theme.

These functions render HTML/CSS or restyle existing Plotly figures. None of
them contain analysis logic -- every function takes already-computed values
(stats, alert lists, figures) and only changes how they're displayed.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st

from design_system import SEVERITY_COLOR_MAP, css_variables_block, plotly_dark_template

_THEME_CSS_PATH = Path(__file__).parent / "assets" / "theme.css"


def inject_theme() -> None:
    """
    Injects the CSS variable block (design_system) and the static
    stylesheet (assets/theme.css) into the page. Call once, near the top
    of app.py, before any other UI is rendered.
    """
    css = css_variables_block()
    if _THEME_CSS_PATH.exists():
        css += "\n" + _THEME_CSS_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def render_hero_banner(title: str, subtitle: str) -> None:
    """Renders the gradient hero banner at the top of the dashboard."""
    escaped_title = html.escape(str(title))
    escaped_subtitle = html.escape(str(subtitle))
    st.markdown(
        f'<div class="soc-hero">'
        f'<h1>{escaped_title}</h1>'
        f'<p>{escaped_subtitle}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_metric_card(icon: Optional[str], label: str, value: str) -> None:
    """
    Renders a single glassmorphism metric card. Use inside st.columns(),
    one call per column, exactly like st.metric() is used today.
    If icon is empty or None, the icon element is omitted cleanly.
    """
    escaped_label = html.escape(str(label))
    escaped_value = html.escape(str(value))
    icon_html = f'<div class="soc-metric-icon">{html.escape(str(icon))}</div>' if icon else ""
    card_html = (
        f'<div class="soc-metric-card">'
        f'{icon_html}'
        f'<div class="soc-metric-label">{escaped_label}</div>'
        f'<div class="soc-metric-value">{escaped_value}</div>'
        f'</div>'
    )
    st.markdown(card_html, unsafe_allow_html=True)


def render_case_banner(
    case_number: str,
    evidence_number: str,
    filename: str,
    packet_count: int,
    duration_str: str,
    sha256_hash: str,
    investigator: Optional[str] = None,
    organization: Optional[str] = None,
) -> None:
    """
    Renders a clean, professional forensic case and evidence banner
    above the analysis tabs.
    """
    investigator_str = investigator if investigator else "Unassigned"
    truncated_hash = f"{sha256_hash[:16]}...{sha256_hash[-16:]}" if len(sha256_hash) > 32 else sha256_hash

    esc_filename = html.escape(str(filename))
    esc_case = html.escape(str(case_number))
    esc_evidence = html.escape(str(evidence_number))
    esc_investigator = html.escape(str(investigator_str))
    esc_duration = html.escape(str(duration_str))
    esc_hash = html.escape(str(sha256_hash))
    esc_truncated_hash = html.escape(str(truncated_hash))
    pkt_count_str = f"{packet_count:,}"

    banner_html = (
        f'<div class="soc-panel" style="margin-bottom: 1.5rem; padding: 1.25rem 1.5rem;">'
        f'<div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem;">'
        f'<div>'
        f'<div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600;">EVIDENCE RECORD</div>'
        f'<div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary); margin-top: 0.2rem;">{esc_filename}</div>'
        f'<div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.35rem; font-family: var(--font-family-mono); word-break: break-all;">'
        f'SHA-256: <span title="{esc_hash}">{esc_truncated_hash}</span>'
        f'</div>'
        f'</div>'
        f'<div style="display: flex; gap: 1.75rem; flex-wrap: wrap;">'
        f'<div>'
        f'<div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em;">CASE / EVIDENCE</div>'
        f'<div style="font-size: 0.95rem; font-weight: 600; color: var(--text-primary); margin-top: 0.2rem;">{esc_case} &middot; {esc_evidence}</div>'
        f'</div>'
        f'<div>'
        f'<div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em;">INVESTIGATOR</div>'
        f'<div style="font-size: 0.95rem; font-weight: 600; color: var(--text-primary); margin-top: 0.2rem;">{esc_investigator}</div>'
        f'</div>'
        f'<div>'
        f'<div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em;">PACKETS / DURATION</div>'
        f'<div style="font-size: 0.95rem; font-weight: 600; color: var(--text-primary); margin-top: 0.2rem;">{pkt_count_str} pkts &middot; {esc_duration}</div>'
        f'</div>'
        f'</div>'
        f'</div>'
        f'</div>'
    )
    st.markdown(banner_html, unsafe_allow_html=True)


def render_status_chip(severity: str) -> str:
    """
    Returns (does not render directly) an HTML status chip for a given
    severity string ("HIGH", "MEDIUM", "LOW", "OK", "CRITICAL"). Intended
    for use inside st.markdown(..., unsafe_allow_html=True) calls or when
    building HTML tables. Falls back gracefully for unknown severities.
    """
    severity_upper = (severity or "").upper()
    css_class = f"soc-chip-{severity_upper.lower()}" if severity_upper in SEVERITY_COLOR_MAP else "soc-chip-low"
    return f'<span class="soc-chip {css_class}">{html.escape(severity_upper or "UNKNOWN")}</span>'


def render_section_header(icon: str, title: str, caption: Optional[str] = None) -> None:
    """Consistent section header used across tabs, replacing bare st.header/st.subheader calls."""
    st.markdown(f"### {icon} {title}")
    if caption:
        st.caption(caption)


def render_data_table(
    data: pd.DataFrame | list[dict] | None,
    max_height: Optional[int | str] = None,
    use_container_width: bool = True,
) -> None:
    """
    Renders a Pandas DataFrame or list of dicts as an accessible, themed SOC HTML table.
    Works seamlessly under both dark and light modes by using semantic
    HTML (div.soc-table-container > table.soc-table) and CSS variables.
    User-uploaded strings are safely escaped via escape=True.
    """
    if data is None:
        st.info("No data available.")
        return

    if isinstance(data, list):
        if not data:
            st.info("No data available.")
            return
        df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        df = pd.DataFrame(data)

    if df.empty:
        st.info("No data available.")
        return

    height_style = ""
    if max_height:
        h = f"{max_height}px" if isinstance(max_height, int) else str(max_height)
        height_style = f"max-height: {h}; overflow-y: auto;"

    table_html = df.to_html(classes="soc-table", index=False, escape=True, border=0)
    container_html = f'<div class="soc-table-container" style="{height_style}">{table_html}</div>'
    st.markdown(container_html, unsafe_allow_html=True)


def style_plotly_figure(fig):
    """
    Applies the SOC theme template (dark or light) to an already-built Plotly figure.
    Takes a figure returned by the existing chart functions (charts.py,
    communication_graph.py, or inline px calls in app.py) and restyles
    layout only -- traces/data are untouched.
    """
    if fig is None:
        return fig
    try:
        from theme_manager import get_theme_mode
        from ui_styles import plotly_light_template
        mode = get_theme_mode()
        template = plotly_light_template() if mode == "light" else plotly_dark_template()
    except Exception:
        template = plotly_dark_template()
    fig.update_layout(**template["layout"])
    return fig


def render_footer() -> None:
    """Renders the professional footer at the bottom of the dashboard."""
    st.markdown(
        '<div class="soc-footer">'
        'PCAP Forensic Analyzer &middot; Enterprise Edition &middot; '
        'For authorized security investigations only'
        '</div>',
        unsafe_allow_html=True,
    )
