"""
design_system.py
Design tokens for the enterprise SOC-style theme (colors, typography,
spacing, radii). This is the single source of truth for the visual
language -- ui_components.py and assets/theme.css both consume it.

Nothing in this module touches analysis logic; it is purely presentational.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ColorTokens:
    # Backgrounds -- deep navy/graphite, not pure black (matches Defender XDR / Cortex)
    bg_primary: str = "#0B1120"
    bg_secondary: str = "#141D2E"
    bg_surface: str = "#141D2E"
    bg_surface_hover: str = "#1A2438"
    table_header_bg: str = "#1A2438"
    border: str = "rgba(148, 163, 184, 0.14)"
    border_hover: str = "rgba(148, 163, 184, 0.28)"

    # Single restrained accent (calmer than a loud dual-tone gradient
    # everywhere) -- used sparingly for emphasis, not as a wall-to-wall wash
    accent_start: str = "#0891b2"   # cyan-600, slightly deeper/calmer
    accent_end: str = "#4f46e5"     # indigo-600
    accent_solid: str = "#06b6d4"   # cyan-500

    # Severity palette
    severity_critical: str = "#f43f5e"
    severity_high: str = "#fb923c"
    severity_medium: str = "#facc15"
    severity_low: str = "#38bdf8"
    severity_ok: str = "#34d399"

    # Text
    text_primary: str = "#f8fafc"
    text_secondary: str = "#94a3b8"
    text_muted: str = "#64748b"

    # Form controls and inputs
    input_bg: str = "#0E1726"
    input_border: str = "rgba(148, 163, 184, 0.2)"
    input_text: str = "#f8fafc"
    input_placeholder: str = "#64748b"
    card_shadow: str = "0 4px 6px -1px rgba(0, 0, 0, 0.25)"
    code_bg: str = "#0E1726"
    code_text: str = "#f8fafc"

    # Action and download buttons (Option 3: Dark SOC palette)
    btn_bg: str = "#172B40"
    btn_text: str = "#67E8F9"
    btn_border: str = "#22D3EE"
    btn_hover_bg: str = "#1E3A57"
    btn_hover_border: str = "#67E8F9"
    btn_hover_text: str = "#A5F3FC"
    btn_focus_ring: str = "rgba(34, 211, 238, 0.45)"
    btn_disabled_bg: str = "rgba(23, 43, 64, 0.5)"
    btn_disabled_text: str = "rgba(103, 232, 249, 0.5)"
    btn_disabled_border: str = "rgba(34, 211, 238, 0.25)"

    # Status chips
    chip_critical_bg: str = "rgba(244, 63, 94, 0.14)"
    chip_critical_text: str = "#f43f5e"
    chip_critical_border: str = "rgba(244, 63, 94, 0.35)"

    chip_high_bg: str = "rgba(251, 146, 60, 0.14)"
    chip_high_text: str = "#fb923c"
    chip_high_border: str = "rgba(251, 146, 60, 0.35)"

    chip_medium_bg: str = "rgba(250, 204, 21, 0.14)"
    chip_medium_text: str = "#facc15"
    chip_medium_border: str = "rgba(250, 204, 21, 0.35)"

    chip_low_bg: str = "rgba(56, 189, 248, 0.14)"
    chip_low_text: str = "#38bdf8"
    chip_low_border: str = "rgba(56, 189, 248, 0.35)"

    chip_ok_bg: str = "rgba(52, 211, 153, 0.14)"
    chip_ok_text: str = "#34d399"
    chip_ok_border: str = "rgba(52, 211, 153, 0.35)"

    # Alert banners
    alert_error_bg: str = "rgba(244, 63, 94, 0.12)"
    alert_error_border: str = "rgba(244, 63, 94, 0.35)"
    alert_error_text: str = "#fecdd3"

    alert_warning_bg: str = "rgba(251, 146, 60, 0.12)"
    alert_warning_border: str = "rgba(251, 146, 60, 0.35)"
    alert_warning_text: str = "#fed7aa"

    alert_success_bg: str = "rgba(52, 211, 153, 0.12)"
    alert_success_border: str = "rgba(52, 211, 153, 0.35)"
    alert_success_text: str = "#a7f3d0"

    alert_info_bg: str = "rgba(56, 189, 248, 0.12)"
    alert_info_border: str = "rgba(56, 189, 248, 0.35)"
    alert_info_text: str = "#bae6fd"


@dataclass(frozen=True)
class TypographyTokens:
    font_family: str = (
        "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "system-ui, sans-serif"
    )
    font_family_mono: str = (
        "'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, monospace"
    )
    # Larger, more confident scale -- editorial-style type rather than
    # cramped default-dashboard sizing
    size_hero: str = "2.75rem"
    size_h2: str = "1.6rem"
    size_body: str = "1rem"
    size_small: str = "0.82rem"
    weight_hero: str = "700"
    letter_spacing_hero: str = "-0.02em"


@dataclass(frozen=True)
class SpacingTokens:
    radius_sm: str = "10px"
    radius_md: str = "18px"
    radius_lg: str = "26px"
    gap_sm: str = "0.6rem"
    gap_md: str = "1.25rem"
    gap_lg: str = "2.25rem"


COLORS = ColorTokens()
TYPOGRAPHY = TypographyTokens()
SPACING = SpacingTokens()

SEVERITY_COLOR_MAP: dict[str, str] = {
    "CRITICAL": COLORS.severity_critical,
    "HIGH": COLORS.severity_high,
    "MEDIUM": COLORS.severity_medium,
    "LOW": COLORS.severity_low,
    "OK": COLORS.severity_ok,
}


def css_variables_block() -> str:
    """
    Renders all design tokens as a :root { --var: value; } CSS block.
    assets/theme.css references these variables, so this must be injected
    into the page *before* (or alongside) theme.css.
    """
    c = COLORS
    return f"""
    :root {{
        --bg-primary: {c.bg_primary};
        --bg-secondary: {c.bg_secondary};
        --bg-surface: {c.bg_surface};
        --bg-surface-hover: {c.bg_surface_hover};
        --table-header-bg: {c.table_header_bg};
        --border-color: {c.border};
        --border-hover: {c.border_hover};

        --accent-start: {c.accent_start};
        --accent-end: {c.accent_end};
        --accent-solid: {c.accent_solid};
        --accent-gradient: linear-gradient(135deg, {c.accent_start}, {c.accent_end});

        --severity-critical: {c.severity_critical};
        --severity-high: {c.severity_high};
        --severity-medium: {c.severity_medium};
        --severity-low: {c.severity_low};
        --severity-ok: {c.severity_ok};

        --text-primary: {c.text_primary};
        --text-secondary: {c.text_secondary};
        --text-muted: {c.text_muted};

        --input-bg: {c.input_bg};
        --input-border: {c.input_border};
        --input-text: {c.input_text};
        --input-placeholder: {c.input_placeholder};
        --btn-bg: {c.btn_bg};
        --btn-text: {c.btn_text};
        --btn-border: {c.btn_border};
        --btn-hover-bg: {c.btn_hover_bg};
        --btn-hover-border: {c.btn_hover_border};
        --btn-hover-text: {c.btn_hover_text};
        --btn-focus-ring: {c.btn_focus_ring};
        --btn-disabled-bg: {c.btn_disabled_bg};
        --btn-disabled-text: {c.btn_disabled_text};
        --btn-disabled-border: {c.btn_disabled_border};
        --card-shadow: {c.card_shadow};
        --code-bg: {c.code_bg};
        --code-text: {c.code_text};

        --chip-critical-bg: {c.chip_critical_bg};
        --chip-critical-text: {c.chip_critical_text};
        --chip-critical-border: {c.chip_critical_border};

        --chip-high-bg: {c.chip_high_bg};
        --chip-high-text: {c.chip_high_text};
        --chip-high-border: {c.chip_high_border};

        --chip-medium-bg: {c.chip_medium_bg};
        --chip-medium-text: {c.chip_medium_text};
        --chip-medium-border: {c.chip_medium_border};

        --chip-low-bg: {c.chip_low_bg};
        --chip-low-text: {c.chip_low_text};
        --chip-low-border: {c.chip_low_border};

        --chip-ok-bg: {c.chip_ok_bg};
        --chip-ok-text: {c.chip_ok_text};
        --chip-ok-border: {c.chip_ok_border};

        --alert-error-bg: {c.alert_error_bg};
        --alert-error-border: {c.alert_error_border};
        --alert-error-text: {c.alert_error_text};

        --alert-warning-bg: {c.alert_warning_bg};
        --alert-warning-border: {c.alert_warning_border};
        --alert-warning-text: {c.alert_warning_text};

        --alert-success-bg: {c.alert_success_bg};
        --alert-success-border: {c.alert_success_border};
        --alert-success-text: {c.alert_success_text};

        --alert-info-bg: {c.alert_info_bg};
        --alert-info-border: {c.alert_info_border};
        --alert-info-text: {c.alert_info_text};

        --font-family: {TYPOGRAPHY.font_family};
        --font-family-mono: {TYPOGRAPHY.font_family_mono};
        --size-hero: {TYPOGRAPHY.size_hero};
        --size-h2: {TYPOGRAPHY.size_h2};
        --size-body: {TYPOGRAPHY.size_body};
        --size-small: {TYPOGRAPHY.size_small};
        --weight-hero: {TYPOGRAPHY.weight_hero};
        --letter-spacing-hero: {TYPOGRAPHY.letter_spacing_hero};

        --radius-sm: {SPACING.radius_sm};
        --radius-md: {SPACING.radius_md};
        --radius-lg: {SPACING.radius_lg};
        --gap-sm: {SPACING.gap_sm};
        --gap-md: {SPACING.gap_md};
        --gap-lg: {SPACING.gap_lg};
    }}
    """


def plotly_dark_template() -> dict:
    """
    A Plotly layout template dict matching the SOC theme, applied via
    fig.update_layout(template=...) to figures that already exist
    (charts.py, communication_graph.py, and the inline px calls in app.py).
    Uses a coordinated, restrained blue/cyan cybersecurity palette.
    """
    return {
        "layout": {
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor": "rgba(0,0,0,0)",
            "font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_primary, "size": 12},
            "title": {"font": {"family": TYPOGRAPHY.font_family, "size": 15, "color": COLORS.text_primary}},
            "legend": {"font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_secondary, "size": 11}},
            "xaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.08)",
                "linecolor": COLORS.border,
                "color": COLORS.text_secondary,
                "tickfont": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_secondary, "size": 11},
                "title": {"font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_secondary, "size": 12}},
                "zerolinecolor": "rgba(148, 163, 184, 0.15)",
            },
            "yaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.08)",
                "linecolor": COLORS.border,
                "color": COLORS.text_secondary,
                "tickfont": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_secondary, "size": 11},
                "title": {"font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_secondary, "size": 12}},
                "zerolinecolor": "rgba(148, 163, 184, 0.15)",
            },
            "hoverlabel": {
                "bgcolor": COLORS.bg_secondary,
                "bordercolor": COLORS.border,
                "font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_primary, "size": 12},
            },
            "colorway": [
                "#06b6d4",  # Cyan-500
                "#3b82f6",  # Blue-500
                "#6366f1",  # Indigo-500
                "#0ea5e9",  # Sky-500
                "#14b8a6",  # Teal-500
                "#8b5cf6",  # Violet-500
                "#38bdf8",  # Sky-400
                "#0284c7",  # Sky-600
                "#818cf8",  # Indigo-400
                "#2dd4bf",  # Teal-400
            ],
        }
    }
