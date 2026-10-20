"""
ui_styles.py
A second, brighter color palette for the dashboard, additive to
design_system.py. The existing dark SOC theme (design_system.COLORS) is
completely untouched and remains the default -- this module only adds a
light alternative that theme_manager.py can swap in.

Reuses ColorTokens/TypographyTokens/SpacingTokens from design_system.py
(same dataclasses, just different field values) so assets/theme.css --
which only references CSS variable names, never raw colors -- works
unmodified under either theme.
"""

from __future__ import annotations

from design_system import ColorTokens, SPACING, TYPOGRAPHY

LIGHT_COLORS = ColorTokens(
    bg_primary="#F4F7FB",      # Solid off-white as requested
    bg_secondary="#FFFFFF",    # Clean solid white
    bg_surface="#FFFFFF",      # Solid white cards and panels (NOT translucent!)
    bg_surface_hover="#F8FAFC",
    border="#E2E8F0",          # Subtle gray border as requested
    border_hover="#CBD5E1",

    accent_start="#0284c7",    # cyan/sky-600
    accent_end="#4f46e5",      # indigo-600
    accent_solid="#0284c7",    # strong readable cyan/blue

    severity_critical="#be123c", # accessible rose-700
    severity_high="#c2410c",     # accessible orange-700
    severity_medium="#a16207",   # accessible amber-700
    severity_low="#0369a1",      # accessible sky-700
    severity_ok="#047857",       # accessible emerald-700

    text_primary="#0f172a",    # Dark slate as requested
    text_secondary="#475569",  # Slate-600
    text_muted="#64748b",      # Slate-500

    input_bg="#FFFFFF",        # White input background as requested
    input_border="#CBD5E1",    # Subtle border
    input_text="#0f172a",      # Dark text in inputs as requested
    input_placeholder="#94a3b8",
    btn_text="#FFFFFF",        # White text on #0284c7
    card_shadow="0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03)",
    code_bg="#F1F5F9",
    code_text="#0f172a",

    # Status chips in light theme (high contrast on white cards)
    chip_critical_bg="#FFF1F2",
    chip_critical_text="#be123c",
    chip_critical_border="#FECDD3",

    chip_high_bg="#FFF7ED",
    chip_high_text="#c2410c",
    chip_high_border="#FFEDD5",

    chip_medium_bg="#FEFCE8",
    chip_medium_text="#a16207",
    chip_medium_border="#FEF08A",

    chip_low_bg="#F0F9FF",
    chip_low_text="#0369a1",
    chip_low_border="#BAE6FD",

    chip_ok_bg="#ECFDF5",
    chip_ok_text="#047857",
    chip_ok_border="#A7F3D0",

    # Alert states
    alert_error_bg="#FFF1F2",
    alert_error_border="#FECDD3",
    alert_error_text="#9F1239",

    alert_warning_bg="#FFFBEB",
    alert_warning_border="#FDE68A",
    alert_warning_text="#92400E",

    alert_success_bg="#ECFDF5",
    alert_success_border="#A7F3D0",
    alert_success_text="#065F46",

    alert_info_bg="#F0F9FF",
    alert_info_border="#BAE6FD",
    alert_info_text="#075985",
)


def light_css_variables_block() -> str:
    """
    Same shape as design_system.css_variables_block(), but built from
    LIGHT_COLORS instead of the module-level dark COLORS. Typography and
    spacing tokens are shared with the dark theme -- only color changes.
    """
    c = LIGHT_COLORS
    return f"""
    :root {{
        --bg-primary: {c.bg_primary};
        --bg-secondary: {c.bg_secondary};
        --bg-surface: {c.bg_surface};
        --bg-surface-hover: {c.bg_surface_hover};
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
        --btn-text: {c.btn_text};
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

    /* Light theme solid background (no geometric patterns) */
    .stApp {{
        background: {c.bg_primary} !important;
    }}
    """


def plotly_light_template() -> dict:
    """Plotly layout template dict matching the light SOC theme."""
    c = LIGHT_COLORS
    return {
        "layout": {
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor": "rgba(0,0,0,0)",
            "font": {"family": TYPOGRAPHY.font_family, "color": c.text_primary},
            "title": {"font": {"size": 16, "color": c.text_primary}},
            "legend": {"font": {"color": c.text_secondary}},
            "xaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.2)",
                "linecolor": c.border,
                "color": c.text_secondary,
            },
            "yaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.2)",
                "linecolor": c.border,
                "color": c.text_secondary,
            },
            "colorway": [
                c.accent_solid, c.accent_end, c.severity_high,
                c.severity_medium, c.severity_ok, c.severity_critical,
            ],
        }
    }
