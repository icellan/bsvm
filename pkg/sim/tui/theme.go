package tui

import "github.com/charmbracelet/lipgloss"

// Theme colours match the spec-15 explorer SPA so the two surfaces feel
// like one product.
var (
	ColorBg      = lipgloss.Color("#0b0f17")
	ColorPanel   = lipgloss.Color("#111827")
	ColorBorder  = lipgloss.Color("#1f2937")
	ColorFg      = lipgloss.Color("#e5e7eb")
	ColorMuted   = lipgloss.Color("#6b7280")
	ColorAccent  = lipgloss.Color("#4f9cf9")
	ColorSuccess = lipgloss.Color("#34d399")
	ColorWarning = lipgloss.Color("#f59e0b")
	ColorDanger  = lipgloss.Color("#ef4444")
)

// PanelStyle returns a reusable lipgloss style for a bordered panel.
func PanelStyle(title string, focused bool) lipgloss.Style {
	borderColor := ColorBorder
	if focused {
		borderColor = ColorAccent
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), true).
		BorderForeground(borderColor).
		Foreground(ColorFg).
		Padding(0, 1)
}

// TitleStyle renders the section title rows inside panels.
func TitleStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
}

// MutedStyle renders secondary text.
func MutedStyle() lipgloss.Style { return lipgloss.NewStyle().Foreground(ColorMuted) }

// OKStyle, WarnStyle and BadStyle colourise status markers.
func OKStyle() lipgloss.Style   { return lipgloss.NewStyle().Foreground(ColorSuccess) }
func WarnStyle() lipgloss.Style { return lipgloss.NewStyle().Foreground(ColorWarning) }
func BadStyle() lipgloss.Style  { return lipgloss.NewStyle().Foreground(ColorDanger) }
