package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/jallphin/wraith/internal/store"
)

type Styles struct {
	Header    lipgloss.Style
	StatusBar lipgloss.Style

	PaneBorder lipgloss.Style
	PaneTitle  lipgloss.Style

	HelpOverlay lipgloss.Style

	FindingRow        lipgloss.Style
	FindingRowActive  lipgloss.Style
	FindingRowMuted   lipgloss.Style
	FindingStatusIcon lipgloss.Style

	DetailLabel lipgloss.Style
	DetailValue lipgloss.Style

	Severity map[store.Severity]lipgloss.Style
}

var S = NewStyles()

func NewStyles() Styles {
	baseBorder := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).BorderForeground(lipgloss.Color("238"))

	sev := map[store.Severity]lipgloss.Style{
		store.SeverityInfo:     lipgloss.NewStyle().Foreground(lipgloss.Color(store.SeverityInfo.Color())),
		store.SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color(store.SeverityLow.Color())),
		store.SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color(store.SeverityMedium.Color())),
		store.SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color(store.SeverityHigh.Color())),
		store.SeverityCritical: lipgloss.NewStyle().Foreground(lipgloss.Color(store.SeverityCritical.Color())).Bold(true),
	}

	return Styles{
		Header:    lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("252")).Background(lipgloss.Color("236")).Bold(true),
		StatusBar: lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("252")).Background(lipgloss.Color("236")),

		PaneBorder: baseBorder,
		PaneTitle:  lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true),

		HelpOverlay: lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), true).BorderForeground(lipgloss.Color("241")).Padding(1, 2).Background(lipgloss.Color("235")).Foreground(lipgloss.Color("252")),

		FindingRow:       lipgloss.NewStyle().Padding(0, 1),
		FindingRowActive: lipgloss.NewStyle().Padding(0, 1).Background(lipgloss.Color("237")).Bold(true),
		FindingRowMuted:  lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("244")),

		FindingStatusIcon: lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Bold(true),

		DetailLabel: lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true),
		DetailValue: lipgloss.NewStyle().Foreground(lipgloss.Color("252")),

		Severity: sev,
	}
}
