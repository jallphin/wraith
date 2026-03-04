package tui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
	"github.com/jallphin/wraith/internal/synthesize"
)

type synthStage int

const (
	stageEvents synthStage = iota
	stagePairs
	stageClusters
	stageAI
	stageSave
	stageDone
)

var stageLabels = map[synthStage]string{
	stageEvents:   "Loading session events",
	stagePairs:    "Extracting command pairs",
	stageClusters: "Clustering activity phases",
	stageAI:       "Sending to AI for analysis",
	stageSave:     "Saving findings",
	stageDone:     "Done",
}

type synthProgressMsg struct {
	stage synthStage
}

type synthDoneMsg struct {
	findings []store.Finding
	err      error
}

type spinnerModel struct {
	spinner  spinner.Model
	stage    synthStage
	quitting bool
	err      error
	findings []store.Finding
	db       *store.DB
	cfg      config.Config
}

func newSpinnerModel(db *store.DB, cfg config.Config) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return spinnerModel{spinner: s, db: db, cfg: cfg, stage: stageAI}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, runSynthesis(m.db, m.cfg))
}

func runSynthesis(db *store.DB, cfg config.Config) tea.Cmd {
	return func() tea.Msg {
		findings, err := synthesize.Run(db, cfg)
		return synthDoneMsg{findings: findings, err: err}
	}
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case synthProgressMsg:
		m.stage = msg.stage
		return m, nil
	case synthDoneMsg:
		m.quitting = true
		m.findings = msg.findings
		m.err = msg.err
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m spinnerModel) View() string {
	if m.quitting {
		return ""
	}
	label := stageLabels[m.stage]
	return fmt.Sprintf("\n  %s %s...\n\n", m.spinner.View(), label)
}

// RunSynthesisWithSpinner runs AI synthesis with a progress spinner.
// Returns findings or error.
func RunSynthesisWithSpinner(db *store.DB, cfg config.Config) ([]store.Finding, error) {
	m := newSpinnerModel(db, cfg)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	result, err := p.Run()
	if err != nil {
		return nil, err
	}
	sm := result.(spinnerModel)
	return sm.findings, sm.err
}
