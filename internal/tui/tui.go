package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jallphin/wraith/internal/store"
)

type pane int

const (
	paneList pane = iota
	paneDetail
	paneEvidence
)

type findingUpdatedMsg struct{ finding store.Finding }

type exportDoneMsg struct{ jsonPath, mdPath string }

type errMsg struct{ err error }

type findingItem struct{ f store.Finding }

func (i findingItem) Title() string       { return i.f.Title }
func (i findingItem) Description() string { return i.f.Asset }
func (i findingItem) FilterValue() string { return i.f.Title }

type findingDelegate struct{ m *Model }

func (d findingDelegate) Height() int  { return 1 }
func (d findingDelegate) Spacing() int { return 0 }
func (d findingDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd {
	return nil
}

func (d findingDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	fi, ok := item.(findingItem)
	if !ok {
		return
	}

	statusIcon := " "
	switch fi.f.Status {
	case store.StatusApproved:
		statusIcon = "✓"
	case store.StatusDiscarded:
		statusIcon = "✗"
	case store.StatusProposed:
		statusIcon = " "
	}

	selected := index == m.Index()
	if selected {
		statusIcon = "▶"
	}

	sev := fi.f.Severity.String()
	if len(sev) > 4 {
		sev = sev[:4]
	}
	sevStyle := S.Severity[fi.f.Severity]

	title := fi.f.Title
	if len(title) > 18 {
		title = title[:18]
	}
	asset := fi.f.Asset
	if len(asset) > 10 {
		asset = asset[:10]
	}

	row := fmt.Sprintf("%s %s  %-4s %-10s", S.FindingStatusIcon.Render(statusIcon), sevStyle.Render(sev), title, asset)

	st := S.FindingRow
	if selected {
		st = S.FindingRowActive
	} else if fi.f.Status == store.StatusDiscarded {
		st = S.FindingRowMuted
	}
	fmt.Fprint(w, st.Render(row))
}

// Model implements the Bubbletea TUI model.
type Model struct {
	// data
	sessionMeta store.SessionMeta
	session     *store.DB
	findings    []store.Finding

	// layout
	width  int
	height int
	focus  pane

	// components
	list      list.Model
	narrative viewport.Model
	editor    textarea.Model
	evidence  viewport.Model

	// state
	editing      bool
	showEvidence bool
	showHelp     bool
	quitConfirm  bool

	statusMsg string
	statusErr bool
}

func NewModel(db *store.DB, meta store.SessionMeta, findings []store.Finding) Model {
	items := make([]list.Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, findingItem{f: f})
	}

	l := list.New(items, findingDelegate{}, 0, 0)
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowPagination(false)

	vp := viewport.New(0, 0)
	evp := viewport.New(0, 0)

	ta := textarea.New()
	ta.Placeholder = "Narrative..."
	ta.ShowLineNumbers = false
	ta.CharLimit = 0
	ta.SetWidth(0)
	ta.SetHeight(5)

	m := Model{
		sessionMeta: meta,
		session:     db,
		findings:    findings,
		focus:       paneList,
		list:        l,
		narrative:   vp,
		editor:      ta,
		evidence:    evp,
	}
	m.refreshDetail()
	return m
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil
	case errMsg:
		m.statusMsg = msg.err.Error()
		m.statusErr = true
		return m, nil
	case exportDoneMsg:
		m.statusErr = false
		m.statusMsg = fmt.Sprintf("exported: %s , %s", msg.jsonPath, msg.mdPath)
		return m, nil
	case findingUpdatedMsg:
		for i := range m.findings {
			if m.findings[i].ID == msg.finding.ID {
				m.findings[i] = msg.finding
				m.list.SetItem(i, findingItem{f: msg.finding})
				break
			}
		}
		m.refreshDetail()
		return m, nil
	}

	// help overlay has top priority
	if m.showHelp {
		if km, ok := msg.(tea.KeyMsg); ok {
			if key.Matches(km, Keys.Help) || key.Matches(km, Keys.Quit) {
				m.showHelp = false
				return m, nil
			}
		}
		return m, nil
	}

	if m.editing {
		return m.updateEditing(msg)
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(km, Keys.Help):
			m.showHelp = true
			return m, nil
		case key.Matches(km, Keys.Cycle):
			m.focus = (m.focus + 1) % 3
			return m, nil
		case key.Matches(km, Keys.Quit):
			if m.quitConfirm {
				return m, tea.Quit
			}
			if m.hasUnsavedChanges() {
				m.quitConfirm = true
				m.statusErr = true
				m.statusMsg = "unsaved changes: press q again to quit"
				return m, nil
			}
			return m, tea.Quit
		case key.Matches(km, Keys.Next) || key.Matches(km, Keys.Prev):
			// let list handle navigation if it has focus
			if m.focus == paneList {
				var cmd tea.Cmd
				m.list, cmd = m.list.Update(msg)
				m.refreshDetail()
				return m, cmd
			}
			// manual navigation when focus isn't list
			if key.Matches(km, Keys.Next) {
				m.list.CursorDown()
			} else {
				m.list.CursorUp()
			}
			m.refreshDetail()
			return m, nil
		case key.Matches(km, Keys.Edit):
			m.startEditing()
			return m, textarea.Blink
		case key.Matches(km, Keys.Approve):
			return m, m.setStatus(store.StatusApproved)
		case key.Matches(km, Keys.Discard):
			return m, m.setStatus(store.StatusDiscarded)
		case key.Matches(km, Keys.Raw):
			m.showEvidence = !m.showEvidence
			m.refreshEvidence()
			return m, nil
		case key.Matches(km, Keys.Severity):
			return m, m.cycleSeverity()
		case key.Matches(km, Keys.Merge):
			return m, m.mergeWithNext()
		case key.Matches(km, Keys.Export):
			return m, m.exportApprovedCmd()
		}
	}

	// update viewports based on focus
	var cmd tea.Cmd
	if m.showEvidence {
		m.evidence, cmd = m.evidence.Update(msg)
		return m, cmd
	}
	m.narrative, cmd = m.narrative.Update(msg)
	return m, cmd
}

func (m Model) updateEditing(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(km, Keys.Esc), key.Matches(km, Keys.SaveExit):
			m.editing = false
			m.editor.Blur()
			m.statusErr = false
			m.statusMsg = "saved"
			return m, m.saveEditCmd(true)
		case key.Matches(km, Keys.Help):
			m.showHelp = true
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.editor, cmd = m.editor.Update(msg)
	return m, cmd
}

func (m *Model) resize() {
	headerH := 1
	statusH := 1
	bodyH := m.height - headerH - statusH
	if bodyH < 5 {
		bodyH = 5
	}

	leftW := int(float64(m.width) * 0.25)
	if leftW < 24 {
		leftW = 24
	}
	if leftW > m.width-20 {
		leftW = m.width - 20
	}
	rightW := m.width - leftW
	if rightW < 20 {
		rightW = 20
	}

	m.list.SetSize(leftW-2, bodyH-2) // inside border
	m.narrative.Width = rightW - 2
	m.narrative.Height = bodyH - 8
	if m.narrative.Height < 3 {
		m.narrative.Height = 3
	}
	m.evidence.Width = rightW - 2
	m.evidence.Height = bodyH - 4
	m.editor.SetWidth(rightW - 6)
	m.editor.SetHeight(bodyH - 10)
	if m.editor.Height() < 3 {
		m.editor.SetHeight(3)
	}

	m.refreshDetail()
	m.refreshEvidence()
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}

	header := m.renderHeader()
	body := m.renderBody()
	status := m.renderStatusBar()

	ui := header + "\n" + body + "\n" + status
	if m.showHelp {
		ui = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, ui+"\n"+m.renderHelp())
	}
	return ui
}

func (m Model) renderHeader() string {
	id := m.sessionMeta.ID
	if len(id) > 8 {
		id = id[:8]
	}
	approved := 0
	for _, f := range m.findings {
		if f.Status == store.StatusApproved {
			approved++
		}
	}
	meta := fmt.Sprintf("wraith review • session %s • %s • %d events • %d/%d approved", id, m.sessionMeta.Duration.Truncate(timeSecond).String(), m.sessionMeta.EventCount, approved, len(m.findings))
	if len(meta) > m.width-2 {
		meta = meta[:m.width-5] + "..."
	}
	return S.Header.Width(m.width).Render(meta)
}

const timeSecond = 1_000_000_000

func (m Model) renderBody() string {
	headerH := 1
	statusH := 1
	bodyH := m.height - headerH - statusH

	leftW := int(float64(m.width) * 0.25)
	if leftW < 24 {
		leftW = 24
	}
	if leftW > m.width-20 {
		leftW = m.width - 20
	}
	rightW := m.width - leftW

	left := S.PaneBorder.Width(leftW).Height(bodyH).Render(m.renderListPane(leftW-2, bodyH-2))
	var right string
	if m.showEvidence {
		right = S.PaneBorder.Width(rightW).Height(bodyH).Render(m.renderEvidencePane(rightW-2, bodyH-2))
	} else {
		right = S.PaneBorder.Width(rightW).Height(bodyH).Render(m.renderDetailPane(rightW-2, bodyH-2))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m Model) renderListPane(w, h int) string {
	title := fmt.Sprintf("FINDINGS  %d", len(m.findings))
	content := m.list.View()
	return lipgloss.JoinVertical(lipgloss.Top, S.PaneTitle.Render(title), content)
}

func (m Model) renderDetailPane(w, h int) string {
	f, ok := m.selectedFinding()
	if !ok {
		return ""
	}

	idx := m.list.Index() + 1
	top := fmt.Sprintf("[%d/%d]  %s — %s", idx, len(m.findings), f.Severity.String(), f.Title)

	lines := []string{
		S.PaneTitle.Render(top),
		"",
		S.DetailLabel.Render("Asset:") + "      " + S.DetailValue.Render(f.Asset),
		S.DetailLabel.Render("Technique:") + "  " + S.DetailValue.Render(f.Technique),
		S.DetailLabel.Render("Phase:") + "      " + S.DetailValue.Render(string(f.Phase)),
		"",
		S.DetailLabel.Render("Narrative:"),
	}

	var narrative string
	if m.editing {
		narrative = m.editor.View()
	} else {
		narrative = m.narrative.View()
	}

	footer := fmt.Sprintf("Evidence: %d events        [r] view raw", len(f.EventIDs))

	return strings.Join(append(lines, narrative, "", footer), "\n")
}

func (m Model) renderEvidencePane(w, h int) string {
	f, ok := m.selectedFinding()
	if !ok {
		return ""
	}

	top := fmt.Sprintf("RAW EVIDENCE — %s", f.Title)
	return strings.Join([]string{S.PaneTitle.Render(top), "", m.evidence.View()}, "\n")
}

func (m Model) renderStatusBar() string {
	hints := "[a]pprove  [e]dit  [d]iscard  [m]erge  [r]aw  [x]export  [?]  [q]quit"
	if m.editing {
		hints = "[ctrl+s] save  [esc] save  [?]  [q] quit"
	}

	left := hints
	if m.statusMsg != "" {
		left = hints + "  •  " + m.statusMsg
	}
	if len(left) > m.width-2 {
		left = left[:m.width-5] + "..."
	}
	return S.StatusBar.Width(m.width).Render(left)
}

func (m Model) renderHelp() string {
	help := strings.Join([]string{
		"Keys:",
		"  j/↓   next finding",
		"  k/↑   prev finding",
		"  tab   cycle focus",
		"  a     approve",
		"  d     discard",
		"  e     edit narrative",
		"  m     merge with next",
		"  r     toggle raw evidence",
		"  s     cycle severity",
		"  x     export approved",
		"  ?     toggle help",
		"  q     quit",
		"",
		"Edit mode:",
		"  esc / ctrl+s  save + exit",
	}, "\n")
	return S.HelpOverlay.Render(help)
}

func (m *Model) selectedFinding() (store.Finding, bool) {
	idx := m.list.Index()
	if idx < 0 || idx >= len(m.findings) {
		return store.Finding{}, false
	}
	return m.findings[idx], true
}

func (m *Model) refreshDetail() {
	f, ok := m.selectedFinding()
	if !ok {
		m.narrative.SetContent("")
		return
	}
	w := m.narrative.Width
	if w <= 0 {
		w = 60
	}
	wrapped := lipgloss.NewStyle().Width(w).Render(strings.TrimSpace(f.Narrative))
	m.narrative.SetContent(wrapped)
	m.list.SetDelegate(findingDelegate{m: m})
}

func (m *Model) refreshEvidence() {
	if !m.showEvidence {
		return
	}
	f, ok := m.selectedFinding()
	if !ok {
		m.evidence.SetContent("")
		return
	}
	lines, err := m.session.LoadEventTexts(f.EventIDs)
	if err != nil {
		m.evidence.SetContent(err.Error())
		return
	}
	m.evidence.SetContent(strings.Join(lines, "\n"))
}

func (m *Model) startEditing() {
	f, ok := m.selectedFinding()
	if !ok {
		return
	}
	m.editing = true
	m.quitConfirm = false
	m.editor.SetValue(f.Narrative)
	m.editor.CursorEnd()
	m.editor.Focus()
}

func (m *Model) hasUnsavedChanges() bool {
	return m.editing
}

func (m Model) saveEditCmd(exit bool) tea.Cmd {
	f, ok := m.selectedFinding()
	if !ok {
		return nil
	}
	narr := m.editor.Value()
	f.Narrative = narr

	return func() tea.Msg {
		if err := m.session.UpdateFinding(f); err != nil {
			return errMsg{err: err}
		}
		return findingUpdatedMsg{finding: f}
	}
}

func (m Model) setStatus(st store.FindingStatus) tea.Cmd {
	f, ok := m.selectedFinding()
	if !ok {
		return nil
	}
	f.Status = st
	return func() tea.Msg {
		if err := m.session.UpdateFinding(f); err != nil {
			return errMsg{err: err}
		}
		return findingUpdatedMsg{finding: f}
	}
}

func (m Model) cycleSeverity() tea.Cmd {
	f, ok := m.selectedFinding()
	if !ok {
		return nil
	}
	f.Severity = (f.Severity + 1) % 5
	return func() tea.Msg {
		if err := m.session.UpdateFinding(f); err != nil {
			return errMsg{err: err}
		}
		return findingUpdatedMsg{finding: f}
	}
}

func (m Model) mergeWithNext() tea.Cmd {
	idx := m.list.Index()
	if idx < 0 || idx >= len(m.findings)-1 {
		return nil
	}
	cur := m.findings[idx]
	nxt := m.findings[idx+1]

	if strings.TrimSpace(nxt.Narrative) != "" {
		if strings.TrimSpace(cur.Narrative) != "" {
			cur.Narrative = strings.TrimSpace(cur.Narrative) + "\n\n" + strings.TrimSpace(nxt.Narrative)
		} else {
			cur.Narrative = nxt.Narrative
		}
	}
	cur.EventIDs = append(cur.EventIDs, nxt.EventIDs...)
	// Keep highest severity
	if nxt.Severity > cur.Severity {
		cur.Severity = nxt.Severity
	}
	// Mark next as discarded (we have no delete API this iteration)
	nxt.Status = store.StatusDiscarded

	return func() tea.Msg {
		if err := m.session.UpdateFinding(cur); err != nil {
			return errMsg{err: err}
		}
		_ = m.session.UpdateFinding(nxt)
		return findingUpdatedMsg{finding: cur}
	}
}

func (m Model) exportApprovedCmd() tea.Cmd {
	return func() tea.Msg {
		jp, mp, err := ExportApproved(m.sessionMeta.ID, m.findings)
		if err != nil {
			return errMsg{err: err}
		}
		return exportDoneMsg{jsonPath: jp, mdPath: mp}
	}
}

// Run launches the Bubbletea program.
func Run(db *store.DB, meta store.SessionMeta, findings []store.Finding) error {
	p := tea.NewProgram(NewModel(db, meta, findings), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// Satisfy unused import guard for key; list delegate expects it.
var _ = key.NewBinding
