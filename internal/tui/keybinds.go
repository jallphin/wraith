package tui

import "github.com/charmbracelet/bubbles/key"

type KeyMap struct {
	Next     key.Binding
	Prev     key.Binding
	Cycle    key.Binding
	Approve  key.Binding
	Discard  key.Binding
	Edit     key.Binding
	Merge    key.Binding
	Raw      key.Binding
	Severity key.Binding
	Export   key.Binding
	Help     key.Binding
	Quit     key.Binding

	SaveExit key.Binding
	Esc      key.Binding
}

var Keys = NewKeyMap()

func NewKeyMap() KeyMap {
	return KeyMap{
		Next: key.NewBinding(
			key.WithKeys("j", "down"),
			key.WithHelp("j/↓", "next"),
		),
		Prev: key.NewBinding(
			key.WithKeys("k", "up"),
			key.WithHelp("k/↑", "prev"),
		),
		Cycle: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "focus"),
		),
		Approve: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "approve"),
		),
		Discard: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "discard"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Merge: key.NewBinding(
			key.WithKeys("m"),
			key.WithHelp("m", "merge"),
		),
		Raw: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "raw"),
		),
		Severity: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "severity"),
		),
		Export: key.NewBinding(
			key.WithKeys("x"),
			key.WithHelp("x", "export"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),

		SaveExit: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "save"),
		),
		Esc: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "save"),
		),
	}
}
