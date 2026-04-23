package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap is the TUI's complete command surface. Help text surfaces via
// the `help` bubble in the footer.
type KeyMap struct {
	Quit         key.Binding
	Help         key.Binding
	TabCycle     key.Binding
	UserAdd      key.Binding
	UserDrop     key.Binding
	WorkloadTog  key.Binding
	RateUp       key.Binding
	RateDown     key.Binding
	RateUpBig    key.Binding
	RateDownBig  key.Binding
	Pause        key.Binding
	Resume       key.Binding
	Up           key.Binding
	Down         key.Binding
}

// DefaultKeyMap constructs the keymap used by the simulator TUI.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		TabCycle:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "cycle panel")),
		UserAdd:     key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add user")),
		UserDrop:    key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "drop user")),
		WorkloadTog: key.NewBinding(key.WithKeys("w"), key.WithHelp("w", "start/stop workload")),
		RateUp:      key.NewBinding(key.WithKeys("+", "="), key.WithHelp("+", "rate +1")),
		RateDown:    key.NewBinding(key.WithKeys("-"), key.WithHelp("-", "rate -1")),
		RateUpBig:   key.NewBinding(key.WithKeys("]"), key.WithHelp("]", "rate +10")),
		RateDownBig: key.NewBinding(key.WithKeys("["), key.WithHelp("[", "rate -10")),
		Pause:       key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause all")),
		Resume:      key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "resume all")),
		Up:          key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:        key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.UserAdd, k.UserDrop, k.WorkloadTog, k.RateUp, k.RateDown, k.Pause, k.Resume, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap (full help view).
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.UserAdd, k.UserDrop, k.WorkloadTog},
		{k.RateUp, k.RateDown, k.RateUpBig, k.RateDownBig},
		{k.Pause, k.Resume, k.TabCycle},
		{k.Up, k.Down, k.Help, k.Quit},
	}
}
