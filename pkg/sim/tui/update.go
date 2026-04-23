package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/sim"
)

// Update handles Bubble Tea messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.tick(), m.refresh())

	case statsMsg:
		m.stats = sim.EngineStats(msg)
		m.clampSelection()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case keyMatches(msg, m.keys.Quit):
		m.cancel()
		return m, tea.Quit
	case keyMatches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
		return m, nil
	case keyMatches(msg, m.keys.TabCycle):
		m.focus = (m.focus + 1) % 3
		return m, nil
	case keyMatches(msg, m.keys.Up):
		m.moveSelection(-1)
		return m, nil
	case keyMatches(msg, m.keys.Down):
		m.moveSelection(1)
		return m, nil
	case keyMatches(msg, m.keys.UserAdd):
		return m, m.addUserCmd()
	case keyMatches(msg, m.keys.UserDrop):
		return m, m.dropUserCmd()
	case keyMatches(msg, m.keys.WorkloadTog):
		return m, m.toggleWorkloadCmd()
	case keyMatches(msg, m.keys.RateUp):
		return m, m.adjustRateCmd(1)
	case keyMatches(msg, m.keys.RateDown):
		return m, m.adjustRateCmd(-1)
	case keyMatches(msg, m.keys.RateUpBig):
		return m, m.adjustRateCmd(10)
	case keyMatches(msg, m.keys.RateDownBig):
		return m, m.adjustRateCmd(-10)
	case keyMatches(msg, m.keys.Pause):
		return m, m.pauseAllCmd()
	case keyMatches(msg, m.keys.Resume):
		return m, m.resumeAllCmd()
	}
	return m, nil
}

func (m *Model) moveSelection(delta int) {
	switch m.focus {
	case PanelWorkloads:
		m.workloadIdx += delta
	case PanelUsers:
		m.userIdx += delta
	}
	m.clampSelection()
}

func (m *Model) clampSelection() {
	if m.workloadIdx < 0 {
		m.workloadIdx = 0
	}
	if n := len(m.stats.Workloads); m.workloadIdx >= n && n > 0 {
		m.workloadIdx = n - 1
	}
	if m.userIdx < 0 {
		m.userIdx = 0
	}
	if n := m.stats.Users; m.userIdx >= n && n > 0 {
		m.userIdx = n - 1
	}
}

// selectedWorkload returns the currently highlighted workload or nil.
func (m *Model) selectedWorkload() *sim.WorkloadStats {
	if m.workloadIdx < 0 || m.workloadIdx >= len(m.stats.Workloads) {
		return nil
	}
	return &m.stats.Workloads[m.workloadIdx]
}

// Command builders — each returns a tea.Cmd that runs on the UI queue
// so the engine mutation stays off the UI goroutine.

func (m *Model) addUserCmd() tea.Cmd {
	engine := m.engine
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 30*1e9) // 30s
		defer cancel()
		fund := new(uint256.Int).Lsh(uint256.NewInt(1), 60)
		_, _ = engine.AddUser(ctx, fund)
		return statsMsg(engine.EngineStats())
	}
}

func (m *Model) dropUserCmd() tea.Cmd {
	engine := m.engine
	users := engine.Pool.Users()
	if len(users) == 0 {
		return nil
	}
	idx := m.userIdx
	if idx >= len(users) {
		idx = len(users) - 1
	}
	id := users[idx].ID
	return func() tea.Msg {
		engine.RemoveUser(id)
		return statsMsg(engine.EngineStats())
	}
}

func (m *Model) toggleWorkloadCmd() tea.Cmd {
	w := m.selectedWorkload()
	if w == nil {
		return nil
	}
	engine := m.engine
	kind := w.Kind
	running := w.Running
	return func() tea.Msg {
		if running {
			_ = engine.Reg.Stop(kind)
		} else {
			_ = engine.Reg.Start(m.ctx, kind)
		}
		return statsMsg(engine.EngineStats())
	}
}

func (m *Model) adjustRateCmd(delta int) tea.Cmd {
	w := m.selectedWorkload()
	if w == nil {
		return nil
	}
	engine := m.engine
	kind := w.Kind
	newRate := w.Rate + delta
	if newRate < 0 {
		newRate = 0
	}
	return func() tea.Msg {
		_ = engine.Reg.SetRate(kind, newRate)
		return statsMsg(engine.EngineStats())
	}
}

func (m *Model) pauseAllCmd() tea.Cmd {
	engine := m.engine
	return func() tea.Msg {
		for _, s := range engine.Reg.Snapshot() {
			if s.Running {
				_ = engine.Reg.Stop(s.Kind)
			}
		}
		return statsMsg(engine.EngineStats())
	}
}

func (m *Model) resumeAllCmd() tea.Cmd {
	engine := m.engine
	return func() tea.Msg {
		for _, s := range engine.Reg.Snapshot() {
			if !s.Running {
				_ = engine.Reg.Start(m.ctx, s.Kind)
			}
		}
		return statsMsg(engine.EngineStats())
	}
}

func keyMatches(k tea.KeyMsg, b interface{ Keys() []string }) bool {
	pressed := k.String()
	for _, bind := range b.Keys() {
		if bind == pressed {
			return true
		}
	}
	return false
}
