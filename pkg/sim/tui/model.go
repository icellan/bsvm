package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/icellan/bsvm/pkg/sim"
)

// Panel enumerates the focusable sections of the TUI.
type Panel int

const (
	PanelNodes Panel = iota
	PanelWorkloads
	PanelUsers
)

func (p Panel) String() string {
	switch p {
	case PanelNodes:
		return "Nodes"
	case PanelWorkloads:
		return "Workloads"
	case PanelUsers:
		return "Users"
	}
	return "?"
}

// Model is the root Bubble Tea model for the simulator TUI.
type Model struct {
	ctx    context.Context
	cancel context.CancelFunc

	engine *sim.Engine
	keys   KeyMap

	// Snapshot of engine state (refreshed on tick).
	stats sim.EngineStats

	// Focus + selection state.
	focus        Panel
	workloadIdx  int
	userIdx      int
	showHelp     bool
	width, height int

	// Workload start/stop palette (kind -> running).
	allKinds []sim.WorkloadKind
}

// NewModel builds the root model. `ctx` is used to drive the tick goroutine;
// cancel via m.Quit.
func NewModel(ctx context.Context, engine *sim.Engine) *Model {
	wctx, wcancel := context.WithCancel(ctx)
	return &Model{
		ctx:    wctx,
		cancel: wcancel,
		engine: engine,
		keys:   DefaultKeyMap(),
		focus:  PanelWorkloads,
		allKinds: []sim.WorkloadKind{
			sim.KindValueTransfer,
			sim.KindERC20Transfer,
			sim.KindStorageSet,
			sim.KindERC721Mint,
			sim.KindWETHCycle,
			sim.KindAMMSwap,
			sim.KindMultisig,
		},
	}
}

// statsMsg carries a refreshed engine snapshot into the TUI loop.
type statsMsg sim.EngineStats

// tickMsg fires every refreshInterval to request a new snapshot.
type tickMsg time.Time

const refreshInterval = 250 * time.Millisecond

// Init starts the refresh ticker.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.tick(), m.refresh())
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) refresh() tea.Cmd {
	return func() tea.Msg {
		return statsMsg(m.engine.EngineStats())
	}
}
