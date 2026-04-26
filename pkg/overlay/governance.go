package overlay

import (
	"fmt"
	"log/slog"
	"sync"
)

// GovernanceState represents the current governance state of the shard.
type GovernanceState int

const (
	// GovernanceActive means the shard is operating normally.
	GovernanceActive GovernanceState = iota
	// GovernanceFrozen means the shard is frozen by a governance key.
	GovernanceFrozen
	// GovernanceUpgrading means the shard is undergoing a covenant upgrade.
	GovernanceUpgrading
)

// String returns the string representation of a GovernanceState.
func (s GovernanceState) String() string {
	switch s {
	case GovernanceActive:
		return "active"
	case GovernanceFrozen:
		return "frozen"
	case GovernanceUpgrading:
		return "upgrading"
	default:
		return "unknown"
	}
}

// GovernanceMonitor watches for governance state changes from the BSV
// covenant and applies them to the overlay node. It handles freeze,
// unfreeze, and upgrade events.
type GovernanceMonitor struct {
	mu    sync.Mutex
	node  *OverlayNode
	state GovernanceState
}

// NewGovernanceMonitor creates a new GovernanceMonitor for the given
// overlay node.
func NewGovernanceMonitor(node *OverlayNode) *GovernanceMonitor {
	return &GovernanceMonitor{
		node:  node,
		state: GovernanceActive,
	}
}

// State returns the current governance state.
func (gm *GovernanceMonitor) State() GovernanceState {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.state
}

// HandleGovernanceFreeze processes a governance freeze event. When
// the shard is frozen, the batcher is paused and no new batches are
// produced. Existing speculative state is retained.
func (gm *GovernanceMonitor) HandleGovernanceFreeze() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.state == GovernanceFrozen {
		return // already frozen
	}

	gm.state = GovernanceFrozen

	// Pause the batcher to stop accepting new transactions.
	if gm.node != nil && gm.node.batcher != nil {
		gm.node.batcher.Pause("covenant frozen by governance")
	}

	slog.Info("governance freeze applied: batcher paused, no new batches will be produced")
}

// HandleGovernanceUnfreeze processes a governance unfreeze event.
// The batcher is resumed and normal operation continues.
func (gm *GovernanceMonitor) HandleGovernanceUnfreeze() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.state != GovernanceFrozen {
		return // not frozen
	}

	gm.state = GovernanceActive

	// Resume the batcher.
	if gm.node != nil && gm.node.batcher != nil {
		gm.node.batcher.Resume()
	}

	slog.Info("governance unfreeze applied: batcher resumed, normal operation restored")
}

// HandleGovernanceUpgrade processes a governance upgrade event. The
// shard must be frozen before an upgrade can be applied. During upgrade,
// both the batcher and the prover are suspended.
func (gm *GovernanceMonitor) HandleGovernanceUpgrade(newScriptHash [32]byte) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.state != GovernanceFrozen {
		slog.Warn("governance upgrade rejected: shard must be frozen before upgrade")
		return
	}

	gm.state = GovernanceUpgrading

	slog.Info("governance upgrade initiated",
		"newScriptHash", fmt.Sprintf("%x", newScriptHash),
	)
}
