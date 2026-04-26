package overlay

import "sync"

// nodeGovernanceMonitors stores per-OverlayNode GovernanceMonitor
// instances side-channel of the node struct. Wiring it through a
// package-level map (rather than as an OverlayNode field) keeps the
// freeze watcher self-contained: it can attach a monitor to any node
// without modifying node.go and surviving concurrent edits to that
// file. The map is keyed by pointer identity so each overlay node
// gets its own monitor; entries are cleared by ClearGovernanceMonitor.
var (
	nodeGovernanceMonitorsMu sync.Mutex
	nodeGovernanceMonitors   = make(map[*OverlayNode]*GovernanceMonitor)
)

// GovernanceMonitor returns the monitor associated with this overlay
// node, lazily constructing one on first access. The monitor is the
// surface used by the freeze watcher and tests to express frozen /
// active / upgrading transitions to the batcher.
//
// The reverse lookup (rather than a direct field) is deliberately
// scoped to this file so the OverlayNode struct does not need an
// extra field — each lookup is O(1) on the map and the lock contention
// is negligible because the map is hit only on freeze events and
// startup.
func (n *OverlayNode) GovernanceMonitor() *GovernanceMonitor {
	if n == nil {
		return nil
	}
	nodeGovernanceMonitorsMu.Lock()
	defer nodeGovernanceMonitorsMu.Unlock()
	if gm, ok := nodeGovernanceMonitors[n]; ok {
		return gm
	}
	gm := NewGovernanceMonitor(n)
	nodeGovernanceMonitors[n] = gm
	return gm
}

// ClearGovernanceMonitor removes the cached monitor for the given
// node. Tests use this to start each subtest with a fresh monitor and
// avoid leaking state between cases.
func ClearGovernanceMonitor(n *OverlayNode) {
	if n == nil {
		return
	}
	nodeGovernanceMonitorsMu.Lock()
	defer nodeGovernanceMonitorsMu.Unlock()
	delete(nodeGovernanceMonitors, n)
}
