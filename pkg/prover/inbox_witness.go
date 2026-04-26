// Package prover — inbox drain witness construction (W4-3, spec 10/11/12).
//
// The on-chain inbox is an append-only hash chain of EVM transactions
// (`pkg/covenant/contracts/inbox.runar.go`). The SP1 guest needs to verify
// that a batch's `inboxRootBefore` public value matches the actual on-chain
// inbox state and recompute `inboxRootAfter` from the carry-forward
// remainder. To do that without trusting the host, the guest needs the
// FULL ordered queue contents — not just the drained subset.
//
// This file defines:
//   - `InboxQueuedTx`: per-tx witness entry shipped to the guest.
//   - `BuildInboxWitness`: helper that converts an `InboxMonitor` snapshot
//     plus a Go-side block of pre-decoded transactions into the witness
//     fields the guest reads.
//   - `InboxChainRoot` / `EmptyInboxRoot`: chain-hash helpers — must stay
//     byte-identical to the Rust `inbox::chain_root` / `empty_inbox_root`
//     in `prover/guest/src/inbox.rs`. Tested for parity with InboxMonitor.

package prover

import (
	"crypto/sha256"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// InboxQueuedTx is one entry in the inbox witness shipped to the SP1
// guest. RawTxRLP is what the on-chain inbox covenant hashed (the
// `evmTxRLP` parameter of the inbox `submit` call); the guest re-hashes
// it to recompute the chain root. Tx is the host-decoded EVM tx fields
// the guest needs to apply through revm — sender recovery is the host's
// responsibility (see W4-2).
type InboxQueuedTx struct {
	// RawTxRLP is the canonical RLP-encoded EVM transaction bytes that
	// were submitted to the on-chain inbox covenant. The guest computes
	// hash256(RawTxRLP) and folds it into the chain.
	RawTxRLP []byte `json:"raw_tx_rlp"`
}

// EmptyInboxRoot returns the genesis empty-chain marker:
// hash256(zeros(32)). Matches `pkg/covenant/inbox_state.go::EmptyInboxState`
// and `pkg/overlay/inbox_monitor.go::NewInboxMonitor`. Mirrors the Rust
// guest's `inbox::empty_inbox_root`.
func EmptyInboxRoot() types.Hash {
	return inboxHash256(make([]byte, 32))
}

// InboxChainRoot computes the inbox hash chain root over an ordered
// sequence of raw EVM tx RLP bytes:
//
//	root_0    = hash256(zeros(32))
//	root_n+1  = hash256(root_n || hash256(tx_n_RLP))
//
// Mirrors the Rust guest's `inbox::chain_root` byte-for-byte.
func InboxChainRoot(rawTxRLPs [][]byte) types.Hash {
	root := EmptyInboxRoot()
	buf := make([]byte, 64)
	for _, rlp := range rawTxRLPs {
		leaf := inboxHash256(rlp)
		copy(buf[0:32], root[:])
		copy(buf[32:64], leaf[:])
		root = inboxHash256(buf)
	}
	return root
}

// inboxHash256 computes BSV's hash256 (double-SHA256) over the input.
func inboxHash256(data []byte) types.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}

// BuildInboxWitness wraps a list of raw inbox tx RLPs (typically
// `InboxMonitor.PendingTxsSnapshot()` — see helper below) into the
// witness shape the SP1 guest expects, and returns the chain root the
// host should claim as `inbox_root_before`.
//
// `drainCount` is how many leading entries this batch will consume; the
// caller is responsible for ensuring those same `drainCount` txs are
// also present at the head of the executed user tx list (the overlay
// node prepends them in `ProcessBatch`).
//
// Returns:
//   - witness:   the InboxQueuedTx slice for ProveInput.InboxQueue.
//   - rootBefore: the chain root over the FULL queue (claimed value).
//   - rootAfter:  the chain root after draining the leading `drainCount`
//                 entries — `EmptyInboxRoot()` if all drained, else the
//                 chain over the trailing remainder.
//   - err: only when `drainCount` exceeds `len(rawQueue)`.
func BuildInboxWitness(rawQueue [][]byte, drainCount uint32) (
	witness []InboxQueuedTx,
	rootBefore types.Hash,
	rootAfter types.Hash,
	err error,
) {
	if int(drainCount) > len(rawQueue) {
		return nil, types.Hash{}, types.Hash{}, fmt.Errorf(
			"inbox drain count %d exceeds queue length %d", drainCount, len(rawQueue))
	}
	witness = make([]InboxQueuedTx, len(rawQueue))
	for i, rlp := range rawQueue {
		cp := make([]byte, len(rlp))
		copy(cp, rlp)
		witness[i] = InboxQueuedTx{RawTxRLP: cp}
	}
	rootBefore = InboxChainRoot(rawQueue)
	if int(drainCount) == len(rawQueue) {
		rootAfter = EmptyInboxRoot()
	} else {
		rootAfter = InboxChainRoot(rawQueue[drainCount:])
	}
	return witness, rootBefore, rootAfter, nil
}
