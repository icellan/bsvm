package prover

// Dual-EVM equivalence comparator — Go side.
//
// This file is the Go counterpart to `prover/host-revm` (the Rust
// post-state exporter). It serves a single purpose now that the Rust
// binary emits both the structural digest *and* a full account map:
//
//   Re-derive the canonical Ethereum MPT root from the Rust side's
//   post-state map (`BuildPostStateRoot`). The implementation opens
//   a fresh `pkg/state.StateDB` rooted at types.Hash{}, walks the
//   accounts, applies nonce / balance / code / each non-zero storage
//   slot, and calls `Commit(true)` — exactly the path `pkg/state`
//   uses to derive its own post-execution root from genesis. If both
//   EVMs are equivalent over the supplied account set, the two roots
//   match byte-for-byte.
//
// Wire-format alignment:
//
//   `RevmPostState` and `RevmPostAccount` mirror the JSON tags emitted
//   by `prover/host-revm/src/lib.rs::HostOutput::accounts` (the
//   `AccountSnapshot` / `StorageSlotSnapshot` types). Drift between
//   the two sides breaks the comparator silently — bumps require a
//   parallel bump in lib.rs. The harness invokes the binary directly
//   via `runHostRevm` (in equivalence_test.go) and unmarshals into
//   `hostRevmOutput`; that struct embeds the same shape and feeds
//   `BuildPostStateRoot` after each fixture.
//
// History:
//
//   - The original DD scaffold (round-4) defined a parallel
//     `runHostRevmComparator` + `RevmComparatorInput` envelope on the
//     assumption a separate "comparator" binary would emit a richer
//     post-state. That binary never landed; instead Z's host-revm
//     was extended in-place to emit `accounts: Vec<AccountSnapshot>`,
//     so the parallel envelope was redundant and got removed. The
//     harness uses `runHostRevm` (in equivalence_test.go) for the
//     subprocess hop and `BuildPostStateRoot` here for the MPT
//     reconstruction.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// RevmComparatorBinaryEnv is the env var the test harness reads to
// locate the prover/host-revm binary. When unset, the comparator path
// is skipped with an informative message rather than failing — this
// keeps CI green on machines that haven't built the Rust binary.
const RevmComparatorBinaryEnv = "BSVM_HOST_REVM_BINARY"

// RevmPostState is the post-execution account map exported by the
// host-revm binary. It mirrors the `accounts` slice on
// `prover/host-revm/src/lib.rs::HostOutput` — the structural digest
// + receipts hash + per-tx gas live elsewhere on the same envelope and
// are read directly by the harness.
//
// `BuildPostStateRoot` consumes a `RevmPostState` whose `Accounts`
// list comes from JSON-unmarshalling the Rust binary's output. The
// other fields on this struct are reserved for future cross-checks;
// the canonical-root path uses `Accounts` only.
type RevmPostState struct {
	Accounts []RevmPostAccount `json:"accounts"`
}

// RevmPostAccount is one account in the post-state export.
//
// JSON tags mirror `prover/host-revm/src/lib.rs::AccountSnapshot`
// exactly. Drift between the two breaks the comparator silently.
type RevmPostAccount struct {
	Address  string                `json:"address"`
	Nonce    uint64                `json:"nonce"`
	Balance  string                `json:"balance"`
	CodeHash string                `json:"code_hash"`
	Code     string                `json:"code,omitempty"`
	Storage  []RevmPostStorageSlot `json:"storage,omitempty"`
}

// RevmPostStorageSlot is one storage slot in the post-state export.
type RevmPostStorageSlot struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// IsEmpty reports whether the post-state export has no account
// entries. The harness uses this as a quick gate before calling
// `BuildPostStateRoot`: an empty list means the Rust binary skipped
// snapshot emission (e.g. an envelope-shape error path) and the MPT
// root comparison should be deferred rather than treated as success.
func (r *RevmPostState) IsEmpty() bool {
	return r == nil || len(r.Accounts) == 0
}

// BuildPostStateRoot re-derives the canonical Ethereum MPT root from
// the Rust comparator's post-state map. It opens a fresh StateDB
// against an empty database, applies each account and storage slot
// from `post`, and calls `Commit(true)` — the same path
// `pkg/state.StateDB` uses to compute its own post-execution root.
//
// The returned hash is the MPT root over the supplied accounts; the
// caller compares it byte-for-byte to the Go EVM's own postStateRoot
// derived via `IntermediateRoot(true)` after `ProcessBatch`.
//
// `extra` lets the caller seed accounts that were present in genesis
// but never touched by the batch (so they don't appear in revm's
// post-state cache). Without this the MPT roots would diverge for
// any batch that doesn't touch every genesis account: the Go EVM's
// trie holds them, the comparator's reconstruction wouldn't.
func BuildPostStateRoot(post *RevmPostState, extra []RevmPostAccount) (root types.Hash, digest types.Hash, err error) {
	if post == nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("BuildPostStateRoot: nil post-state")
	}

	memdb := db.NewMemoryDB()
	sdb, err := state.New(types.Hash{}, memdb)
	if err != nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("open fresh StateDB: %w", err)
	}

	apply := func(prefix string, accounts []RevmPostAccount) error {
		for i, a := range accounts {
			addr, err := parseAddressHex(a.Address)
			if err != nil {
				return fmt.Errorf("%s[%d] address: %w", prefix, i, err)
			}
			balance, err := parseUint256Hex(a.Balance)
			if err != nil {
				return fmt.Errorf("%s[%d] balance: %w", prefix, i, err)
			}
			code, err := parseHexBytes(a.Code)
			if err != nil {
				return fmt.Errorf("%s[%d] code: %w", prefix, i, err)
			}

			// CreateAccount first so the account exists, then
			// balance/nonce/code, then storage. Empty accounts are
			// handled by EIP-161 in Commit(deleteEmptyObjects=true).
			if !sdb.Exist(addr) {
				sdb.CreateAccount(addr)
			}
			sdb.SetBalance(addr, balance)
			sdb.SetNonce(addr, a.Nonce, tracing.NonceChangeUnspecified)
			if len(code) > 0 {
				sdb.SetCode(addr, code, tracing.CodeChangeUnspecified)
			}
			for j, slot := range a.Storage {
				key, err := parseHashHex(slot.Key)
				if err != nil {
					return fmt.Errorf("%s[%d] storage[%d] key: %w", prefix, i, j, err)
				}
				value, err := parseHashHex(slot.Value)
				if err != nil {
					return fmt.Errorf("%s[%d] storage[%d] value: %w", prefix, i, j, err)
				}
				sdb.SetState(addr, key, value)
			}
		}
		return nil
	}
	if err := apply("account", post.Accounts); err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	if err := apply("extra", extra); err != nil {
		return types.Hash{}, types.Hash{}, err
	}

	root, err = sdb.Commit(true)
	if err != nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("commit StateDB: %w", err)
	}
	digest = StructuralDigest(post.Accounts)
	return root, digest, nil
}

// StructuralDigest computes a SHA256 over a canonical encoding of the
// post-state account map. It mirrors the Rust side's
// `bsvm_host_revm::compute_post_state_digest` shape (sans the
// digest_addresses / digest_storage_keys filtering — this helper
// hashes the full account list verbatim).
//
// Encoding (per account, in input order):
//
//	address[20] || nonce[8 BE] || balance[32 BE] || code_hash[32]
//	|| u32-BE storage-count || (key[32] || value[32])* in input order
//
// Callers should pass `accounts` already sorted by address ascending
// (the host-revm binary does this).
func StructuralDigest(accounts []RevmPostAccount) types.Hash {
	h := sha256.New()
	var u64buf [8]byte
	var u32buf [4]byte
	for _, a := range accounts {
		addr, _ := parseAddressHex(a.Address)
		h.Write(addr[:])

		binary.BigEndian.PutUint64(u64buf[:], a.Nonce)
		h.Write(u64buf[:])

		balance, _ := parseUint256Hex(a.Balance)
		balBE := balance.Bytes32()
		h.Write(balBE[:])

		codeHash, _ := parseHashHex(a.CodeHash)
		h.Write(codeHash[:])

		binary.BigEndian.PutUint32(u32buf[:], uint32(len(a.Storage)))
		h.Write(u32buf[:])

		for _, slot := range a.Storage {
			key, _ := parseHashHex(slot.Key)
			val, _ := parseHashHex(slot.Value)
			h.Write(key[:])
			h.Write(val[:])
		}
	}
	var out types.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// SortAccountsForDigest sorts accounts ascending by address. The Rust
// host-revm binary already emits sorted output, but call this on any
// locally-built RevmPostState before computing the structural digest.
func SortAccountsForDigest(accounts []RevmPostAccount) {
	sort.SliceStable(accounts, func(i, j int) bool {
		return strings.ToLower(accounts[i].Address) < strings.ToLower(accounts[j].Address)
	})
}

// --- hex parsing helpers ---

func parseAddressHex(s string) (types.Address, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 40 {
		return types.Address{}, fmt.Errorf("address must be 20 bytes (40 hex chars), got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Address{}, fmt.Errorf("address hex: %w", err)
	}
	var out types.Address
	copy(out[:], b)
	return out, nil
}

func parseHashHex(s string) (types.Hash, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 64 {
		return types.Hash{}, fmt.Errorf("hash must be 32 bytes (64 hex chars), got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, fmt.Errorf("hash hex: %w", err)
	}
	var out types.Hash
	copy(out[:], b)
	return out, nil
}

func parseUint256Hex(s string) (*uint256.Int, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if s == "" {
		return uint256.NewInt(0), nil
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("u256 hex: %w", err)
	}
	if len(b) > 32 {
		return nil, fmt.Errorf("u256 overflow: %d bytes", len(b))
	}
	bi := new(big.Int).SetBytes(b)
	out, overflow := uint256.FromBig(bi)
	if overflow {
		return nil, fmt.Errorf("u256 overflow on parse")
	}
	return out, nil
}

func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
