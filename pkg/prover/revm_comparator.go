package prover

// Dual-EVM equivalence comparator — Go side.
//
// This file is the Go counterpart to `prover/host-revm` (the Rust
// post-state exporter). It does three things:
//
//  1. Defines the JSON wire shape that BOTH sides agree on. The Rust
//     side mirrors these in `prover/host-revm/src/lib.rs::ComparatorOutput`;
//     drift between the two breaks the comparator silently, so the
//     fields here are kept thin and version-pinned. Bumping a wire
//     field here requires a parallel bump in lib.rs.
//
//  2. Runs the Rust comparator binary as a subprocess (`runHostRevm`)
//     when the operator has set BSVM_HOST_REVM_BINARY. The default
//     CI build of host-revm is schema-only (no revm) so the binary
//     emits an empty post-state; `RevmPostState.IsEmpty()` lets the
//     test harness skip the canonical-root comparison without flagging
//     it as a failure.
//
//  3. Re-derives the canonical Ethereum MPT root from the Rust side's
//     post-state map (`BuildPostStateRoot`). The implementation opens
//     a fresh `pkg/state.StateDB` rooted at types.Hash{}, walks the
//     accounts, applies nonce / balance / code / each storage slot,
//     and calls `Commit` — exactly the path the Go EVM uses internally
//     to derive its own post-state root. If both EVMs are equivalent,
//     the two roots match byte-for-byte. This closes Z's open follow-
//     up #3: structural-digest-only comparison is upgraded to canonical
//     MPT-root comparison.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
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

// RevmComparatorInput is the JSON envelope passed on stdin to the
// host-revm binary. It mirrors `ComparatorInput` in
// `prover/host-revm/src/lib.rs` field-for-field. Bumping a field here
// requires a matching bump in lib.rs.
type RevmComparatorInput struct {
	PreStateRoot string                 `json:"pre_state_root"`
	Accounts     []RevmInputAccount     `json:"accounts"`
	Transactions []RevmInputTransaction `json:"transactions"`
	BlockContext RevmInputBlockContext  `json:"block_context"`
	ChainID      uint64                 `json:"chain_id"`
}

// RevmInputAccount is the wire form of one pre-state account.
type RevmInputAccount struct {
	Address      string                 `json:"address"`
	Nonce        uint64                 `json:"nonce"`
	Balance      string                 `json:"balance"`
	CodeHash     string                 `json:"code_hash"`
	StorageRoot  string                 `json:"storage_root,omitempty"`
	Code         string                 `json:"code,omitempty"`
	StorageSlots []RevmInputStorageSlot `json:"storage_slots,omitempty"`
	AccountProof []string               `json:"account_proof,omitempty"`
}

// RevmInputStorageSlot is the wire form of one pre-state storage slot.
type RevmInputStorageSlot struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof,omitempty"`
}

// RevmInputTransaction carries the canonical RLP-encoded transaction
// the Rust side decodes via alloy_consensus.
type RevmInputTransaction struct {
	RawBytes string `json:"raw_bytes"`
}

// RevmInputBlockContext is the wire form of the block-level params.
type RevmInputBlockContext struct {
	Number     uint64 `json:"number"`
	Timestamp  uint64 `json:"timestamp"`
	Coinbase   string `json:"coinbase"`
	GasLimit   uint64 `json:"gas_limit"`
	BaseFee    uint64 `json:"base_fee"`
	PrevRandao string `json:"prev_randao,omitempty"`
}

// RevmPostState is the JSON envelope the host-revm binary writes to
// stdout. It mirrors `ComparatorOutput` in
// `prover/host-revm/src/lib.rs` field-for-field.
type RevmPostState struct {
	PreStateRoot     string            `json:"pre_state_root"`
	Accounts         []RevmPostAccount `json:"accounts"`
	Receipts         []RevmPostReceipt `json:"receipts"`
	GasUsed          uint64            `json:"gas_used"`
	StructuralDigest string            `json:"structural_digest"`
}

// RevmPostAccount is one account in the post-state export.
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

// RevmPostReceipt is one tx receipt in the post-state export.
type RevmPostReceipt struct {
	Status  uint8  `json:"status"`
	GasUsed uint64 `json:"gas_used"`
}

// IsEmpty reports whether the host-revm binary produced a stub envelope
// (schema-only build) rather than a real post-state. The schema-only
// build emits an empty `Accounts` list and zero `GasUsed` for any input;
// the canonical-root comparison is a no-op in that case.
func (r *RevmPostState) IsEmpty() bool {
	return r != nil && len(r.Accounts) == 0 && r.GasUsed == 0 && len(r.Receipts) == 0
}

// runHostRevm invokes the prover/host-revm binary as a subprocess,
// feeding it `input` on stdin and parsing the stdout JSON as a
// RevmPostState. If the binary is unavailable or BSVM_HOST_REVM_BINARY
// is unset, returns (nil, nil) — callers treat that as "skip the
// canonical-root comparison" and proceed.
//
// Errors returned reflect ACTUAL failures (binary returned non-zero,
// stdout was malformed) — not the unset-env case.
func runHostRevm(ctx context.Context, binaryPath string, input *RevmComparatorInput) (*RevmPostState, error) {
	if binaryPath == "" {
		return nil, nil
	}
	if input == nil {
		return nil, fmt.Errorf("runHostRevm: input is nil")
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal RevmComparatorInput: %w", err)
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("host-revm binary failed: %w; stderr: %s",
			err, strings.TrimSpace(stderr.String()))
	}

	var out RevmPostState
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse host-revm stdout JSON: %w; stdout: %s",
			err, stdout.String())
	}
	return &out, nil
}

// BuildPostStateRoot re-derives the canonical Ethereum MPT root from
// the Rust comparator's post-state map. It opens a fresh StateDB
// against an empty database, applies each account and storage slot
// from `post`, and calls Commit — the same path `pkg/state.StateDB`
// uses to compute its own post-execution root.
//
// `extra` provides a SHA256-based structural digest of the same
// post-state for fast pre-flight comparison; account-set divergences
// surface there before the (more expensive) trie build runs.
//
// The returned hash is the MPT root over the supplied accounts; the
// caller compares it byte-for-byte to the Go EVM's own postStateRoot.
func BuildPostStateRoot(post *RevmPostState) (root types.Hash, digest types.Hash, err error) {
	if post == nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("BuildPostStateRoot: nil post-state")
	}

	memdb := db.NewMemoryDB()
	sdb, err := state.New(types.Hash{}, memdb)
	if err != nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("open fresh StateDB: %w", err)
	}

	for i, a := range post.Accounts {
		addr, err := parseAddressHex(a.Address)
		if err != nil {
			return types.Hash{}, types.Hash{}, fmt.Errorf("account[%d] address: %w", i, err)
		}
		balance, err := parseUint256Hex(a.Balance)
		if err != nil {
			return types.Hash{}, types.Hash{}, fmt.Errorf("account[%d] balance: %w", i, err)
		}
		code, err := parseHexBytes(a.Code)
		if err != nil {
			return types.Hash{}, types.Hash{}, fmt.Errorf("account[%d] code: %w", i, err)
		}

		// The order matters: CreateAccount first so the account exists,
		// then balance/nonce/code, then storage. Empty accounts are
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
				return types.Hash{}, types.Hash{}, fmt.Errorf("account[%d] storage[%d] key: %w", i, j, err)
			}
			value, err := parseHashHex(slot.Value)
			if err != nil {
				return types.Hash{}, types.Hash{}, fmt.Errorf("account[%d] storage[%d] value: %w", i, j, err)
			}
			sdb.SetState(addr, key, value)
		}
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
// `bsvm_host_revm::structural_digest` byte-for-byte; drift here breaks
// the cheap pre-flight check.
//
// Encoding (per account, in input order):
//
//	address[20] || nonce[8 BE] || balance[32 BE] || code_hash[32]
//	|| u32-BE storage-count || (key[32] || value[32])* in input order
//
// Callers should pass `accounts` already sorted by address ascending
// (the host-revm binary does this). Drift in sort order surfaces as a
// digest mismatch.
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
