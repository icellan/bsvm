//go:build integration

// Package covenant: real BroadcastClient implementation backed by the Rúnar
// Go SDK and a BSV regtest node (integration build tag only).
//
// The client holds a single deployed contract reference. Each instance is
// configured with a ProofMode at construction time and rejects BroadcastAdvance
// calls whose req.Proof.Mode() does not match. Callers that need to drive
// multiple modes must construct one client per mode.
//
// This client does NOT re-verify SP1 proofs — its sole job is to build and
// broadcast the advanceState contract call for a mode-specific AdvanceProof.
// Proof validity is the prover's responsibility.
package covenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
	"runar-integration/helpers"
)

// ---------------------------------------------------------------------------
// Back-compat synthetic Merkle scaffolding exposed for the regtest deploy
// helpers in test/integration. The multi-mode refactor moved the per-proof
// scaffolding into pkg/overlay/synthetic_proofs.go, but the regtest deploy
// helpers still compile against this package-level root accessor. A follow-up
// sub-agent will rewrite the regtest harness to build proofs directly; until
// then, expose the same depth-20 SHA-256 Merkle root that the synthetic
// BasefoldProof in the overlay uses, so the deploy-time VerifyingKeyHash
// constructor argument stays consistent with the client's advance args.
// ---------------------------------------------------------------------------

const (
	runarBroadcastMerkleDepth     = 20
	runarBroadcastMerkleLeafIndex = 7
)

var runarBroadcastMerkleRootHex string

func init() {
	leafHex := hexSha256Integration("00")
	_, root := buildRunarBroadcastDepth20Proof(leafHex, runarBroadcastMerkleLeafIndex)
	runarBroadcastMerkleRootHex = root
}

// RunarBroadcastMerkleRootHex returns the verifying-key-hash value that
// deployers must supply as the rollup contract's VerifyingKeyHash constructor
// argument so advances produced by the overlay's synthetic BasefoldProof
// pass the Merkle-root check.
func RunarBroadcastMerkleRootHex() string { return runarBroadcastMerkleRootHex }

func hexSha256Integration(h string) string {
	data, _ := hex.DecodeString(h)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func buildRunarBroadcastDepth20Proof(leafHex string, index int) (proofHex, rootHex string) {
	var siblings []string
	current := leafHex
	idx := index
	for d := 0; d < runarBroadcastMerkleDepth; d++ {
		sibling := hexSha256Integration(hex.EncodeToString([]byte{byte(d), byte(idx ^ 1)}))
		siblings = append(siblings, sibling)
		if idx&1 == 0 {
			current = hexSha256Integration(current + sibling)
		} else {
			current = hexSha256Integration(sibling + current)
		}
		idx >>= 1
	}
	p := ""
	for _, s := range siblings {
		p += s
	}
	return p, current
}

// RunarBroadcastClient is a real BroadcastClient implementation that talks
// to a BSV regtest node via the Rúnar Go SDK. It attaches to a pre-deployed
// rollup contract of a single ProofMode and drives it through
// contract.Call("advanceState", args) where args comes from
// req.Proof.ContractCallArgs.
type RunarBroadcastClient struct {
	contract *runar.RunarContract
	provider runar.Provider
	signer   runar.Signer
	chainID  int64
	mode     ProofMode

	mu        sync.Mutex
	confs     map[types.Hash]uint32
	txids     []types.Hash
	lastError error
}

// RunarBroadcastClientOpts configures a RunarBroadcastClient.
type RunarBroadcastClientOpts struct {
	Contract *runar.RunarContract
	Provider runar.Provider
	Signer   runar.Signer
	// ChainID is the chain id embedded in the rollup contract's public-values
	// binding. It MUST match the chainID constructor arg used at deploy time.
	ChainID int64
	// Mode is the ProofMode that the deployed contract implements. The
	// client rejects BroadcastAdvance calls for any other mode.
	Mode ProofMode
}

// NewRunarBroadcastClient constructs a RunarBroadcastClient bound to the
// given deployed contract, provider, and signer.
func NewRunarBroadcastClient(opts RunarBroadcastClientOpts) (*RunarBroadcastClient, error) {
	if opts.Contract == nil {
		return nil, errors.New("contract required")
	}
	if opts.Provider == nil {
		return nil, errors.New("provider required")
	}
	if opts.Signer == nil {
		return nil, errors.New("signer required")
	}
	return &RunarBroadcastClient{
		contract: opts.Contract,
		provider: opts.Provider,
		signer:   opts.Signer,
		chainID:  opts.ChainID,
		mode:     opts.Mode,
		confs:    make(map[types.Hash]uint32),
	}, nil
}

// Mode returns the ProofMode this client was constructed for.
func (c *RunarBroadcastClient) Mode() ProofMode { return c.mode }

// BroadcastAdvance dispatches the advanceState call by extracting the
// mode-specific argument slice from req.Proof.ContractCallArgs. For Mode 3
// (Groth16 witness-assisted) the BN254 witness bundle is pulled directly
// from the concrete *Groth16WitnessProof and forwarded to the SDK via
// runar.CallOptions.Groth16WAWitness; the witness is NOT marshaled into
// the positional arg slice.
func (c *RunarBroadcastClient) BroadcastAdvance(_ context.Context, req BroadcastRequest) (*BroadcastResult, error) {
	if req.Proof == nil {
		return nil, errors.New("nil advance proof")
	}
	if req.Proof.Mode() != c.mode {
		return nil, fmt.Errorf("proof mode %s does not match client mode %s",
			req.Proof.Mode(), c.mode)
	}

	args, err := req.Proof.ContractCallArgs(req)
	if err != nil {
		wrapped := fmt.Errorf("building contract call args: %w", err)
		c.mu.Lock()
		c.lastError = wrapped
		c.mu.Unlock()
		return nil, wrapped
	}

	var callOpts *runar.CallOptions
	if req.Proof.Mode() == ProofModeGroth16Witness {
		waProof, ok := req.Proof.(*Groth16WitnessProof)
		if !ok {
			return nil, fmt.Errorf("mode %s requires *Groth16WitnessProof, got %T",
				req.Proof.Mode(), req.Proof)
		}
		if waProof.Witness == nil {
			return nil, fmt.Errorf("mode %s requires a non-nil BN254 witness bundle",
				req.Proof.Mode())
		}
		callOpts = &runar.CallOptions{
			Groth16WAWitness: waProof.Witness,
		}
	}

	txidStr, _, err := c.contract.Call("advanceState", args, c.provider, c.signer, callOpts)
	if err != nil {
		wrapped := fmt.Errorf("contract.Call advanceState: %w", err)
		c.mu.Lock()
		c.lastError = wrapped
		c.mu.Unlock()
		return nil, wrapped
	}

	txid, err := parseRunarTxID(txidStr)
	if err != nil {
		return nil, fmt.Errorf("parsing returned txid %q: %w", txidStr, err)
	}

	c.mu.Lock()
	c.confs[txid] = 0
	c.txids = append(c.txids, txid)
	c.mu.Unlock()

	return &BroadcastResult{
		TxID:            txid,
		NewCovenantTxID: txid,
		NewCovenantVout: 0,
		// The rollup contract carries forward the same satoshi value on the
		// covenant UTXO — no fee accumulation in the covenant output.
		NewCovenantSats: req.PrevSats,
		BroadcastAt:     time.Now(),
	}, nil
}

// GetConfirmations returns the BSV confirmation count for a broadcast
// advance txid via getrawtransaction (verbose=1). Zero confirmations means
// the tx is in the mempool but not yet mined. An unknown txid produces an
// RPC error propagated to the caller.
func (c *RunarBroadcastClient) GetConfirmations(ctx context.Context, txid types.Hash) (uint32, error) {
	txidHex := hex.EncodeToString(txid[:])

	raw, err := helpers.RPCCall("getrawtransaction", txidHex, 1)
	if err != nil {
		return 0, fmt.Errorf("getrawtransaction %s: %w", txidHex, err)
	}

	var resp struct {
		Confirmations *uint32 `json:"confirmations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("decoding getrawtransaction response: %w", err)
	}
	var confs uint32
	if resp.Confirmations != nil {
		confs = *resp.Confirmations
	}

	c.mu.Lock()
	c.confs[txid] = confs
	c.mu.Unlock()

	return confs, nil
}

// Close is a no-op — the client holds no background resources.
func (c *RunarBroadcastClient) Close() error { return nil }

// TxIDs returns a snapshot of every txid this client has broadcast, in
// order. Intended for test assertions / debug logging.
func (c *RunarBroadcastClient) TxIDs() []types.Hash {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]types.Hash, len(c.txids))
	copy(out, c.txids)
	return out
}

// LastError returns the most recent broadcast error observed by this client,
// or nil if no broadcast has failed. Intended for test diagnostics — the
// overlay logs broadcast errors via slog but does not propagate them out
// of ProcessBatch, so tests that want to inspect the error inline need a
// separate accessor.
func (c *RunarBroadcastClient) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastError
}

// parseRunarTxID converts a hex-string txid returned by contract.Call into
// a types.Hash. The SDK returns 64-char hex (no 0x prefix); we store the
// bytes verbatim so GetConfirmations' reverse encode produces the same
// string to feed back into getrawtransaction.
func parseRunarTxID(s string) (types.Hash, error) {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	if len(b) != 32 {
		return types.Hash{}, fmt.Errorf("expected 32-byte txid, got %d", len(b))
	}
	var h types.Hash
	copy(h[:], b)
	return h, nil
}
