package prover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// SP1Prover generates STARK proofs of EVM execution via SP1.
type SP1Prover struct {
	config Config
}

// NewSP1Prover creates a new SP1Prover with the given configuration.
func NewSP1Prover(config Config) *SP1Prover {
	return &SP1Prover{config: config}
}

// Mode returns the prover backend mode (local / network / mock). Exposed
// as an accessor so the parallel coordinator and RPC metrics can report
// which proving path is active without callers needing to hold the
// Config struct.
func (p *SP1Prover) Mode() ProverMode {
	if p == nil {
		return ProverMock
	}
	return p.config.Mode
}

// BlockContext holds the block-level parameters needed by the SP1 guest.
// This is a simplified version of vm.BlockContext containing only the
// serializable fields needed for proving.
type BlockContext struct {
	// Number is the block number.
	Number uint64 `json:"number"`
	// Timestamp is the block timestamp.
	Timestamp uint64 `json:"timestamp"`
	// Coinbase is the block beneficiary address.
	Coinbase types.Address `json:"coinbase"`
	// GasLimit is the block gas limit.
	GasLimit uint64 `json:"gas_limit"`
	// BaseFee is the EIP-1559 base fee.
	BaseFee uint64 `json:"base_fee"`
	// Random is the PREVRANDAO value (post-merge).
	Random types.Hash `json:"random"`
}

// Withdrawal is an L2 → BSV bridge withdrawal record carried into the
// SP1 guest as part of ProveInput. The guest computes the withdrawal
// Merkle root (committed in public values at offset 144) using these.
//
// Recipient is the 20-byte BSV address (RIPEMD160(SHA256(pubkey))).
// AmountSatoshis is the satoshi-denominated amount (uint64 BE in the
// Merkle leaf), Nonce is the bridge contract's per-withdrawal nonce.
// The leaf is hash256(Recipient || AmountSatoshis_be || Nonce_be), with
// the binary SHA256 tree built per pkg/bridge/withdrawal.go.
type Withdrawal struct {
	Recipient      types.Address `json:"recipient"`
	AmountSatoshis uint64        `json:"amount"`
	Nonce          uint64        `json:"nonce"`
}

// ProveInput contains everything needed to generate a STARK proof.
type ProveInput struct {
	// PreStateRoot is the state root before executing the batch.
	PreStateRoot types.Hash `json:"pre_state_root"`
	// StateExport is the serialized StateExport (JSON) containing
	// accessed accounts, storage, and Merkle proofs.
	StateExport []byte `json:"state_export"`
	// Transactions is a list of RLP-encoded EVM transactions.
	Transactions [][]byte `json:"transactions"`
	// BlockContext holds the block parameters for this batch.
	BlockContext BlockContext `json:"block_context"`

	// InboxRootBefore is the inbox queue hash before draining pending
	// inbox transactions. Computed from InboxMonitor state.
	InboxRootBefore types.Hash `json:"inbox_root_before"`
	// InboxRootAfter is the inbox queue hash after draining pending
	// inbox transactions. Computed from InboxMonitor state.
	InboxRootAfter types.Hash `json:"inbox_root_after"`

	// Withdrawals is the list of L2 → BSV bridge withdrawals included in
	// this batch. The SP1 guest folds these into a binary SHA256 Merkle
	// tree and commits the root in public values at offset 144 so the
	// bridge covenant can verify withdrawal claims off the STARK-attested
	// root. May be empty: empty list ⇒ withdrawalRoot = bytes32(0).
	Withdrawals []Withdrawal `json:"withdrawals,omitempty"`

	// ExpectedResults holds the expected execution outputs from the Go EVM.
	// In mock mode, these values are used to populate PublicValues so that
	// the mock proof matches the Go EVM's computed results. In local and
	// network modes, these values are ignored (the SP1 guest computes them
	// independently).
	ExpectedResults *ExpectedResults `json:"expected_results,omitempty"`
}

// ExpectedResults holds the Go EVM's execution outputs. These are passed to
// the mock prover so it can produce PublicValues that match the Go EVM's
// actual computed state, enabling end-to-end pipeline testing without a
// real SP1 prover.
type ExpectedResults struct {
	// PostStateRoot is the state root after executing the batch.
	PostStateRoot types.Hash `json:"post_state_root"`
	// ReceiptsHash is the hash of the receipts trie.
	ReceiptsHash types.Hash `json:"receipts_hash"`
	// GasUsed is the total gas consumed by the batch.
	GasUsed uint64 `json:"gas_used"`
	// ChainID is the chain ID of the L2 shard.
	ChainID uint64 `json:"chain_id"`
}

// ProveOutput is the result of a successful proving operation.
type ProveOutput struct {
	// Mode identifies which on-chain verification path the produced proof
	// targets (Basefold / Groth16-generic / Groth16-witness). Populated by
	// the SP1Prover from Config.ProofMode; not part of the Rust host bridge
	// JSON envelope.
	Mode ProofMode `json:"-"`
	// Proof is the raw SP1 STARK proof bytes.
	Proof []byte `json:"proof"`
	// PublicValues is the 280-byte committed public outputs.
	PublicValues []byte `json:"public_values"`
	// VKHash is the verification key hash.
	VKHash types.Hash `json:"vk_hash"`
	// Cycles is the number of RISC-V cycles consumed.
	Cycles uint64 `json:"cycles"`
	// ProvingTime is how long proving took.
	ProvingTime time.Duration `json:"proving_time_ns"`
}

// Prove generates a STARK proof of correct EVM execution. The proof mode
// (local, network, mock) is determined by the prover's configuration.
func (p *SP1Prover) Prove(ctx context.Context, input *ProveInput) (*ProveOutput, error) {
	if input == nil {
		return nil, fmt.Errorf("prove input is nil")
	}

	switch p.config.Mode {
	case ProverLocal:
		return p.proveLocal(ctx, input)
	case ProverNetwork:
		return p.proveNetwork(ctx, input)
	case ProverMock:
		return p.proveMock(ctx, input)
	default:
		return nil, fmt.Errorf("unknown prover mode: %d", p.config.Mode)
	}
}

// proveLocal invokes the bsvm-host-bridge Rust binary as a subprocess,
// passing the prove input as JSON on stdin and reading the prove output
// as JSON on stdout.
func (p *SP1Prover) proveLocal(ctx context.Context, input *ProveInput) (*ProveOutput, error) {
	if p.config.HostBridgeBinary == "" {
		return nil, fmt.Errorf("host bridge binary path not configured")
	}
	if p.config.GuestELFPath == "" {
		return nil, fmt.Errorf("guest ELF path not configured")
	}

	// Apply timeout if configured.
	if p.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.config.Timeout)
		defer cancel()
	}

	// Serialize input to JSON for the host bridge.
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("serializing prove input: %w", err)
	}

	// Build the command.
	args := []string{
		"--elf", p.config.GuestELFPath,
		"--prove",
	}
	if p.config.SP1ProofMode != "" {
		args = append(args, "--proof-mode", p.config.SP1ProofMode)
	}

	cmd := exec.CommandContext(ctx, p.config.HostBridgeBinary, args...)
	cmd.Stdin = bytes.NewReader(inputJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sp1 prover failed: %w, stderr: %s", err, stderr.String())
	}

	// Parse output.
	var output ProveOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("parsing prover output: %w", err)
	}
	output.Mode = p.config.ProofMode

	return &output, nil
}

// proveNetwork submits a proving request to the SP1 prover network.
// Network mode requires an SP1 prover network subscription and is not
// available in the current release. Use local or mock mode instead.
func (p *SP1Prover) proveNetwork(_ context.Context, _ *ProveInput) (*ProveOutput, error) {
	return nil, fmt.Errorf("network proving mode is not available: requires SP1 prover network subscription, use local or mock mode")
}

// proveMock generates a dummy proof with correct structure for testing.
// It does not perform any real proving -- the proof bytes are synthetic.
// When ExpectedResults are provided in the input, the mock prover uses
// them to populate the PublicValues so the output matches the Go EVM's
// computed results. Without ExpectedResults, fallback values are used.
func (p *SP1Prover) proveMock(_ context.Context, input *ProveInput) (*ProveOutput, error) {
	start := time.Now()

	// Build a mock public values blob with the correct 280-byte layout.
	// When ExpectedResults are provided, use them for accurate post-state
	// values. Otherwise fall back to pre-state root and zero values.
	// BlockNumber is always sourced from input.BlockContext.Number — the
	// real guest commits the same value, and the covenant binds it to
	// c.BlockNumber+1 on advance.
	pv := &PublicValues{
		PreStateRoot:      input.PreStateRoot,
		BatchDataHash:     hashTransactions(input.Transactions),
		WithdrawalRoot:    computeWithdrawalRoot(input.Withdrawals),
		InboxRootBefore:   input.InboxRootBefore,
		InboxRootAfter:    input.InboxRootAfter,
		MigrateScriptHash: types.Hash{},
		BlockNumber:       input.BlockContext.Number,
	}

	if input.ExpectedResults != nil {
		pv.PostStateRoot = input.ExpectedResults.PostStateRoot
		pv.ReceiptsHash = input.ExpectedResults.ReceiptsHash
		pv.GasUsed = input.ExpectedResults.GasUsed
		pv.ChainID = input.ExpectedResults.ChainID
	} else {
		pv.PostStateRoot = input.PreStateRoot // fallback: unchanged
		pv.ReceiptsHash = types.Hash{}        // fallback: empty
		pv.GasUsed = 0
		pv.ChainID = 0
	}

	publicValues := pv.Encode()

	// Generate a deterministic mock VK hash from the public values.
	vkHash := types.BytesToHash(crypto.Keccak256([]byte("mock-vk")))

	// Generate dummy proof data (just a marker for mock proofs).
	mockProof := []byte("MOCK_SP1_PROOF")

	return &ProveOutput{
		Mode:         p.config.ProofMode,
		Proof:        mockProof,
		PublicValues: publicValues,
		VKHash:       vkHash,
		Cycles:       0,
		ProvingTime:  time.Since(start),
	}, nil
}

// hashTransactions computes hash256 (double-SHA256) over all transaction bytes
// concatenated together, used for the batch data hash. This matches the
// covenant's OP_HASH256 verification: batchDataHash = hash256(batchData).
func hashTransactions(txs [][]byte) types.Hash {
	var buf bytes.Buffer
	for _, tx := range txs {
		buf.Write(tx)
	}
	if buf.Len() == 0 {
		return types.Hash{}
	}
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}
