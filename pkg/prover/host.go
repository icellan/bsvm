package prover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/holiman/uint256"

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
	// inbox transactions. The SP1 guest verifies this against InboxQueue
	// (W4-3, spec 10): it recomputes the chain root over InboxQueue and
	// asserts equality. A mismatch aborts the proof, which is the
	// censorship-resistance gate.
	InboxRootBefore types.Hash `json:"inbox_root_before"`
	// InboxRootAfter is the inbox queue hash after draining
	// InboxDrainCount entries off the front of InboxQueue. The guest
	// recomputes this from the carry-forward remainder; the host
	// supplies it for cross-check / mock-mode use only.
	InboxRootAfter types.Hash `json:"inbox_root_after"`
	// InboxQueue is the full ordered list of currently-queued inbox
	// transactions, exactly as the on-chain inbox covenant has them
	// (raw RLP, identical to what `InboxMonitor.AddInboxTransaction`
	// recorded). The leading InboxDrainCount entries are executed at the
	// HEAD of the batch (before user txs); the remainder is carried
	// forward. The guest verifies the chain root over this list against
	// InboxRootBefore.
	InboxQueue []InboxQueuedTx `json:"inbox_queue,omitempty"`
	// InboxDrainCount is how many leading entries to consume from
	// InboxQueue this batch. Must be <= len(InboxQueue).
	InboxDrainCount uint32 `json:"inbox_drain_count,omitempty"`
	// InboxMustDrainAll is set when on-chain `advancesSinceInbox` has
	// reached the forced-inclusion threshold (spec 10, default 10) and
	// the covenant will REJECT any advance that doesn't fully drain the
	// queue. The guest enforces this defensively.
	InboxMustDrainAll bool `json:"inbox_must_drain_all,omitempty"`

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

	// Translate ProveInput to the bridge's expected wire format. This
	// flattens StateExport (which carries Merkle proofs for W4-1) into
	// the per-account fields the Rust bridge consumes.
	inputJSON, err := buildBridgeInput(input, p.config.SP1ProofMode)
	if err != nil {
		return nil, fmt.Errorf("building bridge input: %w", err)
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
// computed results. Without ExpectedResults, sentinel zero values are used.
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
		pv.PostStateRoot = input.PreStateRoot // sentinel: unchanged
		pv.ReceiptsHash = types.Hash{}        // sentinel: empty
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

// buildBridgeInput translates a ProveInput (the Go-side struct) into the
// JSON envelope expected by prover/host-bridge/src/main.rs. This is where
// the Merkle witnesses produced by ExportStateForProving (W4-1) are lifted
// into the per-account fields the Rust bridge forwards to the SP1 guest.
//
// The bridge envelope intentionally lives next to its only call-site; the
// public ProveInput type stays stable so the parallel prover and overlay
// glue do not need to change.
//
// W4-1 mainnet hardening: a non-empty StateExport with Merkle proofs is
// REQUIRED. The previous "if proofs absent, ship empty accounts" branch
// has been removed — the guest rejects unwitnessed batches outright, so
// silently producing one would just stall the pipeline.
func buildBridgeInput(input *ProveInput, sp1Mode string) ([]byte, error) {
	if len(input.StateExport) == 0 {
		return nil, fmt.Errorf("prove input is missing StateExport: " +
			"the SP1 guest requires Merkle witnesses for every accessed " +
			"account (W4-1 mainnet hardening); call " +
			"prover.ExportStateForProving on the pre-state DB before proving")
	}
	export, err := DeserializeExport(input.StateExport)
	if err != nil {
		return nil, fmt.Errorf("deserializing state export: %w", err)
	}

	envelope := bridgeInput{
		PreStateRoot:      input.PreStateRoot.Hex(),
		Transactions:      transactionsToBridge(input.Transactions),
		BlockContext:      blockContextToBridge(input.BlockContext),
		InboxRootBefore:   input.InboxRootBefore.Hex(),
		InboxRootAfter:    input.InboxRootAfter.Hex(),
		InboxQueue:        inboxQueueToBridge(input.InboxQueue),
		InboxDrainCount:   input.InboxDrainCount,
		InboxMustDrainAll: input.InboxMustDrainAll,
		Mode:              sp1Mode,
	}
	if envelope.Mode == "" {
		// Default mirrors the bridge's "execute" branch — safe for
		// callers that didn't set SP1ProofMode (e.g. dry runs).
		envelope.Mode = "execute"
	}

	envelope.Accounts = make([]bridgeAccount, 0, len(export.Accounts))
	for _, a := range export.Accounts {
		if len(a.AccountProof) == 0 {
			return nil, fmt.Errorf("account %s in StateExport has no AccountProof: "+
				"the SP1 guest requires a Merkle witness for every account "+
				"(W4-1 mainnet hardening)", a.Address.Hex())
		}
		ba := bridgeAccount{
			Address:      a.Address.Hex(),
			Nonce:        a.Nonce,
			Balance:      uint256ToHex(a.Balance),
			CodeHash:     a.CodeHash.Hex(),
			StorageRoot:  a.StorageRoot.Hex(),
			Code:         "0x" + bytesToHex(a.Code),
			AccountProof: bytesSliceToHex(a.AccountProof),
		}
		for _, s := range a.StorageSlots {
			ba.StorageSlots = append(ba.StorageSlots, bridgeStorageSlot{
				Key:   s.Key.Hex(),
				Value: s.Value.Hex(),
				Proof: bytesSliceToHex(s.Proof),
			})
		}
		envelope.Accounts = append(envelope.Accounts, ba)
	}

	return json.Marshal(envelope)
}

// bridgeInput, bridgeAccount, bridgeStorageSlot, bridgeTransaction,
// bridgeBlockContext are the JSON shapes expected by
// prover/host-bridge/src/main.rs. They mirror the Rust HostInput /
// AccountExport / StorageSlotExport / TransactionExport / BlockContext
// types one-to-one. Keep these in lock-step with the Rust bridge.
type bridgeInput struct {
	PreStateRoot      string                `json:"pre_state_root"`
	Accounts          []bridgeAccount       `json:"accounts"`
	Transactions      []bridgeTransaction   `json:"transactions"`
	BlockContext      bridgeBlockContext    `json:"block_context"`
	InboxRootBefore   string                `json:"inbox_root_before,omitempty"`
	InboxRootAfter    string                `json:"inbox_root_after,omitempty"`
	InboxQueue        []bridgeInboxQueuedTx `json:"inbox_queue,omitempty"`
	InboxDrainCount   uint32                `json:"inbox_drain_count,omitempty"`
	InboxMustDrainAll bool                  `json:"inbox_must_drain_all,omitempty"`
	Mode              string                `json:"mode"`
}

// bridgeInboxQueuedTx mirrors the Rust bridge's `InboxQueuedTxExport`
// (prover/host-bridge/src/main.rs). Field shape MUST stay in sync.
type bridgeInboxQueuedTx struct {
	RawTxRLP string `json:"raw_tx_rlp"`
}

type bridgeAccount struct {
	Address      string              `json:"address"`
	Nonce        uint64              `json:"nonce"`
	Balance      string              `json:"balance"`
	CodeHash     string              `json:"code_hash"`
	Code         string              `json:"code"`
	StorageRoot  string              `json:"storage_root,omitempty"`
	AccountProof []string            `json:"account_proof,omitempty"`
	StorageSlots []bridgeStorageSlot `json:"storage_slots,omitempty"`
}

type bridgeStorageSlot struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof,omitempty"`
}

type bridgeTransaction struct {
	TxType         uint8  `json:"tx_type"`
	From           string `json:"from"`
	To             string `json:"to,omitempty"`
	Value          string `json:"value"`
	Data           string `json:"data"`
	Nonce          uint64 `json:"nonce"`
	GasLimit       uint64 `json:"gas_limit"`
	GasPrice       uint64 `json:"gas_price"`
	MaxPriorityFee uint64 `json:"max_priority_fee"`
	RawBytes       string `json:"raw_bytes"`
}

type bridgeBlockContext struct {
	Number     uint64 `json:"number"`
	Timestamp  uint64 `json:"timestamp"`
	Coinbase   string `json:"coinbase"`
	GasLimit   uint64 `json:"gas_limit"`
	BaseFee    uint64 `json:"base_fee"`
	PrevRandao string `json:"prev_randao,omitempty"`
}

// transactionsToBridge unwraps each RLP transaction into the bridge's
// flat transaction record. Most fields can't be recovered from the raw
// bytes alone; the bridge cares about `raw_bytes` for batch hashing and
// reconstructs the rest itself by re-decoding inside the guest. We pass
// raw_bytes only and let the bridge / guest handle the rest.
func transactionsToBridge(txs [][]byte) []bridgeTransaction {
	out := make([]bridgeTransaction, len(txs))
	for i, raw := range txs {
		out[i] = bridgeTransaction{
			RawBytes: "0x" + bytesToHex(raw),
		}
	}
	return out
}

// inboxQueueToBridge serializes the inbox witness for the Rust bridge.
// Each entry carries only the canonical raw EVM RLP bytes — the Rust
// bridge populates the rest of the guest's `EvmTransaction` fields from
// `raw_tx_rlp` via the W4-2 decoder.
func inboxQueueToBridge(queue []InboxQueuedTx) []bridgeInboxQueuedTx {
	if len(queue) == 0 {
		return nil
	}
	out := make([]bridgeInboxQueuedTx, len(queue))
	for i, q := range queue {
		out[i] = bridgeInboxQueuedTx{
			RawTxRLP: "0x" + bytesToHex(q.RawTxRLP),
		}
	}
	return out
}

func blockContextToBridge(bc BlockContext) bridgeBlockContext {
	return bridgeBlockContext{
		Number:     bc.Number,
		Timestamp:  bc.Timestamp,
		Coinbase:   bc.Coinbase.Hex(),
		GasLimit:   bc.GasLimit,
		BaseFee:    bc.BaseFee,
		PrevRandao: bc.Random.Hex(),
	}
}

// uint256ToHex returns a 0x-prefixed left-padded 32-byte hex string. Empty
// (nil) inputs render as 32 zero bytes.
func uint256ToHex(v *uint256.Int) string {
	if v == nil {
		return "0x" + bytesToHex(make([]byte, 32))
	}
	b := v.Bytes32()
	return "0x" + bytesToHex(b[:])
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[2*i] = hexChars[x>>4]
		out[2*i+1] = hexChars[x&0x0f]
	}
	return string(out)
}

func bytesSliceToHex(slices [][]byte) []string {
	out := make([]string, len(slices))
	for i, s := range slices {
		out[i] = "0x" + bytesToHex(s)
	}
	return out
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
