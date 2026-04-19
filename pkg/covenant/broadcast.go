// Package covenant: BroadcastClient defines the seam between the
// overlay node and the BSV network for covenant-advance transactions.
package covenant

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/icellan/bsvm/pkg/proofmode"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ProofMode is re-exported from pkg/proofmode so call sites that already
// import pkg/covenant can refer to the enum without an extra import. New
// code is free to use proofmode.ProofMode directly.
type ProofMode = proofmode.ProofMode

// Re-exported ProofMode constants.
const (
	ProofModeFRI            = proofmode.FRI
	ProofModeGroth16Generic = proofmode.Groth16Generic
	ProofModeGroth16Witness = proofmode.Groth16Witness
)

// BroadcastClient broadcasts covenant advance transactions to the BSV
// network. Implementations include a real Rúnar-SDK-backed client
// (regtest/mainnet) and an in-memory fake (hermetic tests).
type BroadcastClient interface {
	// BroadcastAdvance constructs and broadcasts a covenant advance
	// transaction. The proof carried by req.Proof selects which contract
	// method is invoked and which argument shape is used.
	BroadcastAdvance(ctx context.Context, req BroadcastRequest) (*BroadcastResult, error)

	// GetConfirmations returns the number of BSV block confirmations
	// for the given txid. Returns 0 if the tx is in the mempool but
	// not yet mined. Returns an error if the tx is unknown.
	GetConfirmations(ctx context.Context, txid types.Hash) (uint32, error)

	// Close releases any resources held by the client (RPC connections,
	// background goroutines, etc.). After Close, the client must not be
	// used.
	Close() error
}

// AdvanceProof is the mode-specific proof carried in a BroadcastRequest.
// Each implementation owns the marshaling for its own mode so that callers
// construct the concrete type with real data and the broadcast client never
// needs to know which mode it is handling beyond the dispatch call.
//
// The BatchData / PublicValues / ProofBlob accessors exist so that
// CovenantManager.BroadcastAdvance can validate the underlying data via
// ValidateAdvanceData without caring which concrete proof it was handed.
type AdvanceProof interface {
	// Mode returns the proof mode this advance proof targets.
	Mode() ProofMode

	// BatchData returns the raw batch encoding (canonical batch bytes
	// as emitted by pkg/block.EncodeBatchData) for validation and
	// OP_RETURN embedding.
	BatchData() []byte

	// PublicValues returns the raw SP1 public values blob for validation.
	PublicValues() []byte

	// ProofBlob returns the raw SP1 proof bytes for validation.
	ProofBlob() []byte

	// ContractCallArgs returns the []interface{} slice in the exact
	// order the rollup contract for this mode expects on its
	// advanceState method. Includes the 5 core args (newStateRoot,
	// newBlockNumber, publicValues, batchData, proofBlob) plus any
	// mode-specific proof arguments.
	ContractCallArgs(req BroadcastRequest) ([]interface{}, error)
}

// FRIProof carries the proof data for ProofModeFRI (Mode 1, trust-
// minimized FRI bridge). Its ContractCallArgs method produces the 5-arg
// slice expected by contracts.FRIRollupContract.AdvanceState. There are
// no FRI-specific arguments because Mode 1 does not verify the proof
// on-chain; the Blob field is passed through for off-chain verification
// and future-upgrade ABI stability.
type FRIProof struct {
	// SP1 envelope.
	Values []byte
	Batch  []byte
	Blob   []byte
}

// Mode returns ProofModeFRI.
func (p *FRIProof) Mode() ProofMode { return ProofModeFRI }

// BatchData returns the canonical batch encoding.
func (p *FRIProof) BatchData() []byte { return p.Batch }

// PublicValues returns the raw SP1 public values blob.
func (p *FRIProof) PublicValues() []byte { return p.Values }

// ProofBlob returns the raw SP1 proof bytes.
func (p *FRIProof) ProofBlob() []byte { return p.Blob }

// ContractCallArgs returns the argument slice for
// FRIRollupContract.AdvanceState in the order:
//
//	newStateRoot, newBlockNumber, publicValues, batchData, proofBlob.
func (p *FRIProof) ContractCallArgs(req BroadcastRequest) ([]interface{}, error) {
	if p == nil {
		return nil, errors.New("nil FRI proof")
	}
	newStateRootHex := hex.EncodeToString(req.NewState.StateRoot[:])
	publicValuesHex := hex.EncodeToString(p.Values)
	batchDataHex := hex.EncodeToString(p.Batch)
	proofBlobHex := hex.EncodeToString(p.Blob)
	return []interface{}{
		newStateRootHex,
		int64(req.NewState.BlockNumber),
		publicValuesHex,
		batchDataHex,
		proofBlobHex,
	}, nil
}

// Groth16GenericProof carries the proof data for ProofModeGroth16Generic.
// Its ContractCallArgs method produces the 16-arg slice expected by
// contracts.Groth16RollupContract.AdvanceState.
type Groth16GenericProof struct {
	// SP1 envelope.
	Values []byte
	Batch  []byte
	Blob   []byte

	// BN254 G1 element A (runar.Point on the contract side = 64-byte
	// X || Y hex string).
	ProofAx *big.Int
	ProofAy *big.Int

	// BN254 G2 element B (Fp2 coordinates, runar.Bigint = int64 on the
	// contract side).
	ProofBx0 *big.Int
	ProofBx1 *big.Int
	ProofBy0 *big.Int
	ProofBy1 *big.Int

	// BN254 G1 element C.
	ProofCx *big.Int
	ProofCy *big.Int

	// 5 public inputs for IC linearization (matches the 5 IC slots in
	// Groth16RollupContract: PUB_0..PUB_4).
	PublicInputs [5]*big.Int
}

// Mode returns ProofModeGroth16Generic.
func (p *Groth16GenericProof) Mode() ProofMode { return ProofModeGroth16Generic }

// BatchData returns the canonical batch encoding.
func (p *Groth16GenericProof) BatchData() []byte { return p.Batch }

// PublicValues returns the raw SP1 public values blob.
func (p *Groth16GenericProof) PublicValues() []byte { return p.Values }

// ProofBlob returns the raw SP1 proof bytes.
func (p *Groth16GenericProof) ProofBlob() []byte { return p.Blob }

// ContractCallArgs returns the argument slice for
// Groth16RollupContract.AdvanceState in the order:
//
//	newStateRoot, newBlockNumber, publicValues, batchData, proofBlob,
//	proofA (G1 point hex), proofBX0, proofBX1, proofBY0, proofBY1,
//	proofC (G1 point hex),
//	g16Input0, g16Input1, g16Input2, g16Input3, g16Input4.
//
// The BN254 runar types on the contract side are runar.Point (ByteString =
// 128-char hex X||Y) and runar.Bigint (an int64 alias at the Go type
// level, but the compiled Bitcoin Script emits full-width arbitrary-
// precision BN254 field elements via encodePushBigInt). The Rúnar SDK's
// encodeArg dispatch accepts *big.Int directly, so the proof scalars and
// public inputs flow through as 254-bit values without any int64
// truncation.
//
// Nil scalar / coordinate pointers are rejected as errors; zero values
// are permitted and encoded as OP_0.
func (p *Groth16GenericProof) ContractCallArgs(req BroadcastRequest) ([]interface{}, error) {
	if p == nil {
		return nil, errors.New("nil groth16 generic proof")
	}

	newStateRootHex := hex.EncodeToString(req.NewState.StateRoot[:])
	publicValuesHex := hex.EncodeToString(p.Values)
	batchDataHex := hex.EncodeToString(p.Batch)
	proofBlobHex := hex.EncodeToString(p.Blob)

	aHex, err := bn254PointHex(p.ProofAx, p.ProofAy)
	if err != nil {
		return nil, fmt.Errorf("encoding proofA: %w", err)
	}
	cHex, err := bn254PointHex(p.ProofCx, p.ProofCy)
	if err != nil {
		return nil, fmt.Errorf("encoding proofC: %w", err)
	}

	bx0, err := requireBigInt("proofBX0", p.ProofBx0)
	if err != nil {
		return nil, err
	}
	bx1, err := requireBigInt("proofBX1", p.ProofBx1)
	if err != nil {
		return nil, err
	}
	by0, err := requireBigInt("proofBY0", p.ProofBy0)
	if err != nil {
		return nil, err
	}
	by1, err := requireBigInt("proofBY1", p.ProofBy1)
	if err != nil {
		return nil, err
	}

	in0, err := requireBigInt("publicInputs[0]", p.PublicInputs[0])
	if err != nil {
		return nil, err
	}
	in1, err := requireBigInt("publicInputs[1]", p.PublicInputs[1])
	if err != nil {
		return nil, err
	}
	in2, err := requireBigInt("publicInputs[2]", p.PublicInputs[2])
	if err != nil {
		return nil, err
	}
	in3, err := requireBigInt("publicInputs[3]", p.PublicInputs[3])
	if err != nil {
		return nil, err
	}
	in4, err := requireBigInt("publicInputs[4]", p.PublicInputs[4])
	if err != nil {
		return nil, err
	}

	return []interface{}{
		newStateRootHex,
		int64(req.NewState.BlockNumber),
		publicValuesHex,
		batchDataHex,
		proofBlobHex,
		aHex,
		bx0,
		bx1,
		by0,
		by1,
		cHex,
		in0,
		in1,
		in2,
		in3,
		in4,
	}, nil
}

// Groth16WitnessProof carries the proof data for ProofModeGroth16Witness
// (Mode 3, witness-assisted Groth16). Its ContractCallArgs method produces
// the 5-arg slice expected by contracts.Groth16WARollupContract.AdvanceState.
//
// The Witness field holds the BN254 witness bundle that the Rúnar SDK pushes
// onto the stack ON TOP of the regular ABI argument pushes (via
// runar.CallOptions.Groth16WAWitness). It is NOT included in
// ContractCallArgs — the RunarBroadcastClient reads it directly from the
// concrete *Groth16WitnessProof pointer and forwards it to the SDK.
type Groth16WitnessProof struct {
	// SP1 envelope.
	Values []byte
	Batch  []byte
	Blob   []byte

	// Witness is the full BN254 witness bundle generated via
	// bn254witness.GenerateWitness(vk, proof, publicInputs). Nil is
	// permitted at marshaling time (ContractCallArgs does not touch it)
	// but the real RunarBroadcastClient will reject a Mode 3 advance
	// that arrives with Witness == nil.
	Witness *bn254witness.Witness
}

// Mode returns ProofModeGroth16Witness.
func (p *Groth16WitnessProof) Mode() ProofMode { return ProofModeGroth16Witness }

// BatchData returns the canonical batch encoding.
func (p *Groth16WitnessProof) BatchData() []byte { return p.Batch }

// PublicValues returns the raw SP1 public values blob.
func (p *Groth16WitnessProof) PublicValues() []byte { return p.Values }

// ProofBlob returns the raw SP1 proof bytes.
func (p *Groth16WitnessProof) ProofBlob() []byte { return p.Blob }

// ContractCallArgs returns the argument slice for
// Groth16WARollupContract.AdvanceState in the order:
//
//	newStateRoot, newBlockNumber, publicValues, batchData, proofBlob.
//
// The witness bundle is NOT marshaled here — the RunarBroadcastClient
// reads it from the concrete *Groth16WitnessProof and passes it via
// runar.CallOptions.Groth16WAWitness when invoking the contract.
func (p *Groth16WitnessProof) ContractCallArgs(req BroadcastRequest) ([]interface{}, error) {
	if p == nil {
		return nil, errors.New("nil groth16 witness proof")
	}
	newStateRootHex := hex.EncodeToString(req.NewState.StateRoot[:])
	publicValuesHex := hex.EncodeToString(p.Values)
	batchDataHex := hex.EncodeToString(p.Batch)
	proofBlobHex := hex.EncodeToString(p.Blob)

	return []interface{}{
		newStateRootHex,
		int64(req.NewState.BlockNumber),
		publicValuesHex,
		batchDataHex,
		proofBlobHex,
	}, nil
}

// BroadcastRequest contains everything needed to construct a covenant
// advance transaction. The Proof field is discriminated on its Mode() to
// pick the appropriate rollup contract method and argument shape.
type BroadcastRequest struct {
	PrevTxID types.Hash
	PrevVout uint32
	PrevSats uint64

	NewState CovenantState

	// Proof is the mode-specific advance proof. It carries the batch
	// data, public values, and proof blob plus any mode-specific proof
	// components needed by the rollup contract.
	Proof AdvanceProof
}

// BroadcastResult is returned after a successful BroadcastAdvance call.
type BroadcastResult struct {
	TxID types.Hash

	NewCovenantTxID types.Hash
	NewCovenantVout uint32
	NewCovenantSats uint64

	BroadcastAt time.Time
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// bn254PointHex returns the 128-char hex encoding of a BN254 G1 point as
// 32-byte X followed by 32-byte Y, matching the runar.Point type that the
// Groth16 rollup contract accepts for proofA / proofC arguments.
func bn254PointHex(x, y *big.Int) (string, error) {
	if x == nil || y == nil {
		return "", errors.New("nil point coordinate")
	}
	return hex.EncodeToString(paddedBytes(x, 32)) + hex.EncodeToString(paddedBytes(y, 32)), nil
}

// paddedBytes returns a left-zero-padded big-endian byte representation of v
// at exactly size bytes. Negative values are rejected.
func paddedBytes(v *big.Int, size int) []byte {
	if v == nil {
		return make([]byte, size)
	}
	b := v.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// requireBigInt returns a defensive copy of v if non-nil, or an error
// naming the argument if v is nil. The Rúnar SDK's encodeArg dispatch
// accepts *big.Int directly and encodes it via encodeBigIntScriptNumber
// (LE sign-magnitude Bitcoin Script number), so arbitrary-precision BN254
// field elements flow through unchanged.
func requireBigInt(name string, v *big.Int) (*big.Int, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is nil", name)
	}
	return new(big.Int).Set(v), nil
}
