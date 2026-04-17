//go:build integration

package integration

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Bytecode constants
// ---------------------------------------------------------------------------

// revertContractCode deploys a contract that always REVERTs with 4 bytes of
// error data (0xdeadbeef).
//
// Init (12 bytes): 600d600c600039600d6000f3
//   PUSH1 0x0d   — runtime length (13)
//   PUSH1 0x0c   — runtime starts at byte 12
//   PUSH1 0x00   — memory destination
//   CODECOPY
//   PUSH1 0x0d   — return size
//   PUSH1 0x00   — return offset
//   RETURN
//
// Runtime (13 bytes): 63deadbeef6000526004601cfd
//   PUSH4 0xdeadbeef
//   PUSH1 0x00
//   MSTORE        — stores deadbeef right-aligned in mem[0:32] (bytes 28-31)
//   PUSH1 0x04    — revert data size
//   PUSH1 0x1c    — revert data offset (28)
//   REVERT
var revertContractCode = mustHex("600d600c600039600d6000f363deadbeef6000526004601cfd")

// infiniteLoopContractCode deploys a contract that loops forever.
//
// Init (12 bytes): 6004600c60003960046000f3
// Runtime (4 bytes): 5b600056
//   JUMPDEST (offset 0)
//   PUSH1 0x00
//   JUMP (back to 0)
var infiniteLoopContractCode = mustHex("6004600c60003960046000f35b600056")

// create2FactoryCode deploys a factory that uses CREATE2 to deploy a child
// contract. The salt is read from calldata[0:32]. The child init code is a
// single 0x00 byte (STOP), stored in memory via MSTORE8.
//
// Init (12 bytes): 6017600c60003960176000f3
// Runtime (23 bytes): 6000600053600035600160006000f56000526014600cf3
//   PUSH1 0x00 ; PUSH1 0x00 ; MSTORE8    — mem[0] = 0x00
//   PUSH1 0x00 ; CALLDATALOAD             — salt from calldata[0:32]
//   PUSH1 0x01                             — code length 1
//   PUSH1 0x00                             — code mem offset
//   PUSH1 0x00                             — value 0
//   CREATE2
//   PUSH1 0x00 ; MSTORE                   — store returned address at mem[0:32]
//   PUSH1 0x14 ; PUSH1 0x0c ; RETURN      — return 20 bytes from offset 12
var create2FactoryCode = mustHex("6017600c60003960176000f36000600053600035600160006000f56000526014600cf3")

// callerContractCode deploys a contract that CALLs another contract address
// provided as calldata[0:32] (right-aligned address).
//
// Init (12 bytes): 6017600c60003960176000f3
// Runtime (23 bytes):
//   PUSH1 0 (retSize)
//   PUSH1 0 (retOffset)
//   PUSH1 0 (argSize)
//   PUSH1 0 (argOffset)
//   PUSH1 0 (value)
//   PUSH1 0 ; CALLDATALOAD (loads address from calldata)
//   GAS
//   CALL
//   PUSH1 0 ; MSTORE       — store call result
//   PUSH1 0x20 ; PUSH1 0 ; RETURN
var callerContractCode = mustHex("6017600c60003960176000f3600060006000600060006000355af160005260206000f3")

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEVM_RevertWithData deploys a contract that always REVERTs with 4 bytes
// of error data (0xdeadbeef) and verifies the receipt shows failure.
func TestEVM_RevertWithData(t *testing.T) {
	bundle := happyPathSetup(t)

	// Deploy the revert contract.
	deployTx := signCreate(t, bundle, 0, revertContractCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy ProcessBatch: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", r1.Receipts[0].Status)
	}
	contractAddr := r1.Receipts[0].ContractAddress
	if contractAddr == (types.Address{}) {
		t.Fatal("deploy receipt has zero ContractAddress")
	}

	// Call the contract — it should REVERT.
	callTx := signCall(t, bundle, 1, contractAddr, nil)
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{callTx})
	if err != nil {
		t.Fatalf("call ProcessBatch: %v", err)
	}
	if got := r2.Receipts[0].Status; got != 0 {
		t.Errorf("receipt status = %d, want 0 (reverted)", got)
	}
	if got := r2.Receipts[0].GasUsed; got < 21000 {
		t.Errorf("receipt gasUsed = %d, want >= 21000", got)
	}
}

// TestEVM_OutOfGas deploys an infinite-loop contract and calls it with
// limited gas. The call must fail with all gas consumed.
func TestEVM_OutOfGas(t *testing.T) {
	bundle := happyPathSetup(t)

	// Deploy the infinite-loop contract.
	deployTx := signCreate(t, bundle, 0, infiniteLoopContractCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy ProcessBatch: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", r1.Receipts[0].Status)
	}
	contractAddr := r1.Receipts[0].ContractAddress
	if contractAddr == (types.Address{}) {
		t.Fatal("deploy receipt has zero ContractAddress")
	}

	// Call with exactly 50_000 gas — it will loop until OOG.
	const callGas = uint64(50_000)
	callTx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      callGas,
		To:       &contractAddr,
		Value:    uint256.NewInt(0),
		Data:     nil,
	})

	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{callTx})
	if err != nil {
		t.Fatalf("call ProcessBatch: %v", err)
	}
	if got := r2.Receipts[0].Status; got != 0 {
		t.Errorf("receipt status = %d, want 0 (out of gas)", got)
	}
	if got := r2.Receipts[0].GasUsed; got != callGas {
		t.Errorf("receipt gasUsed = %d, want %d (all gas consumed)", got, callGas)
	}
}

// TestEVM_CREATE2Deterministic deploys a CREATE2 factory, calls it with a
// known salt, and verifies the child is deployed at the predicted address.
func TestEVM_CREATE2Deterministic(t *testing.T) {
	bundle := happyPathSetup(t)

	// Deploy the CREATE2 factory.
	deployTx := signCreate(t, bundle, 0, create2FactoryCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy ProcessBatch: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", r1.Receipts[0].Status)
	}
	factoryAddr := r1.Receipts[0].ContractAddress
	if factoryAddr == (types.Address{}) {
		t.Fatal("deploy receipt has zero ContractAddress")
	}

	// Call factory with salt = 42 (as a 32-byte big-endian word).
	salt := make([]byte, 32)
	binary.BigEndian.PutUint64(salt[24:], 42)

	callTx := signCall(t, bundle, 1, factoryAddr, salt)
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{callTx})
	if err != nil {
		t.Fatalf("call ProcessBatch: %v", err)
	}
	if got := r2.Receipts[0].Status; got != 1 {
		t.Fatalf("CREATE2 call receipt status = %d, want 1", got)
	}

	// Predict child address: keccak256(0xff ++ factory ++ salt ++ keccak256(0x00))[12:]
	var salt32 [32]byte
	copy(salt32[:], salt)
	initCodeHash := crypto.Keccak256([]byte{0x00})
	expectedAddr := types.Address(crypto.CreateAddress2(factoryAddr, salt32, initCodeHash))

	// Verify the child contract exists by checking its nonce (set to 1 by CREATE2).
	sdb := stateAt(t, bundle, r2.StateRoot)
	if got := sdb.GetNonce(expectedAddr); got != 1 {
		t.Errorf("child nonce = %d, want 1 (at predicted address %s)", got, expectedAddr.Hex())
	}
}

// TestEVM_ContractCallsContract deploys a storage target and a caller
// contract, then has the caller invoke the target via CALL.
func TestEVM_ContractCallsContract(t *testing.T) {
	bundle := happyPathSetup(t)

	// Deploy the storage target contract.
	deployTargetTx := signCreate(t, bundle, 0, storageContractCreationCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTargetTx})
	if err != nil {
		t.Fatalf("deploy target ProcessBatch: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy target status = %d, want 1", r1.Receipts[0].Status)
	}
	targetAddr := r1.Receipts[0].ContractAddress

	// Deploy the caller contract.
	deployCallerTx := signCreate(t, bundle, 1, callerContractCode)
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{deployCallerTx})
	if err != nil {
		t.Fatalf("deploy caller ProcessBatch: %v", err)
	}
	if r2.Receipts[0].Status != 1 {
		t.Fatalf("deploy caller status = %d, want 1", r2.Receipts[0].Status)
	}
	callerAddr := r2.Receipts[0].ContractAddress

	// Call the caller contract with the target address (32 bytes, right-aligned).
	calldata := make([]byte, 32)
	copy(calldata[12:], targetAddr[:])

	callTx := signCall(t, bundle, 2, callerAddr, calldata)
	r3, err := bundle.Node.ProcessBatch([]*types.Transaction{callTx})
	if err != nil {
		t.Fatalf("cross-contract call ProcessBatch: %v", err)
	}
	if got := r3.Receipts[0].Status; got != 1 {
		t.Errorf("cross-contract call receipt status = %d, want 1", got)
	}
}

// TestEVM_TransferToSelf sends a 0-value transfer from the sender to itself.
// This is a valid transaction that should succeed with exactly 21000 gas.
func TestEVM_TransferToSelf(t *testing.T) {
	bundle := happyPathSetup(t)

	tx := signTransfer(t, bundle, 0, bundle.TxAddr, uint256.NewInt(0))
	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	r := result.Receipts[0]
	if r.Status != 1 {
		t.Errorf("receipt status = %d, want 1", r.Status)
	}
	if r.GasUsed != 21000 {
		t.Errorf("receipt gasUsed = %d, want 21000", r.GasUsed)
	}
}

// TestEVM_ZeroValueContractCreation deploys the storage contract with zero
// value and verifies the contract is created with zero balance.
func TestEVM_ZeroValueContractCreation(t *testing.T) {
	bundle := happyPathSetup(t)

	deployTx := signCreate(t, bundle, 0, storageContractCreationCode)
	result, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	r := result.Receipts[0]
	if r.Status != 1 {
		t.Fatalf("receipt status = %d, want 1", r.Status)
	}
	contractAddr := r.ContractAddress
	if contractAddr == (types.Address{}) {
		t.Fatal("contract address is zero")
	}

	sdb := stateAt(t, bundle, result.StateRoot)
	if got := sdb.GetBalance(contractAddr); got.Sign() != 0 {
		t.Errorf("contract balance = %s, want 0", got)
	}
}
