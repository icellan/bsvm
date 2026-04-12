package prover

import (
	"encoding/json"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// StateExport contains the subset of state needed by the SP1 guest,
// including Merkle proofs so the guest can verify the pre-state root
// without trusting the host.
type StateExport struct {
	// PreStateRoot is the state trie root before execution.
	PreStateRoot types.Hash `json:"pre_state_root"`
	// Accounts holds the accessed accounts with their Merkle proofs.
	Accounts []AccountExport `json:"accounts"`
}

// AccountExport holds account state and its Merkle proof from the state root.
type AccountExport struct {
	// Address is the account's address.
	Address types.Address `json:"address"`
	// Nonce is the account nonce.
	Nonce uint64 `json:"nonce"`
	// Balance is the account balance.
	Balance *uint256.Int `json:"balance"`
	// CodeHash is the keccak256 hash of the account's code.
	CodeHash types.Hash `json:"code_hash"`
	// StorageRoot is the root of the account's storage trie.
	StorageRoot types.Hash `json:"storage_root"`
	// Code is the full contract bytecode (empty for EOAs).
	Code []byte `json:"code,omitempty"`
	// AccountProof is the Merkle proof from state root to this account.
	AccountProof [][]byte `json:"account_proof"`
	// StorageSlots holds the accessed storage slots with proofs.
	StorageSlots []StorageSlotExport `json:"storage_slots,omitempty"`
}

// StorageSlotExport holds a storage slot value and its Merkle proof from the
// account's storage root.
type StorageSlotExport struct {
	// Key is the storage slot key.
	Key types.Hash `json:"key"`
	// Value is the storage slot value.
	Value types.Hash `json:"value"`
	// Proof is the Merkle proof from storage root to this slot.
	Proof [][]byte `json:"proof"`
}

// ExportStateForProving creates a state export for the SP1 guest. It extracts
// the specified accounts and storage slots from the state database along with
// their Merkle proofs.
//
// IMPORTANT: The statedb parameter MUST be opened at the PRE-STATE root
// (before execution), not the post-execution statedb. The Merkle proofs must
// prove account/storage values in the pre-state trie so the SP1 guest can
// verify it starts from the correct state root.
func ExportStateForProving(
	statedb *state.StateDB,
	accessedAccounts []types.Address,
	accessedSlots map[types.Address][]types.Hash,
) (*StateExport, error) {
	export := &StateExport{
		// Always true: this L2 runs post-Spurious Dragon (EIP-161).
		PreStateRoot: statedb.IntermediateRoot(true),
	}

	for _, addr := range accessedAccounts {
		// Generate Merkle proof for this account in the state trie.
		accountProof, err := statedb.GetProof(addr)
		if err != nil {
			return nil, err
		}

		acct := AccountExport{
			Address:      addr,
			Nonce:        statedb.GetNonce(addr),
			Balance:      statedb.GetBalance(addr),
			CodeHash:     statedb.GetCodeHash(addr),
			StorageRoot:  statedb.GetStorageRoot(addr),
			Code:         statedb.GetCode(addr),
			AccountProof: accountProof,
		}

		// Export accessed storage slots for this account.
		for _, slot := range accessedSlots[addr] {
			storageProof, err := statedb.GetStorageProof(addr, slot)
			if err != nil {
				return nil, err
			}
			acct.StorageSlots = append(acct.StorageSlots, StorageSlotExport{
				Key:   slot,
				Value: statedb.GetState(addr, slot),
				Proof: storageProof,
			})
		}

		export.Accounts = append(export.Accounts, acct)
	}

	return export, nil
}

// SerializeExport serializes a StateExport to JSON bytes for the host bridge.
func SerializeExport(export *StateExport) ([]byte, error) {
	if export == nil {
		return nil, nil
	}
	return json.Marshal(export)
}

// DeserializeExport deserializes a StateExport from JSON bytes.
func DeserializeExport(data []byte) (*StateExport, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var export StateExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, err
	}
	return &export, nil
}
