package prover

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/types"
)

// TestBuildBridgeInput_W4_1_ProofsRoundTrip verifies that buildBridgeInput
// preserves the Merkle witnesses produced by ExportStateForProving end-to-end
// through the JSON envelope. This is the seam the Rust host bridge consumes —
// if proofs do not survive the JSON encode/decode the SP1 guest will fall
// back to its legacy host-trusted code path and the W4-1 / Gate-0 fix is a
// no-op.
//
// The test:
//  1. Builds a small committed StateDB.
//  2. Calls ExportStateForProving -> serialises into ProveInput.StateExport.
//  3. Runs buildBridgeInput to produce the JSON the Rust bridge would read.
//  4. Decodes the JSON back into a generic structure.
//  5. For each account, re-runs mpt.VerifyProof against the included proof
//     and asserts the proof reconciles with PreStateRoot.
//  6. For each storage slot, re-runs mpt.VerifyProof against the slot proof
//     and the per-account StorageRoot.
func TestBuildBridgeInput_W4_1_ProofsRoundTrip(t *testing.T) {
	sdb, _ := makeCommittedState(t)

	addr1 := types.HexToAddress("0xaaaa")
	addr2 := types.HexToAddress("0xbbbb")
	addr3 := types.HexToAddress("0xcccc")

	export, err := ExportStateForProving(
		sdb,
		[]types.Address{addr1, addr2, addr3},
		map[types.Address][]types.Hash{
			addr2: {types.HexToHash("0x01"), types.HexToHash("0x02")},
		},
	)
	if err != nil {
		t.Fatalf("ExportStateForProving: %v", err)
	}

	exportBytes, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("SerializeExport: %v", err)
	}

	input := &ProveInput{
		PreStateRoot: export.PreStateRoot,
		StateExport:  exportBytes,
		Transactions: nil,
		BlockContext: BlockContext{Number: 1, Timestamp: 100, GasLimit: 30_000_000},
	}

	rawJSON, err := buildBridgeInput(input, "execute")
	if err != nil {
		t.Fatalf("buildBridgeInput: %v", err)
	}

	// Decode the bridge envelope. We assert structurally rather than
	// pulling in the bridge's Rust types.
	var envelope struct {
		PreStateRoot string `json:"pre_state_root"`
		Mode         string `json:"mode"`
		Accounts     []struct {
			Address      string   `json:"address"`
			StorageRoot  string   `json:"storage_root"`
			AccountProof []string `json:"account_proof"`
			StorageSlots []struct {
				Key   string   `json:"key"`
				Value string   `json:"value"`
				Proof []string `json:"proof"`
			} `json:"storage_slots"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(rawJSON, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	if envelope.Mode != "execute" {
		t.Errorf("mode: got %q want %q", envelope.Mode, "execute")
	}
	if !strings.EqualFold(envelope.PreStateRoot, export.PreStateRoot.Hex()) {
		t.Errorf("pre_state_root: got %s want %s", envelope.PreStateRoot, export.PreStateRoot.Hex())
	}
	if len(envelope.Accounts) != 3 {
		t.Fatalf("accounts: got %d want 3", len(envelope.Accounts))
	}

	// Re-verify every account proof against the committed pre_state_root.
	for _, ba := range envelope.Accounts {
		if len(ba.AccountProof) == 0 {
			t.Errorf("%s: account_proof should be non-empty", ba.Address)
			continue
		}

		proofDB := db.NewMemoryDB()
		for _, hexNode := range ba.AccountProof {
			node, err := decodeHexW41(hexNode)
			if err != nil {
				t.Fatalf("decode proof node: %v", err)
			}
			h := crypto.Keccak256(node)
			if err := proofDB.Put(h, node); err != nil {
				t.Fatalf("put: %v", err)
			}
		}

		addr := types.HexToAddress(ba.Address)
		key := crypto.Keccak256(addr[:])
		val, err := mpt.VerifyProof(export.PreStateRoot, key, proofDB)
		if err != nil {
			t.Errorf("%s: VerifyProof failed: %v", ba.Address, err)
			continue
		}
		if len(val) == 0 {
			t.Errorf("%s: expected non-empty value (account exists)", ba.Address)
		}

		// Cross-check storage proofs against the per-account storage_root.
		if len(ba.StorageSlots) == 0 {
			continue
		}
		storageRoot := types.HexToHash(ba.StorageRoot)
		for _, slot := range ba.StorageSlots {
			if len(slot.Proof) == 0 {
				t.Errorf("%s slot %s: proof empty", ba.Address, slot.Key)
				continue
			}
			sdb := db.NewMemoryDB()
			for _, hexNode := range slot.Proof {
				node, err := decodeHexW41(hexNode)
				if err != nil {
					t.Fatalf("decode slot proof node: %v", err)
				}
				h := crypto.Keccak256(node)
				if err := sdb.Put(h, node); err != nil {
					t.Fatalf("put: %v", err)
				}
			}
			slotKey := types.HexToHash(slot.Key)
			hashedKey := crypto.Keccak256(slotKey[:])
			val, err := mpt.VerifyProof(storageRoot, hashedKey, sdb)
			if err != nil {
				t.Errorf("%s slot %s: VerifyProof failed: %v", ba.Address, slot.Key, err)
				continue
			}
			if len(val) == 0 {
				t.Errorf("%s slot %s: expected non-empty value", ba.Address, slot.Key)
			}
		}
	}
}

// TestBuildBridgeInput_NoExportProducesNoProofs verifies that a ProveInput
// without a StateExport (legacy callers / mock-mode fallback) produces a
// bridge envelope with an empty accounts array. This keeps the legacy
// host-trusted SP1 guest path reachable while the W4-1 verifier rolls out.
func TestBuildBridgeInput_NoExportProducesNoProofs(t *testing.T) {
	input := &ProveInput{
		PreStateRoot: types.HexToHash("0xabcd"),
		BlockContext: BlockContext{Number: 1, Timestamp: 100},
	}
	rawJSON, err := buildBridgeInput(input, "core")
	if err != nil {
		t.Fatalf("buildBridgeInput: %v", err)
	}
	var envelope struct {
		Accounts []json.RawMessage `json:"accounts"`
		Mode     string            `json:"mode"`
	}
	if err := json.Unmarshal(rawJSON, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(envelope.Accounts) != 0 {
		t.Errorf("accounts: got %d want 0", len(envelope.Accounts))
	}
	if envelope.Mode != "core" {
		t.Errorf("mode: got %q want %q", envelope.Mode, "core")
	}
}

// decodeHexW41 strips an optional 0x prefix and decodes hex to bytes.
func decodeHexW41(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}
