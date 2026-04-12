package prover

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/icellan/bsvm/pkg/types"
)

// PublicValuesSize is the fixed size of the SP1 guest's public values output.
const PublicValuesSize = 272

// PublicValues represents the 272-byte public values committed by the SP1 guest.
// The layout matches the covenant's fixed byte-offset parsing exactly.
type PublicValues struct {
	PreStateRoot      types.Hash // [0..32)
	PostStateRoot     types.Hash // [32..64)
	ReceiptsHash      types.Hash // [64..96)
	GasUsed           uint64     // [96..104) big-endian
	BatchDataHash     types.Hash // [104..136)
	ChainID           uint64     // [136..144) big-endian
	WithdrawalRoot    types.Hash // [144..176)
	InboxRootBefore   types.Hash // [176..208)
	InboxRootAfter    types.Hash // [208..240)
	MigrateScriptHash types.Hash // [240..272)
}

// ParsePublicValues decodes a 272-byte public values blob into a structured
// PublicValues. Returns an error if the data is not exactly 272 bytes.
func ParsePublicValues(data []byte) (*PublicValues, error) {
	if len(data) != PublicValuesSize {
		return nil, errors.New("public values must be exactly 272 bytes")
	}
	pv := &PublicValues{}
	copy(pv.PreStateRoot[:], data[0:32])
	copy(pv.PostStateRoot[:], data[32:64])
	copy(pv.ReceiptsHash[:], data[64:96])
	pv.GasUsed = binary.BigEndian.Uint64(data[96:104])
	copy(pv.BatchDataHash[:], data[104:136])
	pv.ChainID = binary.BigEndian.Uint64(data[136:144])
	copy(pv.WithdrawalRoot[:], data[144:176])
	copy(pv.InboxRootBefore[:], data[176:208])
	copy(pv.InboxRootAfter[:], data[208:240])
	copy(pv.MigrateScriptHash[:], data[240:272])
	return pv, nil
}

// Encode serializes PublicValues to a 272-byte blob with big-endian uint64s.
func (pv *PublicValues) Encode() []byte {
	buf := make([]byte, PublicValuesSize)
	copy(buf[0:32], pv.PreStateRoot[:])
	copy(buf[32:64], pv.PostStateRoot[:])
	copy(buf[64:96], pv.ReceiptsHash[:])
	binary.BigEndian.PutUint64(buf[96:104], pv.GasUsed)
	copy(buf[104:136], pv.BatchDataHash[:])
	binary.BigEndian.PutUint64(buf[136:144], pv.ChainID)
	copy(buf[144:176], pv.WithdrawalRoot[:])
	copy(buf[176:208], pv.InboxRootBefore[:])
	copy(buf[208:240], pv.InboxRootAfter[:])
	copy(buf[240:272], pv.MigrateScriptHash[:])
	return buf
}

// Proof wraps the serialized SP1 proof with metadata.
type Proof struct {
	// Data is the raw SP1 proof bytes.
	Data []byte `json:"data"`
	// PublicValues contains the committed public outputs.
	PublicValues PublicValues `json:"public_values"`
	// VKHash is the verification key hash.
	VKHash types.Hash `json:"vk_hash"`
	// Mode is the proof type: "compressed", "core", or "groth16".
	Mode string `json:"mode"`
}

// SerializeProof serializes a proof to JSON bytes for storage or transmission.
func SerializeProof(proof *Proof) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("cannot serialize nil proof")
	}
	return json.Marshal(proof)
}

// DeserializeProof deserializes a proof from JSON bytes.
func DeserializeProof(data []byte) (*Proof, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot deserialize empty proof data")
	}
	var proof Proof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
