package types

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
)

const (
	// DepositTxType is the EIP-2718 transaction type for deposit system
	// transactions. Uses 0x7E (126), matching the Optimism deposit tx
	// type convention.
	DepositTxType = 0x7E
)

// BridgeSystemAddress is the system sender for deposit transactions.
// This address has no private key and is used solely to identify
// system-originated deposit transactions.
var BridgeSystemAddress = HexToAddress("0x000000000000000000000000000000000000dEaD")

// BridgeContractAddress is the L2 bridge predeploy address.
var BridgeContractAddress = HexToAddress("0x4200000000000000000000000000000000000010")

// SatoshiToWeiMultiplier is the conversion factor: 1 satoshi = 10^10 L2 wei.
var SatoshiToWeiMultiplier = uint256.NewInt(1e10)

// DepositTransaction represents a deposit system transaction that credits
// an L2 account with wBSV. These transactions bypass the EVM entirely
// and are applied as direct state mutations.
type DepositTransaction struct {
	// SourceHash is the BSV deposit txid, used for deduplication.
	SourceHash Hash
	// From is the system sender address (BridgeSystemAddress).
	From Address
	// To is the recipient L2 address from the deposit OP_RETURN.
	To Address
	// Value is the deposit amount in L2 wei (satoshis * 10^10).
	Value *uint256.Int
	// Gas is always 0 for deposit transactions.
	Gas uint64
	// IsSystemTx is always true for deposit transactions.
	IsSystemTx bool
	// Data is empty for deposit transactions.
	Data []byte
}

// depositTxRLP is the RLP-serializable form of a deposit transaction.
type depositTxRLP struct {
	SourceHash Hash
	From       Address
	To         Address
	Value      *uint256.Int
	Gas        uint64
	IsSystemTx bool
	Data       []byte
}

// Hash returns keccak256(0x7E || RLP([sourceHash, from, to, value, gas, isSystemTx, data])).
func (tx *DepositTransaction) Hash() Hash {
	var buf bytes.Buffer
	buf.WriteByte(DepositTxType)
	rlp.Encode(&buf, &depositTxRLP{
		SourceHash: tx.SourceHash,
		From:       tx.From,
		To:         tx.To,
		Value:      tx.Value,
		Gas:        tx.Gas,
		IsSystemTx: tx.IsSystemTx,
		Data:       tx.Data,
	})
	return BytesToHash(crypto.Keccak256(buf.Bytes()))
}

// EncodeRLP writes the RLP encoding of the deposit transaction prefixed
// with the type byte 0x7E.
func (tx *DepositTransaction) EncodeRLP(w io.Writer) error {
	buf := new(bytes.Buffer)
	buf.WriteByte(DepositTxType)
	if err := rlp.Encode(buf, &depositTxRLP{
		SourceHash: tx.SourceHash,
		From:       tx.From,
		To:         tx.To,
		Value:      tx.Value,
		Gas:        tx.Gas,
		IsSystemTx: tx.IsSystemTx,
		Data:       tx.Data,
	}); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// SatoshisToWei converts satoshis to L2 wei. 1 satoshi = 10^10 wei.
func SatoshisToWei(satoshis uint64) *uint256.Int {
	return new(uint256.Int).Mul(
		uint256.NewInt(satoshis),
		SatoshiToWeiMultiplier,
	)
}

// WeiToSatoshis converts L2 wei to satoshis. 1 satoshi = 10^10 wei.
// Fractional satoshis are truncated (floor division). Values whose
// integer satoshi quotient exceeds math.MaxUint64 saturate to
// math.MaxUint64 rather than silently wrapping via the low 64 bits
// of the uint256 division result.
func WeiToSatoshis(wei *uint256.Int) uint64 {
	if wei == nil || wei.IsZero() {
		return 0
	}
	result := new(uint256.Int).Div(wei, SatoshiToWeiMultiplier)
	// Saturate to math.MaxUint64 when the satoshi quotient does not fit
	// in a uint64. uint256.Int.Uint64() returns only the low 64 bits,
	// which silently wraps for huge inputs; guard with IsUint64().
	if !result.IsUint64() {
		return math.MaxUint64
	}
	return result.Uint64()
}

// DepositTxID computes a deterministic source hash for a deposit from
// a BSV transaction ID. This is used as the SourceHash in the deposit
// transaction. The result is keccak256("BSVM-deposit" || txid).
func DepositTxID(bsvTxID Hash) Hash {
	prefix := []byte("BSVM-deposit")
	data := make([]byte, len(prefix)+HashLength)
	copy(data, prefix)
	copy(data[len(prefix):], bsvTxID[:])
	return BytesToHash(crypto.Keccak256(data))
}

// Uint64ToBE encodes a uint64 as an 8-byte big-endian byte slice.
func Uint64ToBE(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}
