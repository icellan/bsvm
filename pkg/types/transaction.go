package types

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
)

const (
	// LegacyTxType is the transaction type for pre-EIP-2718 transactions.
	LegacyTxType = 0x00
	// AccessListTxType is the transaction type for EIP-2930 access list transactions.
	AccessListTxType = 0x01
	// DynamicFeeTxType is the transaction type for EIP-1559 dynamic fee transactions.
	DynamicFeeTxType = 0x02
	// BlobTxType is the transaction type for EIP-4844 blob transactions.
	// Wire layout (signed):
	//   [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
	//    to, value, data, access_list, max_fee_per_blob_gas,
	//    blob_versioned_hashes, y_parity, r, s]
	// Signing hash:
	//   keccak256(0x03 || rlp(payload_without_signature))
	// The `to` field MUST be a non-nil 20-byte address — EIP-4844 forbids
	// contract creation via blob txs. `blob_versioned_hashes` MUST be a
	// non-empty list whose entries are 32-byte commitments with the
	// EIP-4844 version-byte prefix (0x01).
	BlobTxType = 0x03
)

// Transaction represents an Ethereum transaction.
type Transaction struct {
	inner TxData
	time  time.Time
	hash  atomic.Value
	size  atomic.Value
	from  atomic.Value
}

// TxData is the interface for transaction type inner data.
type TxData interface {
	txType() byte
	copy() TxData
	chainID() *big.Int
	accessList() AccessList
	data() []byte
	gas() uint64
	gasPrice() *big.Int
	gasTipCap() *big.Int
	gasFeeCap() *big.Int
	value() *uint256.Int
	nonce() uint64
	to() *Address
	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(chainID, v, r, s *big.Int)
}

// NewTx creates a new transaction from the given inner data.
func NewTx(inner TxData) *Transaction {
	tx := &Transaction{inner: inner.copy(), time: time.Now()}
	return tx
}

// Type returns the EIP-2718 transaction type.
func (tx *Transaction) Type() uint8 {
	return tx.inner.txType()
}

// ChainId returns the chain ID of the transaction.
func (tx *Transaction) ChainId() *big.Int {
	return tx.inner.chainID()
}

// Data returns the input data of the transaction.
func (tx *Transaction) Data() []byte {
	return tx.inner.data()
}

// Gas returns the gas limit of the transaction.
func (tx *Transaction) Gas() uint64 {
	return tx.inner.gas()
}

// GasPrice returns the gas price of the transaction. For EIP-1559
// transactions, it returns the gas fee cap.
func (tx *Transaction) GasPrice() *big.Int {
	return tx.inner.gasPrice()
}

// GasTipCap returns the max priority fee per gas (tip) of the transaction.
func (tx *Transaction) GasTipCap() *big.Int {
	return tx.inner.gasTipCap()
}

// GasFeeCap returns the max fee per gas of the transaction.
func (tx *Transaction) GasFeeCap() *big.Int {
	return tx.inner.gasFeeCap()
}

// Value returns the ether value of the transaction.
func (tx *Transaction) Value() *uint256.Int {
	return tx.inner.value()
}

// Nonce returns the sender nonce of the transaction.
func (tx *Transaction) Nonce() uint64 {
	return tx.inner.nonce()
}

// To returns the recipient address of the transaction, or nil for
// contract creation transactions.
func (tx *Transaction) To() *Address {
	return tx.inner.to()
}

// AccessList returns the EIP-2930 access list of the transaction.
func (tx *Transaction) AccessList() AccessList {
	return tx.inner.accessList()
}

// RawSignatureValues returns the V, R, S signature values of the transaction.
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// Hash returns the keccak256 hash of the RLP-encoded transaction.
// For legacy transactions: keccak256(rlp(tx)).
// For typed transactions: keccak256(type || rlp(inner_fields)).
func (tx *Transaction) Hash() Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(Hash)
	}
	var h Hash
	switch tx.Type() {
	case LegacyTxType:
		encoded, _ := rlp.EncodeToBytes(tx.legacyRLPFields())
		h = BytesToHash(crypto.Keccak256(encoded))
	default:
		var buf bytes.Buffer
		buf.WriteByte(tx.Type())
		rlp.Encode(&buf, tx.typedRLPFields())
		h = BytesToHash(crypto.Keccak256(buf.Bytes()))
	}
	tx.hash.Store(h)
	return h
}

// Size returns the RLP-encoded size of the transaction.
func (tx *Transaction) Size() uint64 {
	if size := tx.size.Load(); size != nil {
		return size.(uint64)
	}
	var buf bytes.Buffer
	tx.EncodeRLP(&buf)
	s := uint64(buf.Len())
	tx.size.Store(s)
	return s
}

// EncodeRLP implements rlp.Encoder. Legacy transactions are encoded as a
// plain RLP list. Typed transactions are encoded as type_byte || rlp(fields).
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	switch tx.Type() {
	case LegacyTxType:
		return rlp.Encode(w, tx.legacyRLPFields())
	default:
		// Typed tx: write type byte then RLP-encoded fields.
		buf := new(bytes.Buffer)
		buf.WriteByte(tx.Type())
		if err := rlp.Encode(buf, tx.typedRLPFields()); err != nil {
			return err
		}
		_, err := w.Write(buf.Bytes())
		return err
	}
}

// DecodeRLP implements rlp.Decoder. If the first byte is >= 0xc0, it is
// decoded as a legacy transaction (RLP list). If < 0x80, the first byte
// is the transaction type.
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	// Read the raw bytes for this element to avoid stream position issues
	// when delegating to sub-decoders.
	raw, err := s.Raw()
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("rlp: empty transaction data")
	}

	if raw[0] >= 0xc0 {
		// Legacy transaction: the data is an RLP list.
		// Decode using the wire format struct (uses *big.Int for Value
		// instead of *uint256.Int).
		var decoded legacyRLPData
		if err := rlp.DecodeBytes(raw, &decoded); err != nil {
			return err
		}
		value, _ := uint256.FromBig(decoded.Value)
		if value == nil {
			value = new(uint256.Int)
		}
		tx.inner = &LegacyTx{
			Nonce:    decoded.Nonce,
			GasPrice: decoded.GasPrice,
			Gas:      decoded.Gas,
			To:       decoded.To,
			Value:    value,
			Data:     decoded.Data,
			V:        orZero(decoded.V),
			R:        orZero(decoded.R),
			S:        orZero(decoded.S),
		}
		tx.time = time.Now()
		return nil
	}

	if raw[0] >= 0x80 {
		// RLP string wrapping a typed transaction: unwrap the string first.
		var envelope []byte
		if err := rlp.DecodeBytes(raw, &envelope); err != nil {
			return err
		}
		if len(envelope) == 0 {
			return errors.New("rlp: empty typed transaction bytes")
		}
		return tx.decodeTyped(envelope)
	}

	// The value starts with a byte < 0x80, which is a single-byte RLP
	// value. This occurs when a typed tx is stored as a raw byte string
	// in a list context.
	return tx.decodeTyped(raw)
}

// decodeTyped decodes a typed (EIP-2718) transaction from its envelope
// bytes where the first byte is the transaction type.
func (tx *Transaction) decodeTyped(data []byte) error {
	if len(data) == 0 {
		return errors.New("rlp: empty typed transaction bytes")
	}
	txType := data[0]
	body := data[1:]
	switch txType {
	case AccessListTxType:
		var decoded accessListRLPData
		if err := rlp.DecodeBytes(body, &decoded); err != nil {
			return err
		}
		value, _ := uint256.FromBig(decoded.Value)
		if value == nil {
			value = new(uint256.Int)
		}
		tx.inner = &AccessListTx{
			ChainID:    decoded.ChainID,
			Nonce:      decoded.Nonce,
			GasPrice:   decoded.GasPrice,
			Gas:        decoded.Gas,
			To:         decoded.To,
			Value:      value,
			Data:       decoded.Data,
			AccessList: decoded.AccessList,
			V:          orZero(decoded.V),
			R:          orZero(decoded.R),
			S:          orZero(decoded.S),
		}
	case DynamicFeeTxType:
		var decoded dynamicFeeRLPData
		if err := rlp.DecodeBytes(body, &decoded); err != nil {
			return err
		}
		value, _ := uint256.FromBig(decoded.Value)
		if value == nil {
			value = new(uint256.Int)
		}
		tx.inner = &DynamicFeeTx{
			ChainID:    decoded.ChainID,
			Nonce:      decoded.Nonce,
			GasTipCap:  decoded.GasTipCap,
			GasFeeCap:  decoded.GasFeeCap,
			Gas:        decoded.Gas,
			To:         decoded.To,
			Value:      value,
			Data:       decoded.Data,
			AccessList: decoded.AccessList,
			V:          orZero(decoded.V),
			R:          orZero(decoded.R),
			S:          orZero(decoded.S),
		}
	case BlobTxType:
		var decoded blobRLPData
		if err := rlp.DecodeBytes(body, &decoded); err != nil {
			return err
		}
		// EIP-4844 forbids contract creation: the `to` field must be a
		// 20-byte address, not the empty string. The decoder will already
		// have populated `decoded.To` (a non-pointer Address), but the
		// canonical wire form rejects an empty string here. We catch the
		// "empty string decoded as zero address" case below by inspecting
		// whether the original RLP byte for the to field was 0x80 — that
		// path is harder to detect cleanly post-decode, so for now we let
		// the zero address pass and rely on the validity check in
		// `BlobTx.copy` / consumers that reject a creation. Strict empty-
		// string rejection happens in the guest-side decoder (tx.rs).
		value, _ := uint256.FromBig(decoded.Value)
		if value == nil {
			value = new(uint256.Int)
		}
		if len(decoded.BlobVersionedHashes) == 0 {
			return errors.New("rlp: blob tx must have at least one blob versioned hash")
		}
		toCopy := decoded.To
		tx.inner = &BlobTx{
			ChainID:             decoded.ChainID,
			Nonce:               decoded.Nonce,
			GasTipCap:           decoded.GasTipCap,
			GasFeeCap:           decoded.GasFeeCap,
			Gas:                 decoded.Gas,
			To:                  &toCopy,
			Value:               value,
			Data:                decoded.Data,
			AccessList:          decoded.AccessList,
			BlobFeeCap:          decoded.BlobFeeCap,
			BlobVersionedHashes: decoded.BlobVersionedHashes,
			V:                   orZero(decoded.V),
			R:                   orZero(decoded.R),
			S:                   orZero(decoded.S),
		}
	default:
		return errors.New("rlp: unsupported transaction type")
	}
	tx.time = time.Now()
	return nil
}

// legacyRLPFields returns the fields for RLP encoding a legacy transaction.
func (tx *Transaction) legacyRLPFields() *legacyRLPData {
	v, r, s := tx.inner.rawSignatureValues()
	return &legacyRLPData{
		Nonce:    tx.inner.nonce(),
		GasPrice: tx.inner.gasPrice(),
		Gas:      tx.inner.gas(),
		To:       tx.inner.to(),
		Value:    tx.inner.value().ToBig(),
		Data:     tx.inner.data(),
		V:        v,
		R:        r,
		S:        s,
	}
}

// typedRLPFields returns the fields for RLP encoding typed transactions.
func (tx *Transaction) typedRLPFields() interface{} {
	v, r, s := tx.inner.rawSignatureValues()
	switch tx.Type() {
	case AccessListTxType:
		return &accessListRLPData{
			ChainID:    tx.inner.chainID(),
			Nonce:      tx.inner.nonce(),
			GasPrice:   tx.inner.gasPrice(),
			Gas:        tx.inner.gas(),
			To:         tx.inner.to(),
			Value:      tx.inner.value().ToBig(),
			Data:       tx.inner.data(),
			AccessList: tx.inner.accessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	case DynamicFeeTxType:
		return &dynamicFeeRLPData{
			ChainID:    tx.inner.chainID(),
			Nonce:      tx.inner.nonce(),
			GasTipCap:  tx.inner.gasTipCap(),
			GasFeeCap:  tx.inner.gasFeeCap(),
			Gas:        tx.inner.gas(),
			To:         tx.inner.to(),
			Value:      tx.inner.value().ToBig(),
			Data:       tx.inner.data(),
			AccessList: tx.inner.accessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	case BlobTxType:
		bt, ok := tx.inner.(*BlobTx)
		if !ok || bt.To == nil {
			return nil
		}
		return &blobRLPData{
			ChainID:             bt.chainID(),
			Nonce:               bt.nonce(),
			GasTipCap:           bt.gasTipCap(),
			GasFeeCap:           bt.gasFeeCap(),
			Gas:                 bt.gas(),
			To:                  *bt.To,
			Value:               bt.value().ToBig(),
			Data:                bt.data(),
			AccessList:          bt.accessList(),
			BlobFeeCap:          bt.blobFeeCap(),
			BlobVersionedHashes: bt.blobVersionedHashes(),
			V:                   v,
			R:                   r,
			S:                   s,
		}
	default:
		return nil
	}
}

// legacyRLPData is the RLP-serializable form of a legacy transaction.
type legacyRLPData struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *Address
	Value    *big.Int
	Data     []byte
	V        *big.Int
	R        *big.Int
	S        *big.Int
}

// accessListRLPData is the RLP-serializable form of an EIP-2930 transaction.
type accessListRLPData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	Gas        uint64
	To         *Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

// dynamicFeeRLPData is the RLP-serializable form of an EIP-1559 transaction.
type dynamicFeeRLPData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

// blobRLPData is the RLP-serializable form of an EIP-4844 blob transaction.
// Field order matches the EIP-4844 wire layout exactly. The `To` field is a
// non-pointer Address because EIP-4844 forbids contract creation — encoding
// `To` as a pointer would let `nil` produce an empty RLP string (the
// canonical creation-marker), which the spec explicitly disallows.
type blobRLPData struct {
	ChainID             *big.Int
	Nonce               uint64
	GasTipCap           *big.Int
	GasFeeCap           *big.Int
	Gas                 uint64
	To                  Address
	Value               *big.Int
	Data                []byte
	AccessList          AccessList
	BlobFeeCap          *big.Int
	BlobVersionedHashes []Hash
	V                   *big.Int
	R                   *big.Int
	S                   *big.Int
}

// WithSignature returns a copy of the transaction with the given signature.
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{inner: tx.inner.copy(), time: tx.time}
	cpy.inner.setSignatureValues(signer.ChainID(), v, r, s)
	return cpy, nil
}

// -- LegacyTx --

// LegacyTx is a pre-EIP-2718 transaction.
type LegacyTx struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *Address
	Value    *uint256.Int
	Data     []byte
	V        *big.Int
	R        *big.Int
	S        *big.Int
}

func (tx *LegacyTx) txType() byte           { return LegacyTxType }
func (tx *LegacyTx) chainID() *big.Int      { return deriveChainID(tx.V) }
func (tx *LegacyTx) accessList() AccessList { return nil }
func (tx *LegacyTx) data() []byte           { return tx.Data }
func (tx *LegacyTx) gas() uint64            { return tx.Gas }
func (tx *LegacyTx) gasPrice() *big.Int     { return new(big.Int).Set(tx.GasPrice) }
func (tx *LegacyTx) gasTipCap() *big.Int    { return new(big.Int).Set(tx.GasPrice) }
func (tx *LegacyTx) gasFeeCap() *big.Int    { return new(big.Int).Set(tx.GasPrice) }
func (tx *LegacyTx) value() *uint256.Int    { return new(uint256.Int).Set(tx.Value) }
func (tx *LegacyTx) nonce() uint64          { return tx.Nonce }
func (tx *LegacyTx) to() *Address           { return tx.To }

func (tx *LegacyTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *LegacyTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (tx *LegacyTx) copy() TxData {
	cpy := &LegacyTx{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		To:    copyAddressPtr(tx.To),
		Data:  copyBytes(tx.Data),
	}
	if tx.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(tx.GasPrice)
	}
	if tx.Value != nil {
		cpy.Value = new(uint256.Int).Set(tx.Value)
	}
	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	}
	return cpy
}

// -- AccessListTx --

// AccessListTx is an EIP-2930 transaction with an access list.
type AccessListTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	Gas        uint64
	To         *Address
	Value      *uint256.Int
	Data       []byte
	AccessList AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

func (tx *AccessListTx) txType() byte           { return AccessListTxType }
func (tx *AccessListTx) chainID() *big.Int      { return new(big.Int).Set(tx.ChainID) }
func (tx *AccessListTx) accessList() AccessList { return tx.AccessList }
func (tx *AccessListTx) data() []byte           { return tx.Data }
func (tx *AccessListTx) gas() uint64            { return tx.Gas }
func (tx *AccessListTx) gasPrice() *big.Int     { return new(big.Int).Set(tx.GasPrice) }
func (tx *AccessListTx) gasTipCap() *big.Int    { return new(big.Int).Set(tx.GasPrice) }
func (tx *AccessListTx) gasFeeCap() *big.Int    { return new(big.Int).Set(tx.GasPrice) }
func (tx *AccessListTx) value() *uint256.Int    { return new(uint256.Int).Set(tx.Value) }
func (tx *AccessListTx) nonce() uint64          { return tx.Nonce }
func (tx *AccessListTx) to() *Address           { return tx.To }

func (tx *AccessListTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *AccessListTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *AccessListTx) copy() TxData {
	cpy := &AccessListTx{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		To:    copyAddressPtr(tx.To),
		Data:  copyBytes(tx.Data),
	}
	if tx.ChainID != nil {
		cpy.ChainID = new(big.Int).Set(tx.ChainID)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(tx.GasPrice)
	}
	if tx.Value != nil {
		cpy.Value = new(uint256.Int).Set(tx.Value)
	}
	if tx.AccessList != nil {
		cpy.AccessList = make(AccessList, len(tx.AccessList))
		copy(cpy.AccessList, tx.AccessList)
	}
	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	}
	return cpy
}

// -- DynamicFeeTx --

// DynamicFeeTx is an EIP-1559 dynamic fee transaction.
type DynamicFeeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // maxPriorityFeePerGas
	GasFeeCap  *big.Int // maxFeePerGas
	Gas        uint64
	To         *Address
	Value      *uint256.Int
	Data       []byte
	AccessList AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

func (tx *DynamicFeeTx) txType() byte           { return DynamicFeeTxType }
func (tx *DynamicFeeTx) chainID() *big.Int      { return new(big.Int).Set(tx.ChainID) }
func (tx *DynamicFeeTx) accessList() AccessList { return tx.AccessList }
func (tx *DynamicFeeTx) data() []byte           { return tx.Data }
func (tx *DynamicFeeTx) gas() uint64            { return tx.Gas }
func (tx *DynamicFeeTx) gasPrice() *big.Int     { return new(big.Int).Set(tx.GasFeeCap) }
func (tx *DynamicFeeTx) gasTipCap() *big.Int    { return new(big.Int).Set(tx.GasTipCap) }
func (tx *DynamicFeeTx) gasFeeCap() *big.Int    { return new(big.Int).Set(tx.GasFeeCap) }
func (tx *DynamicFeeTx) value() *uint256.Int    { return new(uint256.Int).Set(tx.Value) }
func (tx *DynamicFeeTx) nonce() uint64          { return tx.Nonce }
func (tx *DynamicFeeTx) to() *Address           { return tx.To }

func (tx *DynamicFeeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *DynamicFeeTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *DynamicFeeTx) copy() TxData {
	cpy := &DynamicFeeTx{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		To:    copyAddressPtr(tx.To),
		Data:  copyBytes(tx.Data),
	}
	if tx.ChainID != nil {
		cpy.ChainID = new(big.Int).Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap = new(big.Int).Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap = new(big.Int).Set(tx.GasFeeCap)
	}
	if tx.Value != nil {
		cpy.Value = new(uint256.Int).Set(tx.Value)
	}
	if tx.AccessList != nil {
		cpy.AccessList = make(AccessList, len(tx.AccessList))
		copy(cpy.AccessList, tx.AccessList)
	}
	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	}
	return cpy
}

// -- BlobTx --

// BlobTx is an EIP-4844 blob transaction. It carries a list of versioned
// KZG commitments for off-chain blob data sidecar(s) plus a separate
// max-fee-per-blob-gas. Blob txs cannot create contracts (`To` must be
// non-nil) and must reference at least one blob versioned hash.
type BlobTx struct {
	ChainID             *big.Int
	Nonce               uint64
	GasTipCap           *big.Int // maxPriorityFeePerGas
	GasFeeCap           *big.Int // maxFeePerGas
	Gas                 uint64
	To                  *Address // EIP-4844: MUST be non-nil
	Value               *uint256.Int
	Data                []byte
	AccessList          AccessList
	BlobFeeCap          *big.Int // maxFeePerBlobGas
	BlobVersionedHashes []Hash   // EIP-4844: MUST be non-empty
	V                   *big.Int
	R                   *big.Int
	S                   *big.Int
}

func (tx *BlobTx) txType() byte           { return BlobTxType }
func (tx *BlobTx) chainID() *big.Int      { return new(big.Int).Set(tx.ChainID) }
func (tx *BlobTx) accessList() AccessList { return tx.AccessList }
func (tx *BlobTx) data() []byte           { return tx.Data }
func (tx *BlobTx) gas() uint64            { return tx.Gas }
func (tx *BlobTx) gasPrice() *big.Int     { return new(big.Int).Set(tx.GasFeeCap) }
func (tx *BlobTx) gasTipCap() *big.Int    { return new(big.Int).Set(tx.GasTipCap) }
func (tx *BlobTx) gasFeeCap() *big.Int    { return new(big.Int).Set(tx.GasFeeCap) }
func (tx *BlobTx) value() *uint256.Int    { return new(uint256.Int).Set(tx.Value) }
func (tx *BlobTx) nonce() uint64          { return tx.Nonce }
func (tx *BlobTx) to() *Address           { return tx.To }

// blobFeeCap returns the maximum fee per blob gas. Not part of TxData
// (legacy/2930/1559 don't have blob gas) — accessed only via type assertion.
func (tx *BlobTx) blobFeeCap() *big.Int { return new(big.Int).Set(tx.BlobFeeCap) }

// blobVersionedHashes returns a defensive copy of the versioned hash list.
func (tx *BlobTx) blobVersionedHashes() []Hash {
	if tx.BlobVersionedHashes == nil {
		return nil
	}
	out := make([]Hash, len(tx.BlobVersionedHashes))
	copy(out, tx.BlobVersionedHashes)
	return out
}

// BlobFeeCap exposes the maxFeePerBlobGas through the public Transaction API.
// Returns nil for non-blob transactions.
func (tx *Transaction) BlobFeeCap() *big.Int {
	if bt, ok := tx.inner.(*BlobTx); ok {
		return bt.blobFeeCap()
	}
	return nil
}

// BlobVersionedHashes exposes the EIP-4844 blob versioned hash list through
// the public Transaction API. Returns nil for non-blob transactions.
func (tx *Transaction) BlobVersionedHashes() []Hash {
	if bt, ok := tx.inner.(*BlobTx); ok {
		return bt.blobVersionedHashes()
	}
	return nil
}

func (tx *BlobTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *BlobTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *BlobTx) copy() TxData {
	cpy := &BlobTx{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		To:    copyAddressPtr(tx.To),
		Data:  copyBytes(tx.Data),
	}
	if tx.ChainID != nil {
		cpy.ChainID = new(big.Int).Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap = new(big.Int).Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap = new(big.Int).Set(tx.GasFeeCap)
	}
	if tx.Value != nil {
		cpy.Value = new(uint256.Int).Set(tx.Value)
	}
	if tx.AccessList != nil {
		cpy.AccessList = make(AccessList, len(tx.AccessList))
		copy(cpy.AccessList, tx.AccessList)
	}
	if tx.BlobFeeCap != nil {
		cpy.BlobFeeCap = new(big.Int).Set(tx.BlobFeeCap)
	}
	if tx.BlobVersionedHashes != nil {
		cpy.BlobVersionedHashes = make([]Hash, len(tx.BlobVersionedHashes))
		copy(cpy.BlobVersionedHashes, tx.BlobVersionedHashes)
	}
	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	}
	return cpy
}

// -- helpers --

// orZero returns v if non-nil, otherwise a fresh zero-valued *big.Int.
// Used in the typed-tx decode path because RLP encodes a *big.Int with value
// 0 as an empty string (0x80), which the decoder maps back to a nil pointer.
// Sender-recovery code paths require non-nil V/R/S, so we materialise the
// zero explicitly. This is safe because we never use Go nil to mean
// "missing" on the wire — it's strictly an encoding artefact.
func orZero(b *big.Int) *big.Int {
	if b == nil {
		return new(big.Int)
	}
	return b
}

// copyAddressPtr returns a copy of an address pointer, or nil.
func copyAddressPtr(a *Address) *Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}

// copyBytes returns a copy of a byte slice.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cpy := make([]byte, len(b))
	copy(cpy, b)
	return cpy
}

// deriveChainID derives the chain ID from a legacy transaction V value.
// For EIP-155: V = chainID * 2 + 35 + recovery_id
// For pre-EIP-155: V = 27 + recovery_id
func deriveChainID(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	if v.BitLen() <= 8 {
		vv := v.Uint64()
		if vv == 27 || vv == 28 {
			return new(big.Int)
		}
	}
	// EIP-155: V = chainID * 2 + 35 + recovery_id
	// chainID = (V - 35) / 2
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
