package types

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
)

// Signer encapsulates transaction signature handling. Different signers
// correspond to different transaction types and replay protection schemes.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (Address, error)
	// SignatureValues returns the raw R, S, V values corresponding to sig.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed for the given transaction.
	Hash(tx *Transaction) Hash
	// Equal returns true if the given signer is the same as this one.
	Equal(Signer) bool
	// ChainID returns the signer's chain id.
	ChainID() *big.Int
}

// LatestSignerForChainID returns the signer that supports the latest
// transaction types for the given chain ID.
func LatestSignerForChainID(chainID *big.Int) Signer {
	return NewLondonSigner(chainID)
}

// MustSignNewTx signs a new transaction with the given signer and private
// key, panicking on any error. This is a test-only helper following the
// standard Go Must* convention — the panic is intentional because
// callers are expected to provide valid inputs in test code.
func MustSignNewTx(key *ecdsa.PrivateKey, signer Signer, txData TxData) *Transaction {
	tx, err := SignNewTx(key, signer, txData)
	if err != nil {
		panic(err)
	}
	return tx
}

// SignNewTx creates and signs a new transaction from the given data.
func SignNewTx(key *ecdsa.PrivateKey, signer Signer, txData TxData) (*Transaction, error) {
	tx := NewTx(txData)
	return SignTx(tx, signer, key)
}

// SignTx signs a transaction with the given signer and private key.
func SignTx(tx *Transaction, signer Signer, key *ecdsa.PrivateKey) (*Transaction, error) {
	h := signer.Hash(tx)
	sig, err := crypto.Sign(h[:], key)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, sig)
}

// Sender returns the sender address of a transaction using the given signer.
func Sender(signer Signer, tx *Transaction) (Address, error) {
	return signer.Sender(tx)
}

// -- LondonSigner --

// londonSigner implements the EIP-1559 London signer, which also handles
// EIP-2930 access list transactions, EIP-155 legacy transactions, and
// pre-EIP-155 (homestead) legacy transactions.
type londonSigner struct {
	chainID    *big.Int
	chainIDMul *big.Int
}

// NewLondonSigner returns a signer that supports EIP-1559 dynamic fee
// transactions, EIP-2930, EIP-155, and pre-EIP-155 legacy transactions.
func NewLondonSigner(chainID *big.Int) Signer {
	if chainID == nil {
		chainID = new(big.Int)
	}
	return &londonSigner{
		chainID:    chainID,
		chainIDMul: new(big.Int).Mul(chainID, big.NewInt(2)),
	}
}

func (s *londonSigner) ChainID() *big.Int {
	return s.chainID
}

func (s *londonSigner) Equal(other Signer) bool {
	o, ok := other.(*londonSigner)
	if !ok {
		return false
	}
	return s.chainID.Cmp(o.chainID) == 0
}

func (s *londonSigner) Sender(tx *Transaction) (Address, error) {
	v, r, ss := tx.RawSignatureValues()
	if r == nil || ss == nil || v == nil {
		return Address{}, errors.New("missing signature values")
	}

	switch tx.Type() {
	case BlobTxType:
		if tx.ChainId().Cmp(s.chainID) != 0 {
			return Address{}, fmt.Errorf("invalid chain id: have %v want %v", tx.ChainId(), s.chainID)
		}
		// EIP-4844 V is the recovery id directly (0 or 1).
		if v.BitLen() > 8 {
			return Address{}, errors.New("invalid v value for blob tx")
		}
		vByte := byte(v.Uint64())
		if !crypto.ValidateSignatureValues(vByte, r, ss, true) {
			return Address{}, errors.New("invalid transaction signature")
		}
		return recoverPlain(s.Hash(tx), r, ss, vByte)

	case DynamicFeeTxType:
		if tx.ChainId().Cmp(s.chainID) != 0 {
			return Address{}, fmt.Errorf("invalid chain id: have %v want %v", tx.ChainId(), s.chainID)
		}
		// For EIP-1559, V is 0 or 1 (recovery id directly).
		if v.BitLen() > 8 {
			return Address{}, errors.New("invalid v value for dynamic fee tx")
		}
		vByte := byte(v.Uint64())
		if !crypto.ValidateSignatureValues(vByte, r, ss, true) {
			return Address{}, errors.New("invalid transaction signature")
		}
		return recoverPlain(s.Hash(tx), r, ss, vByte)

	case AccessListTxType:
		if tx.ChainId().Cmp(s.chainID) != 0 {
			return Address{}, fmt.Errorf("invalid chain id: have %v want %v", tx.ChainId(), s.chainID)
		}
		// For EIP-2930, V is 0 or 1.
		if v.BitLen() > 8 {
			return Address{}, errors.New("invalid v value for access list tx")
		}
		vByte := byte(v.Uint64())
		if !crypto.ValidateSignatureValues(vByte, r, ss, true) {
			return Address{}, errors.New("invalid transaction signature")
		}
		return recoverPlain(s.Hash(tx), r, ss, vByte)

	case LegacyTxType:
		// Check if this is EIP-155 or pre-EIP-155.
		if v.BitLen() <= 8 {
			vv := v.Uint64()
			if vv == 27 || vv == 28 {
				// Pre-EIP-155 (homestead).
				vByte := byte(vv - 27)
				if !crypto.ValidateSignatureValues(vByte, r, ss, true) {
					return Address{}, errors.New("invalid transaction signature")
				}
				return recoverPlain(s.Hash(tx), r, ss, vByte)
			}
		}
		// EIP-155: V = chainID * 2 + 35 + recovery_id
		derivedChainID := deriveChainID(v)
		if derivedChainID.Cmp(s.chainID) != 0 {
			return Address{}, fmt.Errorf("invalid chain id: have %v want %v", derivedChainID, s.chainID)
		}
		vByte := byte(new(big.Int).Sub(v, new(big.Int).Add(s.chainIDMul, big.NewInt(35))).Uint64())
		if !crypto.ValidateSignatureValues(vByte, r, ss, true) {
			return Address{}, errors.New("invalid transaction signature")
		}
		return recoverPlain(s.Hash(tx), r, ss, vByte)

	default:
		return Address{}, fmt.Errorf("unsupported transaction type: %d", tx.Type())
	}
}

func (s *londonSigner) SignatureValues(tx *Transaction, sig []byte) (r, ss, v *big.Int, err error) {
	if len(sig) != 65 {
		return nil, nil, nil, errors.New("wrong size for signature: got " + fmt.Sprint(len(sig)))
	}
	r = new(big.Int).SetBytes(sig[0:32])
	ss = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64]})

	switch tx.Type() {
	case BlobTxType:
		if v.Uint64() > 1 {
			return nil, nil, nil, errors.New("invalid recovery id")
		}
	case DynamicFeeTxType:
		// V is just 0 or 1 for typed transactions.
		if v.Uint64() > 1 {
			return nil, nil, nil, errors.New("invalid recovery id")
		}
	case AccessListTxType:
		if v.Uint64() > 1 {
			return nil, nil, nil, errors.New("invalid recovery id")
		}
	case LegacyTxType:
		// EIP-155: V = chainID * 2 + 35 + recovery_id
		if s.chainID.Sign() != 0 {
			v = new(big.Int).Add(v, new(big.Int).Add(s.chainIDMul, big.NewInt(35)))
		} else {
			v.Add(v, big.NewInt(27))
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported transaction type: %d", tx.Type())
	}
	return r, ss, v, nil
}

func (s *londonSigner) Hash(tx *Transaction) Hash {
	switch tx.Type() {
	case BlobTxType:
		bt, ok := tx.inner.(*BlobTx)
		if !ok || bt.To == nil {
			// Best-effort fallback — should never happen for a well-formed
			// BlobTx; the To check matches the EIP-4844 wire requirement.
			return Hash{}
		}
		return prefixedRLPHash(tx.Type(), &blobSignData{
			ChainID:             s.chainID,
			Nonce:               tx.Nonce(),
			GasTipCap:           tx.GasTipCap(),
			GasFeeCap:           tx.GasFeeCap(),
			Gas:                 tx.Gas(),
			To:                  *bt.To,
			Value:               tx.Value().ToBig(),
			Data:                tx.Data(),
			AccessList:          tx.AccessList(),
			BlobFeeCap:          bt.blobFeeCap(),
			BlobVersionedHashes: bt.blobVersionedHashes(),
		})
	case DynamicFeeTxType:
		return prefixedRLPHash(tx.Type(), &dynamicFeeSignData{
			ChainID:    s.chainID,
			Nonce:      tx.Nonce(),
			GasTipCap:  tx.GasTipCap(),
			GasFeeCap:  tx.GasFeeCap(),
			Gas:        tx.Gas(),
			To:         tx.To(),
			Value:      tx.Value().ToBig(),
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
		})
	case AccessListTxType:
		return prefixedRLPHash(tx.Type(), &accessListSignData{
			ChainID:    s.chainID,
			Nonce:      tx.Nonce(),
			GasPrice:   tx.GasPrice(),
			Gas:        tx.Gas(),
			To:         tx.To(),
			Value:      tx.Value().ToBig(),
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
		})
	case LegacyTxType:
		if s.chainID.Sign() != 0 {
			// EIP-155: include chainID, 0, 0.
			return rlpHash(&legacySignDataEIP155{
				Nonce:    tx.Nonce(),
				GasPrice: tx.GasPrice(),
				Gas:      tx.Gas(),
				To:       tx.To(),
				Value:    tx.Value().ToBig(),
				Data:     tx.Data(),
				ChainID:  s.chainID,
				Zero1:    new(big.Int),
				Zero2:    new(big.Int),
			})
		}
		// Pre-EIP-155.
		return rlpHash(&legacySignData{
			Nonce:    tx.Nonce(),
			GasPrice: tx.GasPrice(),
			Gas:      tx.Gas(),
			To:       tx.To(),
			Value:    tx.Value().ToBig(),
			Data:     tx.Data(),
		})
	default:
		// Fall through to a best-effort hash.
		return rlpHash([]interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value().ToBig(),
			tx.Data(),
		})
	}
}

// -- EIP2930Signer --

// eip2930Signer supports EIP-2930 access list and legacy transactions.
type eip2930Signer struct {
	londonSigner
}

// NewEIP2930Signer returns a signer that supports EIP-2930 access list
// transactions and legacy transactions.
func NewEIP2930Signer(chainID *big.Int) Signer {
	if chainID == nil {
		chainID = new(big.Int)
	}
	return &eip2930Signer{londonSigner{
		chainID:    chainID,
		chainIDMul: new(big.Int).Mul(chainID, big.NewInt(2)),
	}}
}

func (s *eip2930Signer) Equal(other Signer) bool {
	o, ok := other.(*eip2930Signer)
	if !ok {
		return false
	}
	return s.chainID.Cmp(o.chainID) == 0
}

func (s *eip2930Signer) Sender(tx *Transaction) (Address, error) {
	if tx.Type() == DynamicFeeTxType || tx.Type() == BlobTxType {
		return Address{}, fmt.Errorf("eip2930 signer does not support tx type %d", tx.Type())
	}
	return s.londonSigner.Sender(tx)
}

func (s *eip2930Signer) SignatureValues(tx *Transaction, sig []byte) (r, ss, v *big.Int, err error) {
	if tx.Type() == DynamicFeeTxType || tx.Type() == BlobTxType {
		return nil, nil, nil, fmt.Errorf("eip2930 signer does not support tx type %d", tx.Type())
	}
	return s.londonSigner.SignatureValues(tx, sig)
}

// -- EIP155Signer --

// eip155Signer supports EIP-155 replay-protected legacy transactions.
type eip155Signer struct {
	londonSigner
}

// NewEIP155Signer returns a signer that supports EIP-155 replay protection
// for legacy transactions.
func NewEIP155Signer(chainID *big.Int) Signer {
	if chainID == nil {
		chainID = new(big.Int)
	}
	return &eip155Signer{londonSigner{
		chainID:    chainID,
		chainIDMul: new(big.Int).Mul(chainID, big.NewInt(2)),
	}}
}

func (s *eip155Signer) Equal(other Signer) bool {
	o, ok := other.(*eip155Signer)
	if !ok {
		return false
	}
	return s.chainID.Cmp(o.chainID) == 0
}

func (s *eip155Signer) Sender(tx *Transaction) (Address, error) {
	if tx.Type() != LegacyTxType {
		return Address{}, fmt.Errorf("eip155 signer does not support tx type %d", tx.Type())
	}
	return s.londonSigner.Sender(tx)
}

func (s *eip155Signer) SignatureValues(tx *Transaction, sig []byte) (r, ss, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, fmt.Errorf("eip155 signer does not support tx type %d", tx.Type())
	}
	return s.londonSigner.SignatureValues(tx, sig)
}

// -- HomesteadSigner --

// HomesteadSigner implements the pre-EIP-155 homestead signing scheme.
type HomesteadSigner struct{}

// ChainID returns zero for HomesteadSigner (no replay protection).
func (hs HomesteadSigner) ChainID() *big.Int {
	return new(big.Int)
}

// Equal returns true if the other signer is also a HomesteadSigner.
func (hs HomesteadSigner) Equal(other Signer) bool {
	_, ok := other.(HomesteadSigner)
	return ok
}

// Sender recovers the sender address from a homestead-signed transaction.
func (hs HomesteadSigner) Sender(tx *Transaction) (Address, error) {
	if tx.Type() != LegacyTxType {
		return Address{}, fmt.Errorf("homestead signer does not support tx type %d", tx.Type())
	}
	v, r, s := tx.RawSignatureValues()
	if v == nil || r == nil || s == nil {
		return Address{}, errors.New("missing signature values")
	}
	vByte := byte(v.Uint64() - 27)
	if !crypto.ValidateSignatureValues(vByte, r, s, true) {
		return Address{}, errors.New("invalid transaction signature")
	}
	return recoverPlain(hs.Hash(tx), r, s, vByte)
}

// SignatureValues returns the V, R, S signature values for a homestead
// transaction.
func (hs HomesteadSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, fmt.Errorf("homestead signer does not support tx type %d", tx.Type())
	}
	if len(sig) != 65 {
		return nil, nil, nil, errors.New("wrong size for signature")
	}
	r = new(big.Int).SetBytes(sig[0:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v, nil
}

// Hash returns the hash to be signed by a homestead signer.
func (hs HomesteadSigner) Hash(tx *Transaction) Hash {
	return rlpHash(&legacySignData{
		Nonce:    tx.Nonce(),
		GasPrice: tx.GasPrice(),
		Gas:      tx.Gas(),
		To:       tx.To(),
		Value:    tx.Value().ToBig(),
		Data:     tx.Data(),
	})
}

// -- FrontierSigner --

// FrontierSigner implements the original Ethereum signing scheme.
type FrontierSigner struct{}

// ChainID returns zero for FrontierSigner (no replay protection).
func (fs FrontierSigner) ChainID() *big.Int {
	return new(big.Int)
}

// Equal returns true if the other signer is also a FrontierSigner.
func (fs FrontierSigner) Equal(other Signer) bool {
	_, ok := other.(FrontierSigner)
	return ok
}

// Sender recovers the sender address from a frontier-signed transaction.
func (fs FrontierSigner) Sender(tx *Transaction) (Address, error) {
	if tx.Type() != LegacyTxType {
		return Address{}, fmt.Errorf("frontier signer does not support tx type %d", tx.Type())
	}
	v, r, s := tx.RawSignatureValues()
	if v == nil || r == nil || s == nil {
		return Address{}, errors.New("missing signature values")
	}
	vByte := byte(v.Uint64() - 27)
	if !crypto.ValidateSignatureValues(vByte, r, s, false) {
		return Address{}, errors.New("invalid transaction signature")
	}
	return recoverPlain(fs.Hash(tx), r, s, vByte)
}

// SignatureValues returns the V, R, S signature values for a frontier
// transaction.
func (fs FrontierSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, fmt.Errorf("frontier signer does not support tx type %d", tx.Type())
	}
	if len(sig) != 65 {
		return nil, nil, nil, errors.New("wrong size for signature")
	}
	r = new(big.Int).SetBytes(sig[0:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v, nil
}

// Hash returns the hash to be signed by a frontier signer.
func (fs FrontierSigner) Hash(tx *Transaction) Hash {
	return rlpHash(&legacySignData{
		Nonce:    tx.Nonce(),
		GasPrice: tx.GasPrice(),
		Gas:      tx.Gas(),
		To:       tx.To(),
		Value:    tx.Value().ToBig(),
		Data:     tx.Data(),
	})
}

// -- signing data structs --

// legacySignData is used for signing pre-EIP-155 transactions.
type legacySignData struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *Address
	Value    *big.Int
	Data     []byte
}

// legacySignDataEIP155 is used for signing EIP-155 transactions.
type legacySignDataEIP155 struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *Address
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
	Zero1    *big.Int
	Zero2    *big.Int
}

// accessListSignData is used for signing EIP-2930 transactions.
type accessListSignData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	Gas        uint64
	To         *Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
}

// dynamicFeeSignData is used for signing EIP-1559 transactions.
type dynamicFeeSignData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
}

// blobSignData is used for signing EIP-4844 blob transactions. The struct
// fields and order match the EIP-4844 signing-payload layout exactly.
// `To` is non-pointer because EIP-4844 forbids contract creation: the
// signing hash must commit to a 20-byte address, never an empty RLP string.
type blobSignData struct {
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
}

// -- helpers --

// rlpHash computes the keccak256 hash of the RLP encoding of val.
func rlpHash(val interface{}) Hash {
	b, _ := rlp.EncodeToBytes(val)
	return BytesToHash(crypto.Keccak256(b))
}

// prefixedRLPHash computes keccak256(type_byte || rlp(val)).
func prefixedRLPHash(txType byte, val interface{}) Hash {
	var buf bytes.Buffer
	buf.WriteByte(txType)
	rlp.Encode(&buf, val)
	return BytesToHash(crypto.Keccak256(buf.Bytes()))
}

// recoverPlain recovers the sender address from a hash and signature values.
func recoverPlain(sighash Hash, R, S *big.Int, V byte) (Address, error) {
	// Build 65-byte [R || S || V] signature.
	var sig [65]byte
	rBytes := R.Bytes()
	sBytes := S.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = V

	pub, err := crypto.Ecrecover(sighash[:], sig[:])
	if err != nil {
		return Address{}, err
	}
	if len(pub) == 0 || pub[0] != 0x04 {
		return Address{}, errors.New("invalid public key")
	}
	h := crypto.Keccak256(pub[1:])
	return BytesToAddress(h[12:]), nil
}
