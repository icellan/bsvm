package rpc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// Block tag constants used in JSON-RPC requests.
const (
	blockTagLatest    = "latest"
	blockTagEarliest  = "earliest"
	blockTagPending   = "pending"
	blockTagSafe      = "safe"
	blockTagConfirmed = "confirmed"
	blockTagFinalized = "finalized"
)

// BlockNumberOrHash resolves block identifiers from JSON-RPC requests.
// It supports named tags ("latest", "earliest", "pending", "safe",
// "finalized"), hex block numbers ("0x1a4"), and block hash objects
// ({"blockHash":"0x..."}).
type BlockNumberOrHash struct {
	BlockNumber      *int64
	BlockHash        *types.Hash
	RequireCanonical bool
}

// UnmarshalJSON parses a block identifier from JSON. It handles string tags,
// hex block numbers, and object-form block hash references.
func (b *BlockNumberOrHash) UnmarshalJSON(data []byte) error {
	// Try as a string first (tag or hex number).
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		return b.parseString(str)
	}

	// Try as an object: {"blockHash":"0x...", "requireCanonical": true}
	var obj struct {
		BlockHash        *types.Hash `json:"blockHash"`
		BlockNumber      *string     `json:"blockNumber"`
		RequireCanonical bool        `json:"requireCanonical"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("invalid block identifier: %s", string(data))
	}

	if obj.BlockHash != nil {
		b.BlockHash = obj.BlockHash
		b.RequireCanonical = obj.RequireCanonical
		return nil
	}
	if obj.BlockNumber != nil {
		return b.parseString(*obj.BlockNumber)
	}
	return fmt.Errorf("invalid block identifier: must have blockHash or blockNumber")
}

// parseString handles string-form block identifiers: named tags and hex numbers.
func (b *BlockNumberOrHash) parseString(s string) error {
	switch s {
	case blockTagLatest:
		n := int64(-1)
		b.BlockNumber = &n
	case blockTagEarliest:
		n := int64(0)
		b.BlockNumber = &n
	case blockTagPending:
		n := int64(-1) // same as latest
		b.BlockNumber = &n
	case blockTagSafe:
		n := int64(-2)
		b.BlockNumber = &n
	case blockTagConfirmed:
		n := int64(-4)
		b.BlockNumber = &n
	case blockTagFinalized:
		n := int64(-3)
		b.BlockNumber = &n
	default:
		// Must be a hex number like "0x1a4".
		num, err := parseHexUint64(s)
		if err != nil {
			return fmt.Errorf("invalid block number %q: %w", s, err)
		}
		n := int64(num)
		b.BlockNumber = &n
	}
	return nil
}

// BlockNumberOrHashWithNumber creates a BlockNumberOrHash from a block number.
func BlockNumberOrHashWithNumber(n int64) BlockNumberOrHash {
	return BlockNumberOrHash{BlockNumber: &n}
}

// BlockNumberOrHashWithHash creates a BlockNumberOrHash from a block hash.
func BlockNumberOrHashWithHash(h types.Hash) BlockNumberOrHash {
	return BlockNumberOrHash{BlockHash: &h}
}

// EncodeUint64 returns a hex string with 0x prefix and no leading zeros
// for the given uint64 value. Zero is encoded as "0x0".
func EncodeUint64(v uint64) string {
	if v == 0 {
		return "0x0"
	}
	return "0x" + strconv.FormatUint(v, 16)
}

// EncodeBig returns a hex string with 0x prefix for the given big.Int.
// Nil is encoded as "0x0".
func EncodeBig(v *big.Int) string {
	if v == nil || v.Sign() == 0 {
		return "0x0"
	}
	return "0x" + v.Text(16)
}

// EncodeBytes returns "0x" + hex encoding of the byte slice.
// An empty or nil slice returns "0x".
func EncodeBytes(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return "0x" + fmt.Sprintf("%x", b)
}

// EncodeHash returns the full 0x-prefixed, zero-padded hex representation
// of a 32-byte hash.
func EncodeHash(h types.Hash) string {
	return h.Hex()
}

// EncodeAddress returns the EIP-55 checksum-encoded address string.
func EncodeAddress(a types.Address) string {
	return checksumAddress(a)
}

// parseHexUint64 parses a 0x-prefixed hex string to uint64.
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) == 0 {
		return 0, fmt.Errorf("empty hex string")
	}
	return strconv.ParseUint(s, 16, 64)
}

// parseHexBig parses a 0x-prefixed hex string to *big.Int.
func parseHexBig(s string) (*big.Int, bool) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) == 0 {
		return new(big.Int), true
	}
	return new(big.Int).SetString(s, 16)
}

// checksumAddress returns the EIP-55 mixed-case checksum encoding of an address.
func checksumAddress(a types.Address) string {
	hex := fmt.Sprintf("%x", a[:])
	hash := crypto.Keccak256([]byte(hex))

	result := make([]byte, 2+len(hex))
	result[0] = '0'
	result[1] = 'x'
	for i, c := range []byte(hex) {
		// If the corresponding nibble in the hash is >= 8, uppercase the character.
		hashByte := hash[i/2]
		var nibble byte
		if i%2 == 0 {
			nibble = hashByte >> 4
		} else {
			nibble = hashByte & 0x0f
		}
		if nibble >= 8 && c >= 'a' && c <= 'f' {
			result[2+i] = c - 32 // uppercase
		} else {
			result[2+i] = c
		}
	}
	return string(result)
}

// decodeHexBytes decodes a 0x-prefixed hex string to bytes.
func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi, err := hexNibble(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[2*i+1])
		if err != nil {
			return nil, err
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

// hexNibble converts a hex character to its numeric value.
func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}
