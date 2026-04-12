package rlp

import (
	"fmt"
	"math/bits"
)

// RawValue represents an encoded RLP value and can be used to delay
// RLP decoding or to precompute an encoding. Note that the caller must
// ensure that the value is a valid RLP encoding.
type RawValue []byte

// Kind describes the type of an RLP value.
type Kind int

const (
	// Byte is a single byte value in the range [0x00, 0x7f].
	Byte Kind = iota
	// String is an RLP string (byte sequence).
	String
	// List is an RLP list.
	List
)

func (k Kind) String() string {
	switch k {
	case Byte:
		return "Byte"
	case String:
		return "String"
	case List:
		return "List"
	default:
		return fmt.Sprintf("Unknown(%d)", int(k))
	}
}

// Split returns the kind, content, and remaining bytes after the first
// RLP value in b.
func Split(b []byte) (kind Kind, content, rest []byte, err error) {
	kind, tagSize, contentLen, err := readKind(b)
	if err != nil {
		return 0, nil, nil, err
	}
	end := tagSize + contentLen
	if uint64(len(b)) < end {
		return 0, nil, nil, fmt.Errorf("rlp: value size exceeds available input length")
	}
	return kind, b[tagSize:end], b[end:], nil
}

// SplitString splits b into the content of an RLP string and any
// remaining bytes after the string value.
func SplitString(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, nil, err
	}
	if k == List {
		return nil, nil, fmt.Errorf("rlp: expected string, got list")
	}
	return content, rest, nil
}

// SplitList splits b into the content of an RLP list and any
// remaining bytes after the list value.
func SplitList(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, nil, err
	}
	if k != List {
		return nil, nil, fmt.Errorf("rlp: expected list, got %v", k)
	}
	return content, rest, nil
}

// SplitUint64 decodes an unsigned integer from the beginning of b.
func SplitUint64(b []byte) (val uint64, rest []byte, err error) {
	content, rest, err := SplitString(b)
	if err != nil {
		return 0, nil, err
	}
	switch {
	case len(content) == 0:
		return 0, rest, nil
	case len(content) == 1:
		if content[0] == 0 {
			return 0, nil, fmt.Errorf("rlp: non-canonical integer (leading zero)")
		}
		return uint64(content[0]), rest, nil
	case len(content) > 8:
		return 0, nil, fmt.Errorf("rlp: uint64 overflow")
	default:
		if content[0] == 0 {
			return 0, nil, fmt.Errorf("rlp: non-canonical integer (leading zero)")
		}
		var v uint64
		for _, c := range content {
			v = (v << 8) | uint64(c)
		}
		return v, rest, nil
	}
}

// CountValues counts the number of encoded values in b.
func CountValues(b []byte) (int, error) {
	count := 0
	for len(b) > 0 {
		_, tagSize, contentLen, err := readKind(b)
		if err != nil {
			return 0, err
		}
		end := tagSize + contentLen
		if uint64(len(b)) < end {
			return 0, fmt.Errorf("rlp: value size exceeds available input length")
		}
		b = b[end:]
		count++
	}
	return count, nil
}

// AppendUint64 appends the RLP encoding of i to b.
func AppendUint64(b []byte, i uint64) []byte {
	if i == 0 {
		return append(b, 0x80)
	} else if i < 128 {
		return append(b, byte(i))
	}
	size := putintSize(i)
	buf := make([]byte, size)
	putint(buf, i)
	b = append(b, 0x80+byte(size))
	b = append(b, buf...)
	return b
}

// readKind reads the kind, tag size, and content length from the
// beginning of b.
func readKind(b []byte) (kind Kind, tagSize, contentLen uint64, err error) {
	if len(b) == 0 {
		return 0, 0, 0, fmt.Errorf("rlp: input is empty")
	}
	first := b[0]
	switch {
	case first < 0x80:
		// Single byte, content is the byte itself.
		kind = Byte
		tagSize = 0
		contentLen = 1
	case first <= 0xb7:
		// Short string: 0-55 bytes.
		kind = String
		tagSize = 1
		contentLen = uint64(first - 0x80)
		if contentLen == 1 && len(b) > 1 && b[1] < 0x80 {
			return 0, 0, 0, fmt.Errorf("rlp: non-canonical size for single byte value")
		}
	case first <= 0xbf:
		// Long string: >55 bytes.
		kind = String
		lenOfLen := first - 0xb7
		tagSize = 1 + uint64(lenOfLen)
		contentLen, err = readSize(b[1:], lenOfLen)
		if err != nil {
			return 0, 0, 0, err
		}
	case first <= 0xf7:
		// Short list: 0-55 bytes total.
		kind = List
		tagSize = 1
		contentLen = uint64(first - 0xc0)
	default:
		// Long list: >55 bytes total.
		kind = List
		lenOfLen := first - 0xf7
		tagSize = 1 + uint64(lenOfLen)
		contentLen, err = readSize(b[1:], lenOfLen)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	return kind, tagSize, contentLen, nil
}

// readSize reads a big-endian encoded size from b.
func readSize(b []byte, lenOfLen byte) (uint64, error) {
	if int(lenOfLen) > len(b) {
		return 0, fmt.Errorf("rlp: value size exceeds available input length")
	}
	if lenOfLen > 8 {
		return 0, fmt.Errorf("rlp: size of content length exceeds 8 bytes")
	}
	if b[0] == 0 {
		return 0, fmt.Errorf("rlp: non-canonical size (leading zero)")
	}
	var s uint64
	for i := byte(0); i < lenOfLen; i++ {
		s = (s << 8) | uint64(b[i])
	}
	if s < 56 {
		return 0, fmt.Errorf("rlp: non-canonical size for value < 56 bytes")
	}
	return s, nil
}

// putintSize returns the number of bytes needed to encode i as big-endian.
func putintSize(i uint64) int {
	return (bits.Len64(i) + 7) / 8
}

// putint writes i as big-endian to buf. buf must be the exact size.
func putint(buf []byte, i uint64) {
	for k := len(buf) - 1; k >= 0; k-- {
		buf[k] = byte(i)
		i >>= 8
	}
}

// headSize returns the size of the RLP header for a value with the given
// content length.
func headSize(size uint64) int {
	if size < 56 {
		return 1
	}
	return 1 + putintSize(size)
}
