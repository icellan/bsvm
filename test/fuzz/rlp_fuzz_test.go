package fuzz

import (
	"bytes"
	"testing"

	"github.com/icellan/bsvm/pkg/rlp"
)

// FuzzRLPRoundtrip tests RLP encode/decode roundtrip with random byte slices.
// It encodes the input as a byte slice, decodes it back, re-encodes, and
// verifies the two encodings are identical. This catches any non-determinism
// or data loss in the RLP codec.
func FuzzRLPRoundtrip(f *testing.F) {
	// Seed with known values covering RLP edge cases.
	f.Add([]byte{})                             // empty bytes
	f.Add([]byte{0x00})                         // single zero byte
	f.Add([]byte{0x7f})                         // single byte < 0x80 (direct encoding)
	f.Add([]byte{0x80})                         // single byte = 0x80
	f.Add([]byte{0xff})                         // single byte max
	f.Add(make([]byte, 55))                     // exactly 55 bytes (short string boundary)
	f.Add(make([]byte, 56))                     // 56 bytes (long string threshold)
	f.Add(bytes.Repeat([]byte{0xAB}, 256))      // longer string
	f.Add(bytes.Repeat([]byte{0xCD}, 1024))     // 1KB string
	f.Add([]byte("hello world"))                // ASCII text
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05}) // short sequence

	f.Fuzz(func(t *testing.T, data []byte) {
		// Encode the input bytes.
		encoded, err := rlp.EncodeToBytes(data)
		if err != nil {
			// Some inputs may legitimately fail to encode; that is fine
			// as long as it does not panic.
			return
		}

		// Decode the encoded bytes.
		var decoded []byte
		err = rlp.DecodeBytes(encoded, &decoded)
		if err != nil {
			t.Fatalf("failed to decode valid RLP encoding: %v", err)
		}

		// The decoded bytes must equal the original input.
		if !bytes.Equal(data, decoded) {
			t.Fatalf("roundtrip mismatch: input %x, decoded %x", data, decoded)
		}

		// Re-encode the decoded bytes and verify determinism.
		reEncoded, err := rlp.EncodeToBytes(decoded)
		if err != nil {
			t.Fatalf("failed to re-encode: %v", err)
		}
		if !bytes.Equal(encoded, reEncoded) {
			t.Fatalf("non-deterministic encoding: first %x, second %x", encoded, reEncoded)
		}
	})
}

// FuzzRLPUintRoundtrip tests RLP encode/decode roundtrip for uint64 values.
func FuzzRLPUintRoundtrip(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(127))
	f.Add(uint64(128))
	f.Add(uint64(255))
	f.Add(uint64(256))
	f.Add(uint64(65535))
	f.Add(uint64(1<<32 - 1))
	f.Add(uint64(1<<64 - 1))

	f.Fuzz(func(t *testing.T, val uint64) {
		encoded, err := rlp.EncodeToBytes(val)
		if err != nil {
			t.Fatalf("failed to encode uint64 %d: %v", val, err)
		}

		var decoded uint64
		err = rlp.DecodeBytes(encoded, &decoded)
		if err != nil {
			t.Fatalf("failed to decode uint64: %v", err)
		}

		if decoded != val {
			t.Fatalf("uint64 roundtrip mismatch: input %d, decoded %d", val, decoded)
		}
	})
}

// FuzzRLPStringRoundtrip tests RLP encode/decode roundtrip for Go strings.
func FuzzRLPStringRoundtrip(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("hello")
	f.Add("The quick brown fox jumps over the lazy dog")
	f.Add(string(make([]byte, 55)))
	f.Add(string(make([]byte, 56)))

	f.Fuzz(func(t *testing.T, val string) {
		encoded, err := rlp.EncodeToBytes(val)
		if err != nil {
			return
		}

		var decoded string
		err = rlp.DecodeBytes(encoded, &decoded)
		if err != nil {
			t.Fatalf("failed to decode string: %v", err)
		}

		if decoded != val {
			t.Fatalf("string roundtrip mismatch: input %q, decoded %q", val, decoded)
		}
	})
}

// FuzzRLPDecodeRobustness tests that the RLP decoder does not panic on
// arbitrary input. Any input should either decode successfully or return
// an error -- never panic.
func FuzzRLPDecodeRobustness(f *testing.F) {
	// Seed with valid RLP encodings and malformed data.
	f.Add([]byte{0x80})                                                 // empty string
	f.Add([]byte{0xc0})                                                 // empty list
	f.Add([]byte{0x00})                                                 // single zero byte
	f.Add([]byte{0x83, 0x64, 0x6f, 0x67})                               // "dog"
	f.Add([]byte{0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67}) // ["cat","dog"]
	f.Add([]byte{0xbf})                                                 // malformed long string
	f.Add([]byte{0xff})                                                 // malformed long list
	f.Add([]byte{0xb8, 0x00})                                           // long string with zero length
	f.Add([]byte{0xb9, 0x01, 0x00})                                     // long string 256 bytes (truncated)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try decoding as bytes -- must not panic.
		var decoded []byte
		_ = rlp.DecodeBytes(data, &decoded)

		// Try decoding as uint64 -- must not panic.
		var decodedUint uint64
		_ = rlp.DecodeBytes(data, &decodedUint)

		// Try decoding as string -- must not panic.
		var decodedStr string
		_ = rlp.DecodeBytes(data, &decodedStr)
	})
}
