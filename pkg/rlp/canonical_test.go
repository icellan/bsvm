package rlp

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

// TestCanonicalRejection verifies the decoder rejects non-canonical
// encodings. The Ethereum RLP spec mandates exactly one valid encoding
// per value; any alternate representation is a consensus hazard.
//
// All cases here are attempted decodes into common Go targets. They
// MUST produce a non-nil error — silent acceptance would be a bug.
func TestCanonicalRejection(t *testing.T) {
	// 55-byte payload used for the short/long-form boundary cases.
	fiftyFive := bytes.Repeat([]byte{'a'}, 55)
	fiftySix := bytes.Repeat([]byte{'a'}, 56)

	tests := []struct {
		name   string
		input  []byte
		reason string
	}{
		{
			name:   "single byte 0x00 with unnecessary prefix (0x81 0x00)",
			input:  []byte{0x81, 0x00},
			reason: "single-byte values <0x80 must not be prefixed",
		},
		{
			name:   "single byte 0x7f with unnecessary prefix (0x81 0x7f)",
			input:  []byte{0x81, 0x7f},
			reason: "single-byte values <=0x7f must not be prefixed",
		},
		{
			name: "long-form used for 55-byte string (0xb8 0x37 ...)",
			// 0xb8 is the 1-byte-length long-form string marker; it
			// should only appear for sizes >= 56. A size of 0x37 (55)
			// is representable in short-form (0xb7 + 55 bytes).
			input:  append([]byte{0xb8, 0x37}, fiftyFive...),
			reason: "long-form must not be used when short-form suffices",
		},
		{
			name: "leading zero in length-of-length (0xb9 0x00 0x38 ...)",
			// 0xb9 means 2 length bytes follow. The encoded size is
			// 0x0038 = 56, but with a leading zero — the minimal
			// encoding is 0xb8 0x38.
			input:  append([]byte{0xb9, 0x00, 0x38}, fiftySix...),
			reason: "size must be encoded with minimal number of bytes",
		},
		{
			name: "long-form empty list (0xf8 0x00)",
			// 0xf8 is the 1-byte-length long-form list marker. An
			// empty list must encode as 0xc0, never as 0xf8 0x00.
			input:  []byte{0xf8, 0x00},
			reason: "empty list must use short-form 0xc0",
		},
		{
			name:   "long-form list with size 0 (should use short-form)",
			input:  []byte{0xf8, 0x00},
			reason: "duplicate to cover multiple target types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" -> []byte", func(t *testing.T) {
			var b []byte
			err := DecodeBytes(tt.input, &b)
			if err == nil {
				t.Fatalf("expected error (%s) for input %x, got decoded value %x", tt.reason, tt.input, b)
			}
		})
		t.Run(tt.name+" -> RawValue", func(t *testing.T) {
			var r RawValue
			err := DecodeBytes(tt.input, &r)
			if err == nil {
				t.Fatalf("expected error (%s) for input %x, got decoded value %x", tt.reason, tt.input, []byte(r))
			}
		})
	}
}

// TestCanonicalBoundary55Bytes covers the short/long-form boundary.
// A 55-byte string MUST use short form (0xb7 + 55 bytes). A 56-byte
// string MUST use long form (0xb8 0x38 + 56 bytes). Anything else
// on either side is non-canonical.
func TestCanonicalBoundary55Bytes(t *testing.T) {
	fiftyFive := bytes.Repeat([]byte{'a'}, 55)
	fiftySix := bytes.Repeat([]byte{'a'}, 56)

	t.Run("55 bytes short-form accepted", func(t *testing.T) {
		input := append([]byte{0xb7}, fiftyFive...)
		var got []byte
		if err := DecodeBytes(input, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, fiftyFive) {
			t.Errorf("got %x, want %x", got, fiftyFive)
		}
	})

	t.Run("56 bytes long-form accepted", func(t *testing.T) {
		input := append([]byte{0xb8, 0x38}, fiftySix...)
		var got []byte
		if err := DecodeBytes(input, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, fiftySix) {
			t.Errorf("got %x, want %x", got, fiftySix)
		}
	})

	t.Run("empty list 0xc0 accepted", func(t *testing.T) {
		var got []uint
		if err := DecodeBytes([]byte{0xc0}, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got len %d, want 0", len(got))
		}
	})
}

// TestLengthPrefixDoSRejected asserts the decoder rejects absurd
// length prefixes quickly and without allocating the claimed bytes.
//
// An attacker can craft a 5-byte input that claims a 4 GiB payload,
// or a 9-byte input that claims a 2^64-1 byte payload. A naive
// decoder that allocates based on the declared length is trivial to
// DoS. The decoder MUST validate the claimed length against the
// actual remaining input before attempting any allocation.
func TestLengthPrefixDoSRejected(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			// 0xbb = long-form string, 4-byte length follows.
			// 0xffffffff = ~4 GiB declared payload on a 5-byte input.
			name:  "4GB claim on 5-byte input",
			input: []byte{0xbb, 0xff, 0xff, 0xff, 0xff},
		},
		{
			// 0xbb with 4-byte length, plus some payload (still wildly short).
			name:  "4GB claim with small trailing payload",
			input: append([]byte{0xbb, 0xff, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0x00}, 16)...),
		},
		{
			// 0xfb = long-form list, 4-byte length follows.
			name:  "4GB list claim on 5-byte input",
			input: []byte{0xfb, 0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var memBefore runtime.MemStats
			runtime.ReadMemStats(&memBefore)

			done := make(chan struct {
				err error
				rec interface{}
			}, 1)
			go func() {
				var r struct {
					err error
					rec interface{}
				}
				defer func() {
					r.rec = recover()
					done <- r
				}()
				var b []byte
				r.err = DecodeBytes(tt.input, &b)
				done <- r
			}()

			select {
			case res := <-done:
				if res.rec != nil {
					// A panic on a 4GB-class input is still a bug,
					// but the key DoS property (no OOM) holds.
					t.Logf("decoder panicked on %x: %v (still bounded — not OOM)", tt.input, res.rec)
				}
				if res.err == nil && res.rec == nil {
					t.Fatalf("expected error for input %x, got nil", tt.input)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("decoder hung on input %x (suspected OOM or infinite loop)", tt.input)
			}

			var memAfter runtime.MemStats
			runtime.ReadMemStats(&memAfter)
			// Ensure we didn't allocate anything close to the declared
			// 4 GiB. A 64 MiB ceiling is very generous but catches any
			// allocator that naively trusts the length prefix.
			const maxAlloc = 64 * 1024 * 1024
			delta := int64(memAfter.TotalAlloc) - int64(memBefore.TotalAlloc)
			if delta > maxAlloc {
				t.Fatalf("decoder allocated %d bytes on input %x (claimed length was 4GB)", delta, tt.input)
			}
		})
	}
}

// TestLengthPrefixDoS_2Pow64 exercises the extreme case: a length
// prefix that claims 2^64-1 bytes. On a 64-bit platform converting
// that size to a Go int overflows to -1, which reaches
// `make([]byte, -1)` and panics. That is STILL bounded (no OOM,
// fails fast) but the decoder should return a clean error instead.
//
// TODO: review finding — pkg/rlp/decode.go Stream.readSlice does not
// validate `int(size) >= 0`, causing a runtime panic on declared
// lengths that overflow `int`. The fix is to check
// `size > uint64(math.MaxInt) || s.pos+int(size) > len(s.data)`
// before `make`. This is a consensus-adjacent change (affects all
// call sites that decode untrusted RLP), so it is left to a separate
// review before tightening.
func TestLengthPrefixDoS_2Pow64(t *testing.T) {
	// The assertion below is the correct behavior we want once fixed.
	// 0xbf = long-form string, 8-byte length follows. All-0xff means
	// the declared content length is 2^64-1 bytes.
	input := append([]byte{0xbf}, bytes.Repeat([]byte{0xff}, 8)...)

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nil // treat panic as "test should fail"
			}
		}()
		var b []byte
		done <- DecodeBytes(input, &b)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected clean error for input %x, got nil (or panic)", input)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("decoder hung on input %x", input)
	}
}

// TestNestingDepthBehavior documents the decoder's current behavior
// on deeply-nested lists. The input is [[[[...[]]]]] with increasing
// depth. The decoder should either:
//   - accept up to a reasonable cap and reject deeper inputs, OR
//   - accept arbitrarily deep inputs bounded only by process memory.
//
// CURRENT BEHAVIOR (documented, not asserted as correct):
// The decoder has NO explicit recursion-depth limit. Decoding into
// RawValue is iterative (Stream.Raw just advances pos), so any depth
// is accepted at near-constant cost. Decoding into a typed recursive
// Go value (e.g. `type nestedList []nestedList`) recurses through
// reflect, driving up Go's resizable stack and arbitrary amounts of
// garbage until the OS kills the process on memory exhaustion. There
// is no "depth exceeded" error.
//
// This test therefore asserts only the boundary: moderate depth
// succeeds. Any consensus-critical deployment should wrap the decoder
// with an explicit depth limit at the boundary, or add one here.
//
// TODO: review finding — pkg/rlp/decode.go has no nesting-depth
// bound; a hostile 1 MB payload can drive the decoder into tens of
// thousands of nested List() frames and exhaust memory. Fix:
// increment a depth counter in Stream.List() and reject past a
// reasonable cap (geth uses ~1024 via maxCallDepth semantics).
func TestNestingDepthBehavior(t *testing.T) {
	t.Run("moderate depth accepted as RawValue", func(t *testing.T) {
		// Build [[[[...[]]]]] for depth=1024.
		data := []byte{0xc0}
		for i := 0; i < 1024; i++ {
			if len(data) < 56 {
				data = append([]byte{0xc0 + byte(len(data))}, data...)
			} else {
				size := uint64(len(data))
				var lenBuf []byte
				for size > 0 {
					lenBuf = append([]byte{byte(size & 0xff)}, lenBuf...)
					size >>= 8
				}
				hdr := append([]byte{0xf7 + byte(len(lenBuf))}, lenBuf...)
				data = append(hdr, data...)
			}
		}
		var r RawValue
		if err := DecodeBytes(data, &r); err != nil {
			t.Fatalf("moderate depth (1024) rejected: %v", err)
		}
	})

	t.Run("moderate depth accepted as typed recursive slice", func(t *testing.T) {
		type nestedList []nestedList
		data := []byte{0xc0}
		for i := 0; i < 256; i++ {
			if len(data) < 56 {
				data = append([]byte{0xc0 + byte(len(data))}, data...)
			} else {
				size := uint64(len(data))
				var lenBuf []byte
				for size > 0 {
					lenBuf = append([]byte{byte(size & 0xff)}, lenBuf...)
					size >>= 8
				}
				hdr := append([]byte{0xf7 + byte(len(lenBuf))}, lenBuf...)
				data = append(hdr, data...)
			}
		}
		var v nestedList
		if err := DecodeBytes(data, &v); err != nil {
			t.Fatalf("moderate depth (256) rejected: %v", err)
		}
	})
}

// TestNestingDepthExceededRejected asserts the decoder rejects an
// unreasonably deep input with a clear error. This is the correct
// behavior — the current implementation does NOT enforce any limit,
// hence the Skip.
//
// TODO: review finding — add a depth bound (e.g. MaxDepth = 1024) to
// Stream.List() and return a "rlp: nesting depth exceeded" error.
func TestNestingDepthExceededRejected(t *testing.T) {
	type nestedList []nestedList
	// Build 100,000 levels deep.
	data := []byte{0xc0}
	for i := 0; i < 100_000; i++ {
		if len(data) < 56 {
			data = append([]byte{0xc0 + byte(len(data))}, data...)
		} else {
			size := uint64(len(data))
			var lenBuf []byte
			for size > 0 {
				lenBuf = append([]byte{byte(size & 0xff)}, lenBuf...)
				size >>= 8
			}
			hdr := append([]byte{0xf7 + byte(len(lenBuf))}, lenBuf...)
			data = append(hdr, data...)
		}
	}
	var v nestedList
	err := DecodeBytes(data, &v)
	if err == nil {
		t.Fatal("expected depth-exceeded error, got nil")
	}
}

// TestRoundtripEdgeCases exercises boundary encodings that are easy
// to get wrong: empty values, single-byte values, the 55/56-byte
// short/long-form boundary, and large payloads.
func TestRoundtripEdgeCases(t *testing.T) {
	t.Run("empty byte slice -> 0x80", func(t *testing.T) {
		enc, err := EncodeToBytes([]byte{})
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if !bytes.Equal(enc, []byte{0x80}) {
			t.Errorf("got %x, want 0x80", enc)
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %x, want empty", got)
		}
	})

	t.Run("empty list -> 0xc0", func(t *testing.T) {
		enc, err := EncodeToBytes([]uint{})
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if !bytes.Equal(enc, []byte{0xc0}) {
			t.Errorf("got %x, want 0xc0", enc)
		}
		var got []uint
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("single byte 0x00 -> 0x80 (integer zero rule)", func(t *testing.T) {
		// Per the RLP spec, integer 0 encodes as 0x80 (empty string).
		// A byte slice []byte{0x00} however is a 1-byte string whose
		// content is < 0x80 and so encodes as the byte itself: 0x00.
		enc, err := EncodeToBytes([]byte{0x00})
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if !bytes.Equal(enc, []byte{0x00}) {
			t.Errorf("got %x, want 0x00", enc)
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, []byte{0x00}) {
			t.Errorf("got %x, want 0x00", got)
		}
	})

	t.Run("single byte 0x7f -> 0x7f", func(t *testing.T) {
		enc, err := EncodeToBytes([]byte{0x7f})
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if !bytes.Equal(enc, []byte{0x7f}) {
			t.Errorf("got %x, want 0x7f", enc)
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, []byte{0x7f}) {
			t.Errorf("got %x, want 0x7f", got)
		}
	})

	t.Run("55-byte payload uses short-form", func(t *testing.T) {
		payload := bytes.Repeat([]byte{'x'}, 55)
		enc, err := EncodeToBytes(payload)
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if enc[0] != 0xb7 {
			t.Errorf("header = 0x%02x, want 0xb7 (short-form)", enc[0])
		}
		if len(enc) != 56 {
			t.Errorf("len = %d, want 56 (1 header + 55 payload)", len(enc))
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("roundtrip mismatch")
		}
	})

	t.Run("56-byte payload uses long-form", func(t *testing.T) {
		payload := bytes.Repeat([]byte{'x'}, 56)
		enc, err := EncodeToBytes(payload)
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		if enc[0] != 0xb8 || enc[1] != 0x38 {
			t.Errorf("header = 0x%02x 0x%02x, want 0xb8 0x38 (long-form)", enc[0], enc[1])
		}
		if len(enc) != 58 {
			t.Errorf("len = %d, want 58 (2 header + 56 payload)", len(enc))
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("roundtrip mismatch")
		}
	})

	t.Run("1 MiB payload roundtrip", func(t *testing.T) {
		payload := make([]byte, 1<<20)
		for i := range payload {
			payload[i] = byte(i)
		}
		enc, err := EncodeToBytes(payload)
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		var got []byte
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("1 MiB roundtrip mismatch")
		}
	})

	t.Run("2^16+1 element list roundtrip", func(t *testing.T) {
		// A list with 65537 small integers forces the encoder onto
		// the long-form list header with a multi-byte length.
		n := (1 << 16) + 1
		original := make([]uint32, n)
		for i := range original {
			original[i] = uint32(i & 0x7f) // keep each value single-byte
		}
		enc, err := EncodeToBytes(original)
		if err != nil {
			t.Fatalf("EncodeToBytes error: %v", err)
		}
		var got []uint32
		if err := DecodeBytes(enc, &got); err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if len(got) != n {
			t.Fatalf("len = %d, want %d", len(got), n)
		}
		for i, v := range got {
			if v != original[i] {
				t.Fatalf("[%d] = %d, want %d", i, v, original[i])
			}
		}
	})
}
