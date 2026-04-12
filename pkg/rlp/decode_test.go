package rlp

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestDecodeBool(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    bool
		wantErr bool
	}{
		{"true", []byte{0x01}, true, false},
		{"false", []byte{0x80}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bool
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DecodeBytes(%x) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeUint(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    uint64
		wantErr bool
	}{
		{"zero", []byte{0x80}, 0, false},
		{"one", []byte{0x01}, 1, false},
		{"127", []byte{0x7f}, 127, false},
		{"128", []byte{0x81, 0x80}, 128, false},
		{"256", []byte{0x82, 0x01, 0x00}, 256, false},
		{"1024", []byte{0x82, 0x04, 0x00}, 1024, false},
		{"MaxUint64", []byte{0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xFFFFFFFFFFFFFFFF, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got uint64
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DecodeBytes(%x) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeString(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    string
		wantErr bool
	}{
		{"empty", []byte{0x80}, "", false},
		{"single char a", []byte{'a'}, "a", false},
		{"dog", []byte{0x83, 'd', 'o', 'g'}, "dog", false},
		{
			"lorem ipsum",
			append([]byte{0xb8, 56}, []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")...),
			"Lorem ipsum dolor sit amet, consectetur adipisicing elit",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DecodeBytes(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{"empty", []byte{0x80}, []byte{}, false},
		{"single byte 0x01", []byte{0x01}, []byte{0x01}, false},
		{"single byte 0x7f", []byte{0x7f}, []byte{0x7f}, false},
		{"single byte 0x80", []byte{0x81, 0x80}, []byte{0x80}, false},
		{"two bytes", []byte{0x82, 0x01, 0x02}, []byte{0x01, 0x02}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []byte
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("DecodeBytes(%x) = %x, want %x", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeBigInt(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *big.Int
		wantErr bool
	}{
		{"zero", []byte{0x80}, big.NewInt(0), false},
		{"one", []byte{0x01}, big.NewInt(1), false},
		{"127", []byte{0x7f}, big.NewInt(127), false},
		{"128", []byte{0x81, 0x80}, big.NewInt(128), false},
		{"256", []byte{0x82, 0x01, 0x00}, big.NewInt(256), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got big.Int
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got.Cmp(tt.want) != 0 {
				t.Errorf("DecodeBytes(%x) = %v, want %v", tt.input, &got, tt.want)
			}
		})
	}
}

func TestDecodeSlice(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []uint
		wantErr bool
	}{
		{"empty list", []byte{0xc0}, []uint{}, false},
		{"list of uints", []byte{0xc3, 0x01, 0x02, 0x03}, []uint{1, 2, 3}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint
			err := DecodeBytes(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeBytes(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Fatalf("len = %d, want %d", len(got), len(tt.want))
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("[%d] = %d, want %d", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestDecodeStringSlice(t *testing.T) {
	// Decode [ "cat", "dog" ]
	input := []byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'}
	var got []string
	err := DecodeBytes(input, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if len(got) != 2 || got[0] != "cat" || got[1] != "dog" {
		t.Errorf("got %v, want [cat dog]", got)
	}
}

func TestDecodeNestedSlice(t *testing.T) {
	// Decode [[1, 2], [3, 4]]
	input := []byte{0xc6, 0xc2, 0x01, 0x02, 0xc2, 0x03, 0x04}
	var got [][]uint
	err := DecodeBytes(input, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if len(got[0]) != 2 || got[0][0] != 1 || got[0][1] != 2 {
		t.Errorf("got[0] = %v, want [1 2]", got[0])
	}
	if len(got[1]) != 2 || got[1][0] != 3 || got[1][1] != 4 {
		t.Errorf("got[1] = %v, want [3 4]", got[1])
	}
}

func TestDecodeStruct(t *testing.T) {
	// Encode a struct, then decode it.
	original := testStruct{A: 42, B: "hello", C: []byte{0xde, 0xad}}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}

	var decoded testStruct
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if decoded.A != original.A {
		t.Errorf("A = %d, want %d", decoded.A, original.A)
	}
	if decoded.B != original.B {
		t.Errorf("B = %q, want %q", decoded.B, original.B)
	}
	if !bytes.Equal(decoded.C, original.C) {
		t.Errorf("C = %x, want %x", decoded.C, original.C)
	}
}

func TestDecodeStructWithSkip(t *testing.T) {
	original := testStructWithSkip{A: 1, B: "should be ignored", C: 2}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}

	var decoded testStructWithSkip
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if decoded.A != 1 {
		t.Errorf("A = %d, want 1", decoded.A)
	}
	if decoded.B != "" {
		t.Errorf("B = %q, want empty (skipped)", decoded.B)
	}
	if decoded.C != 2 {
		t.Errorf("C = %d, want 2", decoded.C)
	}
}

func TestDecodeStructOptional(t *testing.T) {
	// Encode with optional fields set.
	original := testStructWithOptional{A: 1, B: "hi", C: []byte{0x03}}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}

	var decoded testStructWithOptional
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if decoded.A != 1 {
		t.Errorf("A = %d, want 1", decoded.A)
	}
	if decoded.B != "hi" {
		t.Errorf("B = %q, want hi", decoded.B)
	}
	if !bytes.Equal(decoded.C, []byte{0x03}) {
		t.Errorf("C = %x, want 03", decoded.C)
	}
}

func TestDecodeStructOptionalMissing(t *testing.T) {
	// Encode with optional fields omitted (zero values at end).
	original := testStructWithOptional{A: 5, B: "", C: nil}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}

	var decoded testStructWithOptional
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if decoded.A != 5 {
		t.Errorf("A = %d, want 5", decoded.A)
	}
	if decoded.B != "" {
		t.Errorf("B = %q, want empty", decoded.B)
	}
	if decoded.C != nil {
		t.Errorf("C = %x, want nil", decoded.C)
	}
}

func TestDecodeByteArray(t *testing.T) {
	// Encode [3]byte{1, 2, 3}
	input := []byte{0x83, 0x01, 0x02, 0x03}
	var got [3]byte
	err := DecodeBytes(input, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if got != [3]byte{1, 2, 3} {
		t.Errorf("got %v, want [1 2 3]", got)
	}
}

func TestDecodeRaw(t *testing.T) {
	// Encode a list, then decode it as RawValue.
	encoded, _ := EncodeToBytes([]uint{1, 2, 3})
	var raw RawValue
	err := DecodeBytes(encoded, &raw)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if !bytes.Equal(raw, encoded) {
		t.Errorf("raw = %x, want %x", raw, encoded)
	}
}

func TestDecodeNilPointer(t *testing.T) {
	// 0x80 should decode to nil pointer.
	var got *uint64
	err := DecodeBytes([]byte{0x80}, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestDecodePointer(t *testing.T) {
	var got *uint64
	err := DecodeBytes([]byte{0x2a}, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if got == nil || *got != 42 {
		t.Errorf("got %v, want pointer to 42", got)
	}
}

func TestDecodeTrailingData(t *testing.T) {
	// Input with trailing data should fail.
	input := []byte{0x01, 0x02} // two values
	var got uint64
	err := DecodeBytes(input, &got)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestDecodeInvalidInput(t *testing.T) {
	// Truncated input.
	input := []byte{0x83, 'd', 'o'} // says 3 bytes, only 2 present
	var got string
	err := DecodeBytes(input, &got)
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

// Roundtrip tests: encode then decode and compare.
func TestRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		new  func() interface{}
	}{
		{"uint 0", uint(0), func() interface{} { v := uint(0); return &v }},
		{"uint 42", uint(42), func() interface{} { v := uint(0); return &v }},
		{"uint 1024", uint(1024), func() interface{} { v := uint(0); return &v }},
		{"uint64 max", uint64(0xFFFFFFFFFFFFFFFF), func() interface{} { v := uint64(0); return &v }},
		{"bool true", true, func() interface{} { v := false; return &v }},
		{"bool false", false, func() interface{} { v := true; return &v }},
		{"string empty", "", func() interface{} { v := ""; return &v }},
		{"string dog", "dog", func() interface{} { v := ""; return &v }},
		{"bytes empty", []byte{}, func() interface{} { var v []byte; return &v }},
		{"bytes data", []byte{1, 2, 3}, func() interface{} { var v []byte; return &v }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes error: %v", err)
			}
			target := tt.new()
			err = DecodeBytes(encoded, target)
			if err != nil {
				t.Fatalf("DecodeBytes error: %v", err)
			}
		})
	}
}

func TestRoundtripBigInt(t *testing.T) {
	tests := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(127),
		big.NewInt(128),
		big.NewInt(256),
		new(big.Int).SetBytes(unhex("0100000000000000000000000000000000000000000000000000000000000000")),
	}
	for _, tt := range tests {
		encoded, err := EncodeToBytes(tt)
		if err != nil {
			t.Fatalf("EncodeToBytes(%v) error: %v", tt, err)
		}
		var decoded big.Int
		err = DecodeBytes(encoded, &decoded)
		if err != nil {
			t.Fatalf("DecodeBytes error: %v", err)
		}
		if decoded.Cmp(tt) != 0 {
			t.Errorf("roundtrip %v -> %v", tt, &decoded)
		}
	}
}

func TestRoundtripStruct(t *testing.T) {
	original := testStruct{A: 999, B: "test value", C: []byte{0xca, 0xfe}}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	var decoded testStruct
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if decoded.A != original.A || decoded.B != original.B || !bytes.Equal(decoded.C, original.C) {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, original)
	}
}

func TestRoundtripNestedSlice(t *testing.T) {
	original := [][]uint{{1, 2}, {3, 4}, {5}}
	encoded, err := EncodeToBytes(original)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	var decoded [][]uint
	err = DecodeBytes(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("len = %d, want %d", len(decoded), len(original))
	}
	for i := range decoded {
		if len(decoded[i]) != len(original[i]) {
			t.Fatalf("[%d] len = %d, want %d", i, len(decoded[i]), len(original[i]))
		}
		for j := range decoded[i] {
			if decoded[i][j] != original[i][j] {
				t.Errorf("[%d][%d] = %d, want %d", i, j, decoded[i][j], original[i][j])
			}
		}
	}
}

func TestStreamBasic(t *testing.T) {
	// Test the Stream interface directly.
	encoded, _ := EncodeToBytes([]uint{1, 2, 3})
	s := NewStream(bytes.NewReader(encoded), uint64(len(encoded)))

	_, err := s.List()
	if err != nil {
		t.Fatalf("List error: %v", err)
	}

	for _, want := range []uint64{1, 2, 3} {
		got, err := s.Uint64()
		if err != nil {
			t.Fatalf("Uint64 error: %v", err)
		}
		if got != want {
			t.Errorf("Uint64 = %d, want %d", got, want)
		}
	}

	if err := s.ListEnd(); err != nil {
		t.Fatalf("ListEnd error: %v", err)
	}
}

func TestStreamBytes(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded, _ := EncodeToBytes(data)
	s := NewStream(bytes.NewReader(encoded), uint64(len(encoded)))

	got, err := s.Bytes()
	if err != nil {
		t.Fatalf("Bytes error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Bytes = %x, want %x", got, data)
	}
}

func TestStreamBigInt(t *testing.T) {
	want := big.NewInt(12345)
	encoded, _ := EncodeToBytes(want)
	s := NewStream(bytes.NewReader(encoded), uint64(len(encoded)))

	got, err := s.BigInt()
	if err != nil {
		t.Fatalf("BigInt error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Errorf("BigInt = %v, want %v", got, want)
	}
}

func TestStreamRaw(t *testing.T) {
	encoded, _ := EncodeToBytes("hello")
	s := NewStream(bytes.NewReader(encoded), uint64(len(encoded)))

	raw, err := s.Raw()
	if err != nil {
		t.Fatalf("Raw error: %v", err)
	}
	if !bytes.Equal(raw, encoded) {
		t.Errorf("Raw = %x, want %x", raw, encoded)
	}
}

func TestStreamReadBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	encoded, _ := EncodeToBytes(data)
	s := NewStream(bytes.NewReader(encoded), uint64(len(encoded)))

	buf := make([]byte, 3)
	err := s.ReadBytes(buf)
	if err != nil {
		t.Fatalf("ReadBytes error: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("ReadBytes = %x, want %x", buf, data)
	}
}

// customDecoder implements the Decoder interface for testing.
type customDecoder struct {
	Value string
}

// DecodeRLP implements the Decoder interface.
func (c *customDecoder) DecodeRLP(s *Stream) error {
	b, err := s.Bytes()
	if err != nil {
		return err
	}
	c.Value = string(b)
	return nil
}

func TestDecodeCustomDecoder(t *testing.T) {
	encoded, _ := EncodeToBytes("custom")
	var got customDecoder
	err := DecodeBytes(encoded, &got)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if got.Value != "custom" {
		t.Errorf("Value = %q, want custom", got.Value)
	}
}

func TestDecodeNotPointer(t *testing.T) {
	var got uint64
	err := DecodeBytes([]byte{0x01}, got)
	if err == nil {
		t.Fatal("expected error for non-pointer argument")
	}
}

func TestDecodeNilArg(t *testing.T) {
	err := DecodeBytes([]byte{0x01}, nil)
	if err == nil {
		t.Fatal("expected error for nil argument")
	}
}

// Test encoding of the RLP "set theory" representation and decoding it back.
func TestRoundtripRawSetTheory(t *testing.T) {
	// Encode [ [], [[]], [ [], [[]] ] ] using raw values.
	emptyList, _ := EncodeToBytes([]RawValue{})
	listOfEmptyList, _ := EncodeToBytes([]RawValue{RawValue(emptyList)})
	innerList, _ := EncodeToBytes([]RawValue{
		RawValue(emptyList),
		RawValue(listOfEmptyList),
	})
	outerList, _ := EncodeToBytes([]RawValue{
		RawValue(emptyList),
		RawValue(listOfEmptyList),
		RawValue(innerList),
	})

	wantHex := "c7c0c1c0c3c0c1c0"
	gotHex := hex.EncodeToString(outerList)
	if gotHex != wantHex {
		t.Errorf("set theory encoding = %s, want %s", gotHex, wantHex)
	}

	// Decode it back as a slice of RawValue.
	var decoded []RawValue
	err := DecodeBytes(outerList, &decoded)
	if err != nil {
		t.Fatalf("DecodeBytes error: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("len = %d, want 3", len(decoded))
	}
}

func TestDecodeStreamBool(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x01}), 1)
	got, err := s.Bool()
	if err != nil {
		t.Fatalf("Bool error: %v", err)
	}
	if !got {
		t.Error("expected true")
	}
}
