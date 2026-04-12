package rlp

import (
	"bytes"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
)

// customEncoder implements the Encoder interface for testing.
type customEncoder struct {
	Value string
}

// EncodeRLP implements the Encoder interface.
func (c *customEncoder) EncodeRLP(w io.Writer) error {
	b, err := EncodeToBytes(c.Value)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncodeBool(t *testing.T) {
	tests := []struct {
		name string
		val  bool
		want []byte
	}{
		{"false", false, []byte{0x80}},
		{"true", true, []byte{0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%v) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

func TestEncodeUint(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want []byte
	}{
		{"uint 0", uint(0), []byte{0x80}},
		{"uint 1", uint(1), []byte{0x01}},
		{"uint 127", uint(127), []byte{0x7f}},
		{"uint 128", uint(128), []byte{0x81, 0x80}},
		{"uint 255", uint(255), []byte{0x81, 0xff}},
		{"uint 256", uint(256), []byte{0x82, 0x01, 0x00}},
		{"uint 1024", uint(1024), []byte{0x82, 0x04, 0x00}},
		{"uint 0xFFFF", uint(0xFFFF), []byte{0x82, 0xff, 0xff}},
		{"uint 0xFFFFFF", uint(0xFFFFFF), []byte{0x83, 0xff, 0xff, 0xff}},
		{"uint8 0", uint8(0), []byte{0x80}},
		{"uint8 1", uint8(1), []byte{0x01}},
		{"uint8 127", uint8(127), []byte{0x7f}},
		{"uint8 128", uint8(128), []byte{0x81, 0x80}},
		{"uint16 0", uint16(0), []byte{0x80}},
		{"uint16 256", uint16(256), []byte{0x82, 0x01, 0x00}},
		{"uint32 0", uint32(0), []byte{0x80}},
		{"uint64 0", uint64(0), []byte{0x80}},
		{"uint64 MaxUint64", uint64(0xFFFFFFFFFFFFFFFF), []byte{0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%v) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

func TestEncodeString(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want []byte
	}{
		{"empty string", "", []byte{0x80}},
		{"single char a", "a", []byte{'a'}},
		{"short string dog", "dog", []byte{0x83, 'd', 'o', 'g'}},
		{
			"lorem ipsum",
			"Lorem ipsum dolor sit amet, consectetur adipisicing elit",
			append([]byte{0xb8, 56}, []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%q) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%q) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

func TestEncodeBytes(t *testing.T) {
	tests := []struct {
		name string
		val  []byte
		want []byte
	}{
		{"empty bytes", []byte{}, []byte{0x80}},
		{"single byte 0x00", []byte{0x00}, []byte{0x00}},
		{"single byte 0x01", []byte{0x01}, []byte{0x01}},
		{"single byte 0x7f", []byte{0x7f}, []byte{0x7f}},
		{"single byte 0x80", []byte{0x80}, []byte{0x81, 0x80}},
		{"two bytes", []byte{0x01, 0x02}, []byte{0x82, 0x01, 0x02}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%x) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%x) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

func TestEncodeBigInt(t *testing.T) {
	tests := []struct {
		name string
		val  *big.Int
		want []byte
	}{
		{"zero", big.NewInt(0), []byte{0x80}},
		{"one", big.NewInt(1), []byte{0x01}},
		{"127", big.NewInt(127), []byte{0x7f}},
		{"128", big.NewInt(128), []byte{0x81, 0x80}},
		{"256", big.NewInt(256), []byte{0x82, 0x01, 0x00}},
		{
			"large number",
			new(big.Int).SetBytes(unhex("0100000000000000000000000000000000000000000000000000000000000000")),
			append([]byte{0xa0}, unhex("0100000000000000000000000000000000000000000000000000000000000000")...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%v) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

func TestEncodeNegativeBigInt(t *testing.T) {
	_, err := EncodeToBytes(big.NewInt(-1))
	if err == nil {
		t.Fatal("expected error encoding negative big.Int")
	}
}

func TestEncodeList(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want []byte
	}{
		{"empty list", []interface{}{}, []byte{0xc0}},
		{"list of strings", []string{"cat", "dog"}, []byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'}},
		{"list of uints", []uint{1, 2, 3}, []byte{0xc3, 0x01, 0x02, 0x03}},
		{"empty string list", []string{}, []byte{0xc0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeToBytes(%v) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

// Ethereum Yellow Paper test vectors: encoding of set theory representation.
func TestEncodeYellowPaperExamples(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		// The string "dog" = [ 0x83, 'd', 'o', 'g' ]
		{"dog", "dog", "83646f67"},
		// The list [ "cat", "dog" ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
		{"cat_dog_list", []string{"cat", "dog"}, "c88363617483646f67"},
		// The empty string = [ 0x80 ]
		{"empty_string", "", "80"},
		// The empty list = [ 0xc0 ]
		{"empty_list", []string{}, "c0"},
		// The integer 0 = [ 0x80 ]
		{"integer_0", uint(0), "80"},
		// The byte 0x00 = [ 0x00 ]
		{"byte_0x00", []byte{0x00}, "00"},
		// The byte 0x0f = [ 0x0f ]
		{"byte_0x0f", []byte{0x0f}, "0f"},
		// The integer 15 = [ 0x0f ]
		{"integer_15", uint(15), "0f"},
		// The integer 1024 = [ 0x82, 0x04, 0x00 ]
		{"integer_1024", uint(1024), "820400"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.want {
				t.Errorf("EncodeToBytes(%v) = %s, want %s", tt.val, gotHex, tt.want)
			}
		})
	}
}

type testStruct struct {
	A uint
	B string
	C []byte
}

type testStructWithOptional struct {
	A uint
	B string `rlp:"optional"`
	C []byte `rlp:"optional"`
}

type testStructWithSkip struct {
	A uint
	B string `rlp:"-"`
	C uint
}

type testStructWithTail struct {
	A    uint
	B    string
	Tail []RawValue `rlp:"tail"`
}

func TestEncodeStruct(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		{
			"simple struct",
			testStruct{A: 1, B: "hello", C: []byte{0x01, 0x02}},
			"ca0185" + hex.EncodeToString([]byte("hello")) + "820102",
		},
		{
			"struct with zero values",
			testStruct{A: 0, B: "", C: []byte{}},
			"c3808080",
		},
		{
			"struct with skip",
			testStructWithSkip{A: 1, B: "ignored", C: 2},
			"c20102",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.want {
				t.Errorf("EncodeToBytes(%v) = %s, want %s", tt.val, gotHex, tt.want)
			}
		})
	}
}

func TestEncodeStructOptional(t *testing.T) {
	tests := []struct {
		name string
		val  testStructWithOptional
		want string
	}{
		{
			"all fields set",
			testStructWithOptional{A: 1, B: "hi", C: []byte{0x03}},
			"c50182686903",
		},
		{
			"optional fields zero",
			testStructWithOptional{A: 1, B: "", C: nil},
			"c101",
		},
		{
			"only B set",
			testStructWithOptional{A: 1, B: "hi", C: nil},
			"c401826869",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("EncodeToBytes(%v) error: %v", tt.val, err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.want {
				t.Errorf("EncodeToBytes(%v) = %s, want %s", tt.val, gotHex, tt.want)
			}
		})
	}
}

func TestEncodeNilPointer(t *testing.T) {
	var p *uint
	got, err := EncodeToBytes(p)
	if err != nil {
		t.Fatalf("EncodeToBytes(nil) error: %v", err)
	}
	if !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("EncodeToBytes(nil) = %x, want 80", got)
	}
}

func TestEncodePointer(t *testing.T) {
	v := uint(42)
	got, err := EncodeToBytes(&v)
	if err != nil {
		t.Fatalf("EncodeToBytes(&42) error: %v", err)
	}
	if !bytes.Equal(got, []byte{0x2a}) {
		t.Errorf("EncodeToBytes(&42) = %x, want 2a", got)
	}
}

func TestEncodeCustomEncoder(t *testing.T) {
	v := &customEncoder{Value: "test"}
	got, err := EncodeToBytes(v)
	if err != nil {
		t.Fatalf("EncodeToBytes(customEncoder) error: %v", err)
	}
	want, _ := EncodeToBytes("test")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeToBytes(customEncoder) = %x, want %x", got, want)
	}
}

func TestEncode_Writer(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, "dog")
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	want := []byte{0x83, 'd', 'o', 'g'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("Encode = %x, want %x", buf.Bytes(), want)
	}
}

func TestEncodeToReader(t *testing.T) {
	size, r, err := EncodeToReader("dog")
	if err != nil {
		t.Fatalf("EncodeToReader error: %v", err)
	}
	if size != 4 {
		t.Errorf("size = %d, want 4", size)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	want := []byte{0x83, 'd', 'o', 'g'}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeToReader = %x, want %x", got, want)
	}
}

func TestEncodeLongString(t *testing.T) {
	// A 56-byte string should use the long string encoding.
	s := make([]byte, 56)
	for i := range s {
		s[i] = byte(i)
	}
	got, err := EncodeToBytes(s)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	// Header: 0xb8 (0xb7 + 1 byte for length), 0x38 (56)
	if got[0] != 0xb8 {
		t.Errorf("header byte = %x, want b8", got[0])
	}
	if got[1] != 56 {
		t.Errorf("length byte = %d, want 56", got[1])
	}
	if !bytes.Equal(got[2:], s) {
		t.Error("content mismatch")
	}
}

func TestEncodeLongList(t *testing.T) {
	// Create a list that encodes to > 55 bytes.
	items := make([]string, 20)
	for i := range items {
		items[i] = "abcd"
	}
	got, err := EncodeToBytes(items)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	// Each item encodes as [0x84, 'a', 'b', 'c', 'd'] = 5 bytes.
	// Total content: 20 * 5 = 100 bytes.
	// Header: 0xf8 (0xf7 + 1 byte for length), 0x64 (100)
	if got[0] != 0xf8 {
		t.Errorf("header byte = %x, want f8", got[0])
	}
	if got[1] != 100 {
		t.Errorf("length byte = %d, want 100", got[1])
	}
}

func TestEncodeNestedList(t *testing.T) {
	// Nested list: [[1, 2], [3, 4]]
	val := [][]uint{{1, 2}, {3, 4}}
	got, err := EncodeToBytes(val)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	// Inner list [1, 2] encodes as [0xc2, 0x01, 0x02]
	// Inner list [3, 4] encodes as [0xc2, 0x03, 0x04]
	// Outer list header: [0xc6] (6 bytes total)
	want := []byte{0xc6, 0xc2, 0x01, 0x02, 0xc2, 0x03, 0x04}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeToBytes(%v) = %x, want %x", val, got, want)
	}
}

func TestEncodeRawValue(t *testing.T) {
	// RawValue should be written as-is.
	raw := RawValue([]byte{0xc3, 0x01, 0x02, 0x03})
	got, err := EncodeToBytes(raw)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("EncodeToBytes(RawValue) = %x, want %x", got, raw)
	}
}

func TestEncodeEmptyRawValue(t *testing.T) {
	raw := RawValue(nil)
	got, err := EncodeToBytes(raw)
	if err != nil {
		t.Fatalf("EncodeToBytes error: %v", err)
	}
	if !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("EncodeToBytes(empty RawValue) = %x, want 80", got)
	}
}

// Set theory representation from Yellow Paper: [ [], [[]], [ [], [[]] ] ]
func TestEncodeSetTheory(t *testing.T) {
	// This is the canonical RLP example from the Ethereum Yellow Paper.
	// We encode it as nested uint slices and byte slices to approximate.
	// The exact encoding is: c7c0c1c0c3c0c1c0

	// Build the structure manually using RawValue.
	emptyList, _ := EncodeToBytes([]RawValue{})                          // c0
	listOfEmptyList, _ := EncodeToBytes([]RawValue{RawValue(emptyList)}) // c1c0
	innerList, _ := EncodeToBytes([]RawValue{
		RawValue(emptyList),
		RawValue(listOfEmptyList),
	})
	outerList, _ := EncodeToBytes([]RawValue{
		RawValue(emptyList),
		RawValue(listOfEmptyList),
		RawValue(innerList),
	})

	want := "c7c0c1c0c3c0c1c0"
	gotHex := hex.EncodeToString(outerList)
	if gotHex != want {
		t.Errorf("set theory encoding = %s, want %s", gotHex, want)
	}
}
