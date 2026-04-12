package rlp

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sync"
)

// Encoder is implemented by types that require custom RLP encoding rules.
// The EncodeRLP method should write the RLP encoding of the receiver to w.
type Encoder interface {
	EncodeRLP(io.Writer) error
}

var (
	encoderType  = reflect.TypeOf((*Encoder)(nil)).Elem()
	bigIntType   = reflect.TypeOf((*big.Int)(nil))
	rawValueType = reflect.TypeOf(RawValue{})

	// encBufPool is a pool of reusable encode buffers.
	encBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

// Encode writes the RLP encoding of val to w.
func Encode(w io.Writer, val interface{}) error {
	buf := encBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer encBufPool.Put(buf)
	if err := encodeValue(buf, reflect.ValueOf(val)); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// EncodeToBytes returns the RLP encoding of val as a byte slice.
func EncodeToBytes(val interface{}) ([]byte, error) {
	buf := encBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer encBufPool.Put(buf)
	if err := encodeValue(buf, reflect.ValueOf(val)); err != nil {
		return nil, err
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// EncodeToReader returns the size and a reader for the RLP encoding of val.
func EncodeToReader(val interface{}) (size int, r io.Reader, err error) {
	b, err := EncodeToBytes(val)
	if err != nil {
		return 0, nil, err
	}
	return len(b), bytes.NewReader(b), nil
}

// encodeValue writes the RLP encoding of the given reflect.Value to w.
func encodeValue(w *bytes.Buffer, val reflect.Value) error {
	if !val.IsValid() {
		// nil or invalid value encodes as empty string.
		w.WriteByte(0x80)
		return nil
	}

	// Dereference pointers.
	for val.Kind() == reflect.Ptr {
		if val.IsNil() {
			w.WriteByte(0x80)
			return nil
		}
		val = val.Elem()
	}

	// Check for Encoder interface on value and pointer.
	if val.CanAddr() {
		addr := val.Addr()
		if addr.Type().Implements(encoderType) {
			return addr.Interface().(Encoder).EncodeRLP(w)
		}
	}
	if val.Type().Implements(encoderType) {
		return val.Interface().(Encoder).EncodeRLP(w)
	}

	// Check for RawValue type (already encoded).
	if val.Type() == rawValueType {
		raw := val.Bytes()
		if len(raw) == 0 {
			w.WriteByte(0x80)
			return nil
		}
		w.Write(raw)
		return nil
	}

	// Check for *big.Int.
	if val.Type() == bigIntType.Elem() {
		return encodeBigInt(w, val)
	}

	switch val.Kind() {
	case reflect.Bool:
		return encodeBool(w, val)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return encodeUint(w, val)
	case reflect.String:
		return encodeString(w, val)
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return encodeBytes(w, val)
		}
		return encodeSlice(w, val)
	case reflect.Array:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return encodeByteArray(w, val)
		}
		return encodeArray(w, val)
	case reflect.Struct:
		return encodeStruct(w, val)
	case reflect.Interface:
		if val.IsNil() {
			w.WriteByte(0x80)
			return nil
		}
		return encodeValue(w, val.Elem())
	default:
		return fmt.Errorf("rlp: cannot encode type %v", val.Type())
	}
}

// encodeBool encodes a boolean value.
func encodeBool(w *bytes.Buffer, val reflect.Value) error {
	if val.Bool() {
		w.WriteByte(0x01)
	} else {
		w.WriteByte(0x80)
	}
	return nil
}

// encodeUint encodes an unsigned integer value.
func encodeUint(w *bytes.Buffer, val reflect.Value) error {
	i := val.Uint()
	if i == 0 {
		w.WriteByte(0x80)
	} else if i < 128 {
		w.WriteByte(byte(i))
	} else {
		size := putintSize(i)
		buf := make([]byte, size)
		putint(buf, i)
		w.WriteByte(0x80 + byte(size))
		w.Write(buf)
	}
	return nil
}

// encodeString encodes a Go string value as an RLP string.
func encodeString(w *bytes.Buffer, val reflect.Value) error {
	s := val.String()
	return writeStringHeader(w, []byte(s))
}

// encodeBytes encodes a byte slice as an RLP string.
func encodeBytes(w *bytes.Buffer, val reflect.Value) error {
	b := val.Bytes()
	return writeStringHeader(w, b)
}

// encodeByteArray encodes a byte array as an RLP string.
func encodeByteArray(w *bytes.Buffer, val reflect.Value) error {
	b := make([]byte, val.Len())
	reflect.Copy(reflect.ValueOf(b), val)
	return writeStringHeader(w, b)
}

// writeStringHeader writes the RLP encoding of a string (byte sequence).
func writeStringHeader(w *bytes.Buffer, b []byte) error {
	if len(b) == 1 && b[0] < 0x80 {
		w.WriteByte(b[0])
		return nil
	}
	writeHeader(w, 0x80, uint64(len(b)))
	w.Write(b)
	return nil
}

// encodeSlice encodes a slice (non-byte) as an RLP list.
func encodeSlice(w *bytes.Buffer, val reflect.Value) error {
	return encodeListItems(w, val)
}

// encodeArray encodes an array (non-byte) as an RLP list.
func encodeArray(w *bytes.Buffer, val reflect.Value) error {
	return encodeListItems(w, val)
}

// encodeListItems encodes the elements of an indexable value as an RLP list.
func encodeListItems(w *bytes.Buffer, val reflect.Value) error {
	// First, encode all items into a temporary buffer to get the total length.
	itemBuf := encBufPool.Get().(*bytes.Buffer)
	itemBuf.Reset()
	defer encBufPool.Put(itemBuf)
	for i := 0; i < val.Len(); i++ {
		if err := encodeValue(itemBuf, val.Index(i)); err != nil {
			return err
		}
	}
	writeHeader(w, 0xc0, uint64(itemBuf.Len()))
	w.Write(itemBuf.Bytes())
	return nil
}

// encodeBigInt encodes a *big.Int value.
func encodeBigInt(w *bytes.Buffer, val reflect.Value) error {
	i := val.Addr().Interface().(*big.Int)
	if i.Sign() < 0 {
		return fmt.Errorf("rlp: cannot encode negative big.Int")
	}
	if i.Sign() == 0 {
		w.WriteByte(0x80)
		return nil
	}
	b := i.Bytes() // big-endian, no leading zeros
	return writeStringHeader(w, b)
}

// encodeStruct encodes a struct as an RLP list.
func encodeStruct(w *bytes.Buffer, val reflect.Value) error {
	fields := getStructFields(val.Type())

	// Find the last non-optional field with a non-zero value.
	// Optional fields at the end that are zero-valued are omitted.
	lastField := len(fields)
	for i := len(fields) - 1; i >= 0; i-- {
		if !fields[i].optional {
			break
		}
		fval := val.Field(fields[i].index)
		if isZeroValue(fval) {
			lastField = i
		} else {
			break
		}
	}

	itemBuf := encBufPool.Get().(*bytes.Buffer)
	itemBuf.Reset()
	defer encBufPool.Put(itemBuf)

	for i := 0; i < lastField; i++ {
		f := fields[i]
		fval := val.Field(f.index)
		if f.optional && isZeroValue(fval) {
			// Encode zero-valued optional field as empty string.
			itemBuf.WriteByte(0x80)
			continue
		}
		if f.tail {
			// Tail field: encode each element of the slice directly into the list.
			if fval.Kind() != reflect.Slice {
				return fmt.Errorf("rlp: tail field must be a slice")
			}
			for j := 0; j < fval.Len(); j++ {
				if err := encodeValue(itemBuf, fval.Index(j)); err != nil {
					return err
				}
			}
			continue
		}
		if err := encodeValue(itemBuf, fval); err != nil {
			return err
		}
	}

	writeHeader(w, 0xc0, uint64(itemBuf.Len()))
	w.Write(itemBuf.Bytes())
	return nil
}

// writeHeader writes an RLP header (either string or list prefix).
// base is 0x80 for strings, 0xc0 for lists.
func writeHeader(w *bytes.Buffer, base byte, size uint64) {
	if size < 56 {
		w.WriteByte(base + byte(size))
	} else {
		lenSize := putintSize(size)
		lenBuf := make([]byte, lenSize)
		putint(lenBuf, size)
		if base == 0x80 {
			w.WriteByte(0xb7 + byte(lenSize))
		} else {
			w.WriteByte(0xf7 + byte(lenSize))
		}
		w.Write(lenBuf)
	}
}

// structField describes a single struct field for RLP encoding.
type structField struct {
	index    int
	optional bool
	tail     bool
}

// structFieldsCache caches struct field information.
var structFieldsCache sync.Map // map[reflect.Type][]structField

// getStructFields returns the RLP-relevant fields of a struct type.
func getStructFields(t reflect.Type) []structField {
	if cached, ok := structFieldsCache.Load(t); ok {
		return cached.([]structField)
	}

	var fields []structField
	tailSeen := false
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("rlp")
		if tag == "-" {
			continue
		}
		if tailSeen {
			// This panic fires during type-reflection caching at init
			// time. It indicates a programming error in a struct
			// definition (a field tagged after the tail field) and
			// cannot be triggered by user input.
			panic(fmt.Sprintf("rlp: struct field after tail field in %v", t))
		}
		sf := structField{index: i}
		switch tag {
		case "tail":
			sf.tail = true
			tailSeen = true
		case "optional":
			sf.optional = true
		}
		fields = append(fields, sf)
	}

	structFieldsCache.Store(t, fields)
	return fields
}

// isZeroValue reports whether val is a zero value for its type.
func isZeroValue(val reflect.Value) bool {
	switch val.Kind() {
	case reflect.Bool:
		return !val.Bool()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return val.Uint() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int() == 0
	case reflect.String:
		return val.String() == ""
	case reflect.Slice, reflect.Array:
		return val.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return val.IsNil()
	case reflect.Struct:
		// Check if all exported fields are zero.
		for i := 0; i < val.NumField(); i++ {
			if val.Type().Field(i).IsExported() && !isZeroValue(val.Field(i)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
