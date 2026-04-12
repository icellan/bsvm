package rlp

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

// Decoder is implemented by types that require custom RLP decoding.
type Decoder interface {
	DecodeRLP(*Stream) error
}

var (
	decoderType = reflect.TypeOf((*Decoder)(nil)).Elem()
)

// Decode reads an RLP value from r and stores the result in val.
// Val must be a non-nil pointer.
func Decode(r io.Reader, val interface{}) error {
	// Read all data from r first.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s := NewStream(bytes.NewReader(data), uint64(len(data)))
	return s.Decode(val)
}

// DecodeBytes parses RLP data from b into val. Val must be a non-nil
// pointer. The input must contain exactly one value and no trailing data.
func DecodeBytes(b []byte, val interface{}) error {
	s := newByteStream(b)
	if err := s.Decode(val); err != nil {
		return err
	}
	if s.pos < len(s.data) {
		return fmt.Errorf("rlp: input contains more than one value")
	}
	return nil
}

// Stream provides streaming access to RLP-encoded data. It is not
// safe for concurrent use.
type Stream struct {
	data  []byte
	pos   int
	stack []listFrame
}

// listFrame tracks the reading state of an RLP list.
type listFrame struct {
	end int // absolute byte position where this list ends
}

// newByteStream creates a stream backed by a byte slice.
func newByteStream(data []byte) *Stream {
	return &Stream{data: data}
}

// NewStream creates a new RLP stream reading from r. If r implements
// io.ByteReader, the stream does not introduce any buffering.
// If inputLimit > 0, the stream will not read more than inputLimit bytes.
func NewStream(r io.Reader, inputLimit uint64) *Stream {
	data, err := io.ReadAll(r)
	if err != nil {
		return &Stream{}
	}
	if inputLimit > 0 && uint64(len(data)) > inputLimit {
		data = data[:inputLimit]
	}
	return &Stream{data: data}
}

// Reset resets the stream for reuse with a new reader.
func (s *Stream) Reset(r io.Reader, inputLimit uint64) {
	data, _ := io.ReadAll(r)
	if inputLimit > 0 && uint64(len(data)) > inputLimit {
		data = data[:inputLimit]
	}
	s.data = data
	s.pos = 0
	s.stack = s.stack[:0]
}

// Decode reads the next value from the stream and stores it in val.
// Val must be a non-nil pointer.
func (s *Stream) Decode(val interface{}) error {
	if val == nil {
		return fmt.Errorf("rlp: decode argument must not be nil")
	}
	rv := reflect.ValueOf(val)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("rlp: decode argument must be a non-nil pointer")
	}
	return s.decodeValue(rv.Elem())
}

// remaining returns the number of bytes remaining in the current context.
func (s *Stream) remaining() int {
	if len(s.stack) > 0 {
		end := s.stack[len(s.stack)-1].end
		return end - s.pos
	}
	return len(s.data) - s.pos
}

// readByte reads a single byte.
func (s *Stream) readByte() (byte, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	if len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
		return 0, io.EOF
	}
	b := s.data[s.pos]
	s.pos++
	return b, nil
}

// peekByte peeks at the next byte without consuming it.
func (s *Stream) peekByte() (byte, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	if len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
		return 0, io.EOF
	}
	return s.data[s.pos], nil
}

// readSlice reads n bytes.
func (s *Stream) readSlice(n int) ([]byte, error) {
	if s.pos+n > len(s.data) {
		return nil, io.ErrUnexpectedEOF
	}
	if len(s.stack) > 0 && s.pos+n > s.stack[len(s.stack)-1].end {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	copy(b, s.data[s.pos:s.pos+n])
	s.pos += n
	return b, nil
}

// Kind returns the kind and size of the next RLP value in the stream.
// The returned size is the number of bytes that make up the value's content.
func (s *Stream) Kind() (kind Kind, size uint64, err error) {
	b, err := s.readByte()
	if err != nil {
		return 0, 0, err
	}

	switch {
	case b < 0x80:
		// Single byte value.
		s.pos-- // unread: the byte IS the content
		return Byte, 0, nil
	case b <= 0xb7:
		// Short string: 0-55 bytes.
		size := uint64(b - 0x80)
		if size == 1 {
			// Check canonical encoding.
			next, err := s.peekByte()
			if err != nil {
				return 0, 0, err
			}
			if next < 0x80 {
				return 0, 0, fmt.Errorf("rlp: non-canonical size for single byte value")
			}
		}
		return String, size, nil
	case b <= 0xbf:
		// Long string.
		lenOfLen := int(b - 0xb7)
		size, err := s.readBigEndianSize(lenOfLen)
		if err != nil {
			return 0, 0, err
		}
		return String, size, nil
	case b <= 0xf7:
		// Short list.
		return List, uint64(b - 0xc0), nil
	default:
		// Long list.
		lenOfLen := int(b - 0xf7)
		size, err := s.readBigEndianSize(lenOfLen)
		if err != nil {
			return 0, 0, err
		}
		return List, size, nil
	}
}

// Bytes reads an RLP string and returns its contents as a byte slice.
func (s *Stream) Bytes() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	switch kind {
	case Byte:
		b, err := s.readByte()
		if err != nil {
			return nil, err
		}
		return []byte{b}, nil
	case String:
		if size == 0 {
			return []byte{}, nil
		}
		return s.readSlice(int(size))
	case List:
		return nil, fmt.Errorf("rlp: expected string or byte, got list")
	}
	return nil, fmt.Errorf("rlp: unexpected kind")
}

// ReadBytes reads the next RLP string value into b. The value must
// be exactly len(b) bytes long.
func (s *Stream) ReadBytes(b []byte) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}
	switch kind {
	case Byte:
		if len(b) != 1 {
			return fmt.Errorf("rlp: input value has wrong size 1, expected %d", len(b))
		}
		bb, err := s.readByte()
		if err != nil {
			return err
		}
		b[0] = bb
		return nil
	case String:
		if uint64(len(b)) != size {
			return fmt.Errorf("rlp: input value has wrong size %d, expected %d", size, len(b))
		}
		data, err := s.readSlice(int(size))
		if err != nil {
			return err
		}
		copy(b, data)
		return nil
	case List:
		return fmt.Errorf("rlp: expected string, got list")
	}
	return fmt.Errorf("rlp: unexpected kind")
}

// Raw reads the next RLP value (including its header) as raw bytes.
func (s *Stream) Raw() ([]byte, error) {
	startPos := s.pos
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}

	if kind == Byte {
		// The byte value hasn't been consumed by Kind (we unreaded it).
		b, err := s.readByte()
		if err != nil {
			return nil, err
		}
		return []byte{b}, nil
	}

	// Skip over the content.
	_, err = s.readSlice(int(size))
	if err != nil {
		return nil, err
	}

	// Return everything from startPos to current pos.
	result := make([]byte, s.pos-startPos)
	copy(result, s.data[startPos:s.pos])
	return result, nil
}

// List starts decoding an RLP list. It returns the size (in bytes) of
// the list content. After reading all list elements, ListEnd must be
// called.
func (s *Stream) List() (uint64, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	if kind != List {
		return 0, fmt.Errorf("rlp: expected list, got %v", kind)
	}
	s.stack = append(s.stack, listFrame{end: s.pos + int(size)})
	return size, nil
}

// ListEnd verifies that all elements of the current list have been read
// and returns to the enclosing list or top-level stream.
func (s *Stream) ListEnd() error {
	if len(s.stack) == 0 {
		return fmt.Errorf("rlp: not in a list")
	}
	top := s.stack[len(s.stack)-1]
	if s.pos < top.end {
		// Skip remaining bytes.
		s.pos = top.end
	}
	s.stack = s.stack[:len(s.stack)-1]
	return nil
}

// Uint reads an RLP value and decodes it as a uint64.
func (s *Stream) Uint() (uint64, error) {
	return s.Uint64()
}

// Uint64 reads an RLP string and decodes it as a uint64.
func (s *Stream) Uint64() (uint64, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	switch kind {
	case Byte:
		b, err := s.readByte()
		if err != nil {
			return 0, err
		}
		return uint64(b), nil
	case String:
		if size == 0 {
			return 0, nil
		}
		if size > 8 {
			return 0, fmt.Errorf("rlp: uint64 overflow")
		}
		b, err := s.readSlice(int(size))
		if err != nil {
			return 0, err
		}
		if b[0] == 0 {
			return 0, fmt.Errorf("rlp: non-canonical integer (leading zero)")
		}
		var v uint64
		for _, c := range b {
			v = (v << 8) | uint64(c)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("rlp: expected string, got list")
	}
}

// Bool reads an RLP value and decodes it as a boolean.
func (s *Stream) Bool() (bool, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return false, err
	}
	switch kind {
	case Byte:
		b, err := s.readByte()
		if err != nil {
			return false, err
		}
		switch b {
		case 0x01:
			return true, nil
		default:
			return false, fmt.Errorf("rlp: invalid boolean value: %d", b)
		}
	case String:
		if size == 0 {
			return false, nil
		}
		return false, fmt.Errorf("rlp: invalid boolean encoding")
	default:
		return false, fmt.Errorf("rlp: expected string, got list")
	}
}

// BigInt reads an RLP value and decodes it as a *big.Int.
func (s *Stream) BigInt() (*big.Int, error) {
	b, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, fmt.Errorf("rlp: non-canonical integer (leading zero)")
	}
	i := new(big.Int).SetBytes(b)
	return i, nil
}

// readBigEndianSize reads a big-endian encoded size.
func (s *Stream) readBigEndianSize(lenOfLen int) (uint64, error) {
	if lenOfLen > 8 {
		return 0, fmt.Errorf("rlp: size of content length exceeds 8 bytes")
	}
	b, err := s.readSlice(lenOfLen)
	if err != nil {
		return 0, err
	}
	if b[0] == 0 {
		return 0, fmt.Errorf("rlp: non-canonical size (leading zero)")
	}
	var size uint64
	for _, c := range b {
		size = (size << 8) | uint64(c)
	}
	if size < 56 {
		return 0, fmt.Errorf("rlp: non-canonical size for value < 56 bytes")
	}
	return size, nil
}

// decodeValue reads the next RLP value from the stream into val.
func (s *Stream) decodeValue(val reflect.Value) error {
	// Handle pointer types first so that nil pointers are allocated
	// before checking the Decoder interface. This prevents calling
	// DecodeRLP on a nil pointer receiver.
	if val.Kind() == reflect.Ptr {
		return s.decodePtr(val)
	}

	// Check for Decoder interface.
	if val.CanAddr() {
		addr := val.Addr()
		if addr.Type().Implements(decoderType) {
			return addr.Interface().(Decoder).DecodeRLP(s)
		}
	}
	if val.Type().Implements(decoderType) {
		return val.Interface().(Decoder).DecodeRLP(s)
	}

	// Handle RawValue.
	if val.Type() == rawValueType {
		raw, err := s.Raw()
		if err != nil {
			return err
		}
		val.SetBytes(raw)
		return nil
	}

	// Handle *big.Int.
	if val.Type() == bigIntType.Elem() {
		return s.decodeBigInt(val)
	}

	switch val.Kind() {
	case reflect.Bool:
		return s.decodeBool(val)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return s.decodeUint(val)
	case reflect.String:
		return s.decodeString(val)
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return s.decodeByteSlice(val)
		}
		return s.decodeSlice(val)
	case reflect.Array:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return s.decodeByteArray(val)
		}
		return s.decodeArray(val)
	case reflect.Struct:
		return s.decodeStruct(val)
	case reflect.Interface:
		return fmt.Errorf("rlp: cannot decode into interface type %v", val.Type())
	default:
		return fmt.Errorf("rlp: cannot decode into type %v", val.Type())
	}
}

// decodePtr handles decoding into pointer types.
func (s *Stream) decodePtr(val reflect.Value) error {
	// Peek at what kind of value we have.
	b, err := s.peekByte()
	if err != nil {
		return err
	}
	// If it's an empty string (0x80), set the pointer to nil.
	if b == 0x80 {
		// Consume the byte.
		s.readByte()
		val.Set(reflect.Zero(val.Type()))
		return nil
	}
	// Allocate a new value and decode into it.
	if val.IsNil() {
		val.Set(reflect.New(val.Type().Elem()))
	}
	return s.decodeValue(val.Elem())
}

// decodeBool decodes a boolean from the stream.
func (s *Stream) decodeBool(val reflect.Value) error {
	b, err := s.Bool()
	if err != nil {
		return err
	}
	val.SetBool(b)
	return nil
}

// decodeUint decodes an unsigned integer from the stream.
func (s *Stream) decodeUint(val reflect.Value) error {
	i, err := s.Uint64()
	if err != nil {
		return err
	}
	val.SetUint(i)
	return nil
}

// decodeString decodes a string from the stream.
func (s *Stream) decodeString(val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return err
	}
	val.SetString(string(b))
	return nil
}

// decodeByteSlice decodes a byte slice from the stream.
func (s *Stream) decodeByteSlice(val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return err
	}
	val.SetBytes(b)
	return nil
}

// decodeByteArray decodes a byte array from the stream.
func (s *Stream) decodeByteArray(val reflect.Value) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}
	arrayLen := val.Len()
	switch kind {
	case Byte:
		if arrayLen == 0 {
			return fmt.Errorf("rlp: input value has wrong size 1, expected 0")
		}
		b, err := s.readByte()
		if err != nil {
			return err
		}
		for i := 0; i < arrayLen; i++ {
			val.Index(i).SetUint(0)
		}
		val.Index(0).SetUint(uint64(b))
		return nil
	case String:
		if uint64(arrayLen) < size {
			return fmt.Errorf("rlp: input value has wrong size %d, expected at most %d", size, arrayLen)
		}
		for i := 0; i < arrayLen; i++ {
			val.Index(i).SetUint(0)
		}
		b, err := s.readSlice(int(size))
		if err != nil {
			return err
		}
		for i := 0; i < int(size); i++ {
			val.Index(i).SetUint(uint64(b[i]))
		}
		return nil
	case List:
		return fmt.Errorf("rlp: expected string, got list")
	}
	return fmt.Errorf("rlp: unexpected kind")
}

// decodeSlice decodes a non-byte slice from the stream.
func (s *Stream) decodeSlice(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	elemType := val.Type().Elem()
	var elems []reflect.Value
	for {
		if s.remaining() == 0 && len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
			break
		}
		elem := reflect.New(elemType).Elem()
		if err := s.decodeValue(elem); err != nil {
			return err
		}
		elems = append(elems, elem)
	}
	if err := s.ListEnd(); err != nil {
		return err
	}
	slice := reflect.MakeSlice(val.Type(), len(elems), len(elems))
	for i, e := range elems {
		slice.Index(i).Set(e)
	}
	val.Set(slice)
	return nil
}

// decodeArray decodes a non-byte array from the stream.
func (s *Stream) decodeArray(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	i := 0
	for {
		if s.remaining() == 0 && len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
			break
		}
		if i >= val.Len() {
			return fmt.Errorf("rlp: input list has too many elements for array of length %d", val.Len())
		}
		if err := s.decodeValue(val.Index(i)); err != nil {
			return err
		}
		i++
	}
	if err := s.ListEnd(); err != nil {
		return err
	}
	for ; i < val.Len(); i++ {
		val.Index(i).Set(reflect.Zero(val.Type().Elem()))
	}
	return nil
}

// decodeBigInt decodes a big.Int from the stream.
func (s *Stream) decodeBigInt(val reflect.Value) error {
	bi, err := s.BigInt()
	if err != nil {
		return err
	}
	val.Set(reflect.ValueOf(*bi))
	return nil
}

// decodeStruct decodes a struct from the stream.
func (s *Stream) decodeStruct(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	fields := getStructFields(val.Type())

	for i := 0; i < len(fields); i++ {
		f := fields[i]
		fval := val.Field(f.index)

		if f.tail {
			if fval.Kind() != reflect.Slice {
				return fmt.Errorf("rlp: tail field must be a slice")
			}
			elemType := fval.Type().Elem()
			var elems []reflect.Value
			for {
				if s.remaining() == 0 && len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
					break
				}
				elem := reflect.New(elemType).Elem()
				if err := s.decodeValue(elem); err != nil {
					return err
				}
				elems = append(elems, elem)
			}
			slice := reflect.MakeSlice(fval.Type(), len(elems), len(elems))
			for j, e := range elems {
				slice.Index(j).Set(e)
			}
			fval.Set(slice)
			continue
		}

		// Check if we've reached the end of the list (optional field).
		if len(s.stack) > 0 && s.pos >= s.stack[len(s.stack)-1].end {
			if f.optional {
				fval.Set(reflect.Zero(fval.Type()))
				continue
			}
			return fmt.Errorf("rlp: too few elements for struct")
		}

		if err := s.decodeValue(fval); err != nil {
			return err
		}
	}

	return s.ListEnd()
}
