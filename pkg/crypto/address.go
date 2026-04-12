package crypto

// CreateAddress creates an Ethereum contract address from sender address and nonce.
// address = keccak256(rlp([sender, nonce]))[12:]
//
// The RLP encoding is done inline to avoid circular dependencies with pkg/rlp.
func CreateAddress(sender [20]byte, nonce uint64) [20]byte {
	// RLP encode the list: [sender (20 bytes), nonce]
	//
	// sender is encoded as: 0x94 (0x80 + 20) followed by 20 bytes
	// nonce is RLP-encoded as an integer

	// Encode the sender: 0x94 + 20 bytes = 21 bytes
	senderEncoded := make([]byte, 21)
	senderEncoded[0] = 0x80 + 20
	copy(senderEncoded[1:], sender[:])

	// Encode the nonce
	nonceEncoded := rlpEncodeUint64(nonce)

	// Total content length
	contentLen := len(senderEncoded) + len(nonceEncoded)

	// Encode the list header
	var buf []byte
	if contentLen < 56 {
		buf = make([]byte, 0, 1+contentLen)
		buf = append(buf, 0xc0+byte(contentLen))
	} else {
		// For content >= 56 bytes (unlikely with 20-byte address + nonce, but correct)
		lenBytes := putUintBigEndian(uint64(contentLen))
		buf = make([]byte, 0, 1+len(lenBytes)+contentLen)
		buf = append(buf, 0xf7+byte(len(lenBytes)))
		buf = append(buf, lenBytes...)
	}
	buf = append(buf, senderEncoded...)
	buf = append(buf, nonceEncoded...)

	hash := Keccak256(buf)
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// CreateAddress2 creates an EIP-1014 CREATE2 address.
// address = keccak256(0xff ++ sender ++ salt ++ keccak256(initcode))[12:]
func CreateAddress2(sender [20]byte, salt [32]byte, initCodeHash []byte) [20]byte {
	// 1 byte (0xff) + 20 bytes (sender) + 32 bytes (salt) + 32 bytes (hash) = 85 bytes
	buf := make([]byte, 1+20+32+32)
	buf[0] = 0xff
	copy(buf[1:], sender[:])
	copy(buf[21:], salt[:])
	copy(buf[53:], initCodeHash)

	hash := Keccak256(buf)
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// rlpEncodeUint64 encodes a uint64 as an RLP string (integer encoding).
func rlpEncodeUint64(i uint64) []byte {
	if i == 0 {
		return []byte{0x80}
	}
	if i < 128 {
		return []byte{byte(i)}
	}
	// Encode as big-endian bytes with a length prefix
	b := putUintBigEndian(i)
	return append([]byte{0x80 + byte(len(b))}, b...)
}

// putUintBigEndian encodes a uint64 as minimal big-endian bytes.
func putUintBigEndian(i uint64) []byte {
	switch {
	case i < (1 << 8):
		return []byte{byte(i)}
	case i < (1 << 16):
		return []byte{byte(i >> 8), byte(i)}
	case i < (1 << 24):
		return []byte{byte(i >> 16), byte(i >> 8), byte(i)}
	case i < (1 << 32):
		return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	case i < (1 << 40):
		return []byte{byte(i >> 32), byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	case i < (1 << 48):
		return []byte{byte(i >> 40), byte(i >> 32), byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	case i < (1 << 56):
		return []byte{byte(i >> 48), byte(i >> 40), byte(i >> 32), byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	default:
		return []byte{byte(i >> 56), byte(i >> 48), byte(i >> 40), byte(i >> 32), byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	}
}
