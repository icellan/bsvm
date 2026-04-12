package types

import (
	"encoding/binary"

	"github.com/icellan/bsvm/pkg/crypto"
)

const (
	// BloomByteLength represents the number of bytes in a bloom filter.
	BloomByteLength = 256
	// BloomBitLength represents the number of bits in a bloom filter.
	BloomBitLength = 8 * BloomByteLength
)

// Bloom represents a 2048-bit bloom filter used in Ethereum for log filtering.
type Bloom [BloomByteLength]byte

// SetBytes sets the bloom filter from a byte slice.
func (b *Bloom) SetBytes(d []byte) {
	if len(d) > BloomByteLength {
		d = d[len(d)-BloomByteLength:]
	}
	copy(b[BloomByteLength-len(d):], d)
}

// Add adds data to the bloom filter using the bloom9 algorithm.
// bloom9: keccak256 the data, take bytes [0:2], [2:4], [4:6] as big-endian
// uint16, mod 2048 each to get 3 bit indices, then set those bits.
func (b *Bloom) Add(d []byte) {
	i1, i2, i3 := bloom9(d)
	b[BloomByteLength-1-i1/8] |= 1 << (i1 % 8)
	b[BloomByteLength-1-i2/8] |= 1 << (i2 % 8)
	b[BloomByteLength-1-i3/8] |= 1 << (i3 % 8)
}

// Test checks if data might be contained in the bloom filter.
func (b Bloom) Test(d []byte) bool {
	i1, i2, i3 := bloom9(d)
	return b[BloomByteLength-1-i1/8]&(1<<(i1%8)) != 0 &&
		b[BloomByteLength-1-i2/8]&(1<<(i2%8)) != 0 &&
		b[BloomByteLength-1-i3/8]&(1<<(i3%8)) != 0
}

// OrBloom performs a bitwise OR with another bloom filter.
func (b *Bloom) OrBloom(bl Bloom) {
	for i := range b {
		b[i] |= bl[i]
	}
}

// Bytes returns the byte slice representation of the bloom filter.
func (b Bloom) Bytes() []byte {
	return b[:]
}

// bloom9 returns three bit indices derived from the keccak256 hash of d.
func bloom9(d []byte) (uint, uint, uint) {
	h := crypto.Keccak256(d)
	i1 := uint(binary.BigEndian.Uint16(h[0:2])) & (BloomBitLength - 1)
	i2 := uint(binary.BigEndian.Uint16(h[2:4])) & (BloomBitLength - 1)
	i3 := uint(binary.BigEndian.Uint16(h[4:6])) & (BloomBitLength - 1)
	return i1, i2, i3
}

// CreateBloom creates a bloom filter from a slice of receipts.
func CreateBloom(receipts []*Receipt) Bloom {
	var b Bloom
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			b.Add(log.Address.Bytes())
			for _, topic := range log.Topics {
				b.Add(topic.Bytes())
			}
		}
	}
	return b
}

// LogsBloom creates a bloom filter from a slice of logs and returns the
// raw bytes.
func LogsBloom(logs []*Log) []byte {
	var b Bloom
	for _, log := range logs {
		b.Add(log.Address.Bytes())
		for _, topic := range log.Topics {
			b.Add(topic.Bytes())
		}
	}
	return b.Bytes()
}

// BloomLookup tests if the bloom filter might contain the given topic.
func BloomLookup(bloom Bloom, topic []byte) bool {
	return bloom.Test(topic)
}
