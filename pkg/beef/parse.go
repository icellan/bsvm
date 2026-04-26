package beef

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// BEEF magic bytes per BRC-62 ("Atomic BEEF" version 0100BEEF and
// the V2 0200BEEF extension carry the same wire prefix; we accept
// both variants and reject anything else). Stored as little-endian
// uint32 on the wire.
const (
	beefMagicV1 uint32 = 0x0100BEEF
	beefMagicV2 uint32 = 0x0200BEEF
)

// ParsedTx is a minimal representation of a parsed BSV transaction
// extracted from a BEEF body. It carries the raw bytes plus the
// computed double-SHA256 txid (BSV little-endian wire form). Inputs
// and outputs are NOT deserialised here — consumers that need fields
// (e.g. the bridge to read the OP_RETURN deposit envelope) walk the
// raw bytes themselves using a transaction-parsing helper from the
// BSV SDK.
type ParsedTx struct {
	TxID    [32]byte
	RawTx   []byte
	HasBUMP bool
	BUMPRef uint32 // index into ParsedBEEF.BUMPs when HasBUMP, else 0
}

// ParsedBUMP is a minimal stand-in for a BRC-74 BUMP (BSV Unified
// Merkle Path). The full BUMP structure is parsed by go-wallet-toolbox
// in production; here we keep just the raw bytes so the BEEF round-
// trips faithfully and downstream consumers can hand them to a real
// parser.
type ParsedBUMP struct {
	BlockHeight uint64
	Raw         []byte
}

// ParsedBEEF is the result of parsing a BRC-62 BEEF body. It exposes
// the target transaction (last entry by BRC-62 convention), every
// ancestor transaction, and every BUMP in the BEEF.
type ParsedBEEF struct {
	Version  uint32
	BUMPs    []ParsedBUMP
	Txs      []ParsedTx
	TargetID [32]byte
}

// Target returns the BEEF's target transaction (the last tx in the
// BRC-62 ordering).
func (p *ParsedBEEF) Target() *ParsedTx {
	if len(p.Txs) == 0 {
		return nil
	}
	return &p.Txs[len(p.Txs)-1]
}

// errBEEFTruncated is returned when a BEEF body is shorter than its
// declared structure requires.
var errBEEFTruncated = errors.New("beef: truncated body")

// ParseBEEF parses a BRC-62 BEEF body into its constituent pieces.
//
// The implementation is intentionally minimal:
//
//   - It recognises the V1 (0100BEEF) and V2 (0200BEEF) magic prefixes.
//   - It walks the BUMPs array using BRC-74's varint-prefixed encoding,
//     skipping each BUMP's payload and storing the raw bytes for later
//     use.
//   - It walks the transactions array and computes each tx's txid via
//     double-SHA256 over the raw bytes.
//
// Full BUMP parsing, ancestor-graph reconstruction, and inclusion
// verification against chaintracks are NOT performed here. They are the
// job of go-wallet-toolbox's BEEF helpers, which production wiring will
// call before placing entries into the BEEFStore.
func ParseBEEF(body []byte) (*ParsedBEEF, error) {
	if len(body) < 4 {
		return nil, errBEEFTruncated
	}
	magic := binary.LittleEndian.Uint32(body[:4])
	if magic != beefMagicV1 && magic != beefMagicV2 {
		return nil, fmt.Errorf("beef: bad magic 0x%08x", magic)
	}
	pos := 4

	bumpCount, n, err := readVarInt(body[pos:])
	if err != nil {
		return nil, fmt.Errorf("beef: read bump count: %w", err)
	}
	pos += n

	out := &ParsedBEEF{Version: magic}
	for i := uint64(0); i < bumpCount; i++ {
		// A BUMP starts with a varint block height, then a varint tree
		// height, then per-level path data. Without re-implementing the
		// full BRC-74 parser we walk the BUMP using its declared length
		// prefix — but BRC-74 does not carry an outer length prefix, so
		// we do a best-effort skip: read block height + tree height,
		// then for each level read varint count and consume two varint-
		// prefixed entries per leaf (offset + hash/duplicate flag).
		//
		// This skip is sufficient for round-tripping and for envelope
		// validation; production-grade verification still goes through
		// go-wallet-toolbox.
		blockHeight, hn, herr := readVarInt(body[pos:])
		if herr != nil {
			return nil, fmt.Errorf("beef: bump %d block height: %w", i, herr)
		}
		startPos := pos
		pos += hn
		treeHeight, thn, therr := readVarInt(body[pos:])
		if therr != nil {
			return nil, fmt.Errorf("beef: bump %d tree height: %w", i, therr)
		}
		pos += thn
		for lvl := uint64(0); lvl <= treeHeight; lvl++ {
			leafCount, lcn, lcerr := readVarInt(body[pos:])
			if lcerr != nil {
				return nil, fmt.Errorf("beef: bump %d level %d leaf count: %w", i, lvl, lcerr)
			}
			pos += lcn
			for leaf := uint64(0); leaf < leafCount; leaf++ {
				_, on, oerr := readVarInt(body[pos:])
				if oerr != nil {
					return nil, fmt.Errorf("beef: bump %d leaf %d offset: %w", i, leaf, oerr)
				}
				pos += on
				if pos >= len(body) {
					return nil, errBEEFTruncated
				}
				flag := body[pos]
				pos++
				switch flag {
				case 0x00:
					// Hash follows.
					if pos+32 > len(body) {
						return nil, errBEEFTruncated
					}
					pos += 32
				case 0x01:
					// Duplicate: nothing more on this leaf.
				case 0x02:
					// Client tx leaf at the bottom level: hash follows.
					if pos+32 > len(body) {
						return nil, errBEEFTruncated
					}
					pos += 32
				default:
					return nil, fmt.Errorf("beef: bump %d leaf %d unknown flag 0x%02x", i, leaf, flag)
				}
			}
		}
		out.BUMPs = append(out.BUMPs, ParsedBUMP{
			BlockHeight: blockHeight,
			Raw:         append([]byte(nil), body[startPos:pos]...),
		})
	}

	txCount, tn, err := readVarInt(body[pos:])
	if err != nil {
		return nil, fmt.Errorf("beef: read tx count: %w", err)
	}
	pos += tn

	for i := uint64(0); i < txCount; i++ {
		txStart := pos
		_, consumed, terr := readBSVTransaction(body[pos:])
		if terr != nil {
			return nil, fmt.Errorf("beef: tx %d: %w", i, terr)
		}
		pos += consumed
		if pos >= len(body) {
			return nil, errBEEFTruncated
		}
		hasBUMP := body[pos]
		pos++
		var bumpRef uint32
		if hasBUMP == 0x01 {
			bumpIdx, bn, bumpErr := readVarInt(body[pos:])
			if bumpErr != nil {
				return nil, fmt.Errorf("beef: tx %d bump ref: %w", i, bumpErr)
			}
			pos += bn
			bumpRef = uint32(bumpIdx)
		} else if hasBUMP != 0x00 {
			return nil, fmt.Errorf("beef: tx %d unknown has-bump flag 0x%02x", i, hasBUMP)
		}
		raw := body[txStart : pos-1-bumpRefSize(hasBUMP, bumpRef)]
		_ = raw
		// Recompute raw bytes range: tx body only.
		txBody := body[txStart : txStart+consumed]
		out.Txs = append(out.Txs, ParsedTx{
			TxID:    bsvTxID(txBody),
			RawTx:   append([]byte(nil), txBody...),
			HasBUMP: hasBUMP == 0x01,
			BUMPRef: bumpRef,
		})
	}

	if pos != len(body) {
		return nil, fmt.Errorf("beef: trailing %d bytes", len(body)-pos)
	}
	if t := out.Target(); t != nil {
		out.TargetID = t.TxID
	}
	return out, nil
}

// bumpRefSize is a placeholder kept to make the slicing arithmetic
// above explicit; the real raw slice is computed via the consumed
// counter only, so this returns zero.
func bumpRefSize(_ byte, _ uint32) int { return 0 }

// readVarInt parses a BSV varint (Bitcoin compact size) from buf and
// returns the value plus the number of bytes consumed.
func readVarInt(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, errBEEFTruncated
	}
	prefix := buf[0]
	switch {
	case prefix < 0xfd:
		return uint64(prefix), 1, nil
	case prefix == 0xfd:
		if len(buf) < 3 {
			return 0, 0, errBEEFTruncated
		}
		return uint64(binary.LittleEndian.Uint16(buf[1:3])), 3, nil
	case prefix == 0xfe:
		if len(buf) < 5 {
			return 0, 0, errBEEFTruncated
		}
		return uint64(binary.LittleEndian.Uint32(buf[1:5])), 5, nil
	default:
		if len(buf) < 9 {
			return 0, 0, errBEEFTruncated
		}
		return binary.LittleEndian.Uint64(buf[1:9]), 9, nil
	}
}

// readBSVTransaction walks a serialised BSV transaction starting at
// buf[0] and returns its declared length plus the consumed bytes.
//
// Layout:
//   - 4 bytes version (LE)
//   - varint input count
//     for each input:
//   - 32 bytes prev txid
//   - 4 bytes vout (LE)
//   - varint script length
//   - script bytes
//   - 4 bytes sequence (LE)
//   - varint output count
//     for each output:
//   - 8 bytes value (LE)
//   - varint script length
//   - script bytes
//   - 4 bytes locktime (LE)
func readBSVTransaction(buf []byte) (length int, consumed int, err error) {
	if len(buf) < 4 {
		return 0, 0, errBEEFTruncated
	}
	pos := 4 // version
	inCount, n, err := readVarInt(buf[pos:])
	if err != nil {
		return 0, 0, fmt.Errorf("input count: %w", err)
	}
	pos += n
	for i := uint64(0); i < inCount; i++ {
		if pos+36 > len(buf) {
			return 0, 0, errBEEFTruncated
		}
		pos += 36 // prev txid + vout
		scriptLen, sn, serr := readVarInt(buf[pos:])
		if serr != nil {
			return 0, 0, fmt.Errorf("input %d script len: %w", i, serr)
		}
		pos += sn
		if uint64(pos)+scriptLen+4 > uint64(len(buf)) {
			return 0, 0, errBEEFTruncated
		}
		pos += int(scriptLen) + 4 // script + sequence
	}

	outCount, n, err := readVarInt(buf[pos:])
	if err != nil {
		return 0, 0, fmt.Errorf("output count: %w", err)
	}
	pos += n
	for i := uint64(0); i < outCount; i++ {
		if pos+8 > len(buf) {
			return 0, 0, errBEEFTruncated
		}
		pos += 8 // value
		scriptLen, sn, serr := readVarInt(buf[pos:])
		if serr != nil {
			return 0, 0, fmt.Errorf("output %d script len: %w", i, serr)
		}
		pos += sn
		if uint64(pos)+scriptLen > uint64(len(buf)) {
			return 0, 0, errBEEFTruncated
		}
		pos += int(scriptLen)
	}

	if pos+4 > len(buf) {
		return 0, 0, errBEEFTruncated
	}
	pos += 4 // locktime
	return pos, pos, nil
}

// bsvTxID returns the double-SHA256 of raw in BSV little-endian wire
// form (the canonical txid byte order matching what the network
// publishes). Big-endian display form is the reverse.
func bsvTxID(raw []byte) [32]byte {
	a := sha256.Sum256(raw)
	return sha256.Sum256(a[:])
}
