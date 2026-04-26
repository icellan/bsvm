// Package beef implements the BEEF (BRC-62) wire format and gossip
// envelope used by BSVM nodes to exchange BSV transactions plus their
// SPV-verifiable ancestry. See spec/17-CHAINTRACKS-BEEF-ARC.md.
//
// This package is scaffold-quality: it ships the 17-byte gossip envelope
// codec, a BEEF transaction parser sufficient for the bridge / inbox /
// governance use cases, and an in-memory + LevelDB-backed BEEFStore.
// Full BRC-62 ancestry-graph reconstruction and BUMP verification against
// chaintracks headers is a follow-up wave; this package gives the rest
// of the codebase a stable surface to call into.
package beef

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Topic magic for BEEF gossip envelopes ("BSVB" in ASCII = 0x42535642).
const TopicMagic = 0x42535642

// EnvelopeVersion is the current version of the BEEF gossip envelope.
const EnvelopeVersion byte = 0x01

// EnvelopeHeaderSize is the fixed length of a BEEF gossip envelope
// header in bytes (4 magic + 1 ver + 1 intent + 1 flags + 8 shard +
// 2 reserved).
const EnvelopeHeaderSize = 17

// Intent codes per spec 17.
const (
	IntentCovenantAdvanceUnconfirmed byte = 0x01
	IntentCovenantAdvanceConfirmed   byte = 0x02
	IntentBridgeDeposit              byte = 0x03
	IntentFeeWalletFunding           byte = 0x04
	IntentInboxSubmission            byte = 0x05
	IntentGovernanceAction           byte = 0x06
)

// IntentName returns a human-readable name for an intent code.
func IntentName(intent byte) string {
	switch intent {
	case IntentCovenantAdvanceUnconfirmed:
		return "covenant-advance-unconfirmed"
	case IntentCovenantAdvanceConfirmed:
		return "covenant-advance-confirmed"
	case IntentBridgeDeposit:
		return "bridge-deposit"
	case IntentFeeWalletFunding:
		return "fee-wallet-funding"
	case IntentInboxSubmission:
		return "inbox-submission"
	case IntentGovernanceAction:
		return "governance-action"
	default:
		return fmt.Sprintf("unknown-intent-0x%02x", intent)
	}
}

// IntentValid reports whether intent is a recognised BEEF intent code.
func IntentValid(intent byte) bool {
	return intent >= IntentCovenantAdvanceUnconfirmed && intent <= IntentGovernanceAction
}

// FlagShardBound is bit 0 of the envelope flag byte. When set, the
// shard ID field is meaningful; when clear, it MUST be zero.
const FlagShardBound byte = 0x01

// EnvelopeHeader is the parsed form of the 17-byte gossip envelope
// prefix. The body BEEF bytes follow this header on the wire and are
// not parsed by this codec.
type EnvelopeHeader struct {
	Version  byte
	Intent   byte
	Flags    byte
	ShardID  uint64
	Reserved uint16
}

// ShardBound reports whether the envelope's shard ID is meaningful.
func (h EnvelopeHeader) ShardBound() bool {
	return h.Flags&FlagShardBound != 0
}

// Encode serialises h into the 17-byte gossip envelope header layout.
// The body BEEF bytes (h is purely the prefix) are the caller's
// responsibility to append.
func (h EnvelopeHeader) Encode() ([]byte, error) {
	if h.Version != EnvelopeVersion {
		return nil, fmt.Errorf("beef: unsupported envelope version 0x%02x", h.Version)
	}
	if !IntentValid(h.Intent) {
		return nil, fmt.Errorf("beef: unknown intent 0x%02x", h.Intent)
	}
	if h.Flags&^FlagShardBound != 0 {
		return nil, fmt.Errorf("beef: reserved flag bits set in 0x%02x", h.Flags)
	}
	if !h.ShardBound() && h.ShardID != 0 {
		return nil, errors.New("beef: shard ID nonzero with shard-bound flag clear")
	}
	if h.Reserved != 0 {
		return nil, fmt.Errorf("beef: reserved bytes nonzero (0x%04x)", h.Reserved)
	}

	out := make([]byte, EnvelopeHeaderSize)
	binary.BigEndian.PutUint32(out[0:4], TopicMagic)
	out[4] = h.Version
	out[5] = h.Intent
	out[6] = h.Flags
	binary.BigEndian.PutUint64(out[7:15], h.ShardID)
	binary.BigEndian.PutUint16(out[15:17], h.Reserved)
	return out, nil
}

// DecodeEnvelopeHeader parses the 17-byte prefix from buf and returns
// the parsed header plus the remaining body bytes (the BEEF payload).
// It rejects malformed envelopes — wrong magic, unsupported version,
// unknown intents, reserved bits set, or buffer too short.
func DecodeEnvelopeHeader(buf []byte) (EnvelopeHeader, []byte, error) {
	var h EnvelopeHeader
	if len(buf) < EnvelopeHeaderSize {
		return h, nil, fmt.Errorf("beef: envelope too short (%d < %d)", len(buf), EnvelopeHeaderSize)
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != TopicMagic {
		return h, nil, fmt.Errorf("beef: bad topic magic 0x%08x", magic)
	}
	h.Version = buf[4]
	if h.Version != EnvelopeVersion {
		return h, nil, fmt.Errorf("beef: unsupported envelope version 0x%02x", h.Version)
	}
	h.Intent = buf[5]
	if !IntentValid(h.Intent) {
		return h, nil, fmt.Errorf("beef: unknown intent 0x%02x", h.Intent)
	}
	h.Flags = buf[6]
	if h.Flags&^FlagShardBound != 0 {
		return h, nil, fmt.Errorf("beef: reserved flag bits set in 0x%02x", h.Flags)
	}
	h.ShardID = binary.BigEndian.Uint64(buf[7:15])
	if !h.ShardBound() && h.ShardID != 0 {
		return h, nil, errors.New("beef: shard ID nonzero with shard-bound flag clear")
	}
	h.Reserved = binary.BigEndian.Uint16(buf[15:17])
	if h.Reserved != 0 {
		return h, nil, fmt.Errorf("beef: reserved bytes nonzero (0x%04x)", h.Reserved)
	}
	return h, buf[EnvelopeHeaderSize:], nil
}

// EncodeEnvelope serialises the gossip envelope header followed by body
// into a single buffer ready for the wire. body is the BRC-62 BEEF
// bytes; it is appended verbatim without validation.
func EncodeEnvelope(h EnvelopeHeader, body []byte) ([]byte, error) {
	hdr, err := h.Encode()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, EnvelopeHeaderSize+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out, nil
}
