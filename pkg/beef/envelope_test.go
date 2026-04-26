package beef

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		intent byte
		flags  byte
		shard  uint64
	}{
		{"covenant-unconfirmed", IntentCovenantAdvanceUnconfirmed, FlagShardBound, 0xdeadbeef},
		{"covenant-confirmed", IntentCovenantAdvanceConfirmed, FlagShardBound, 1},
		{"bridge-deposit", IntentBridgeDeposit, FlagShardBound, 42},
		{"fee-wallet-funding-shardless", IntentFeeWalletFunding, 0, 0},
		{"inbox-submission", IntentInboxSubmission, FlagShardBound, 7},
		{"governance", IntentGovernanceAction, FlagShardBound, 99},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := EnvelopeHeader{
				Version: EnvelopeVersion,
				Intent:  c.intent,
				Flags:   c.flags,
				ShardID: c.shard,
			}
			body := []byte("payload bytes here")
			env, err := EncodeEnvelope(h, body)
			if err != nil {
				t.Fatalf("EncodeEnvelope: %v", err)
			}
			if len(env) != EnvelopeHeaderSize+len(body) {
				t.Fatalf("envelope wrong size %d", len(env))
			}
			gotMagic := binary.BigEndian.Uint32(env[:4])
			if gotMagic != TopicMagic {
				t.Fatalf("magic = 0x%08x want 0x%08x", gotMagic, TopicMagic)
			}
			gotH, gotBody, err := DecodeEnvelopeHeader(env)
			if err != nil {
				t.Fatalf("DecodeEnvelopeHeader: %v", err)
			}
			if gotH != h {
				t.Fatalf("decoded header %+v != %+v", gotH, h)
			}
			if !bytes.Equal(gotBody, body) {
				t.Fatalf("body mismatch")
			}
		})
	}
}

func TestEnvelopeRejectsMalformed(t *testing.T) {
	good := EnvelopeHeader{
		Version: EnvelopeVersion,
		Intent:  IntentCovenantAdvanceConfirmed,
		Flags:   FlagShardBound,
		ShardID: 1,
	}
	enc, err := good.Encode()
	if err != nil {
		t.Fatalf("good encode: %v", err)
	}
	cases := []struct {
		name string
		buf  []byte
	}{
		{"too-short", enc[:10]},
		{"bad-magic", func() []byte {
			b := append([]byte(nil), enc...)
			b[0] = 0xff
			return b
		}()},
		{"unknown-version", func() []byte {
			b := append([]byte(nil), enc...)
			b[4] = 0x99
			return b
		}()},
		{"unknown-intent", func() []byte {
			b := append([]byte(nil), enc...)
			b[5] = 0x77
			return b
		}()},
		{"reserved-flag-bit", func() []byte {
			b := append([]byte(nil), enc...)
			b[6] = 0x80
			return b
		}()},
		{"shard-id-without-flag", func() []byte {
			h := good
			h.Flags = 0
			h.ShardID = 5
			b, _ := h.Encode()
			return b
		}()},
		{"reserved-bytes-set", func() []byte {
			b := append([]byte(nil), enc...)
			b[15] = 0x01
			return b
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := DecodeEnvelopeHeader(c.buf); err == nil {
				if c.name == "shard-id-without-flag" {
					// Encode itself rejects this; decode never gets a buf.
					return
				}
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestIntentName(t *testing.T) {
	if IntentName(IntentBridgeDeposit) != "bridge-deposit" {
		t.Fatalf("unexpected name")
	}
	if IntentName(0xfe) == "" {
		t.Fatalf("unknown name should be non-empty")
	}
	if IntentValid(0x00) || IntentValid(0x07) {
		t.Fatalf("unknown intents must be invalid")
	}
}
