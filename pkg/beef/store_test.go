package beef

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
)

func sampleEnvelope(intent byte, txid byte, confirmed bool, height uint64, recv time.Time) *Envelope {
	var id [32]byte
	for i := range id {
		id[i] = txid
	}
	return &Envelope{
		Header: EnvelopeHeader{
			Version: EnvelopeVersion,
			Intent:  intent,
			Flags:   FlagShardBound,
			ShardID: 1,
		},
		Beef:        []byte{0xef, 0xbe, 0x00, 0x01},
		TargetTxID:  id,
		Confirmed:   confirmed,
		BlockHeight: height,
		ReceivedAt:  recv.UTC(),
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now().UTC()
	env := sampleEnvelope(IntentCovenantAdvanceUnconfirmed, 0xab, false, 0, now)
	if err := s.Put(env); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ok, err := s.Has(env.TargetTxID)
	if err != nil || !ok {
		t.Fatalf("Has: ok=%v err=%v", ok, err)
	}
	got, err := s.Get(env.TargetTxID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.TargetTxID != env.TargetTxID {
		t.Fatalf("unexpected get result: %+v", got)
	}
	// confirm upgrade keeps the better entry
	upgraded := sampleEnvelope(IntentCovenantAdvanceConfirmed, 0xab, true, 100, now.Add(time.Second))
	upgraded.TargetTxID = env.TargetTxID
	if err := s.Put(upgraded); err != nil {
		t.Fatalf("Put upgrade: %v", err)
	}
	got, _ = s.Get(env.TargetTxID)
	if !got.Confirmed || got.BlockHeight != 100 {
		t.Fatalf("upgrade not applied: %+v", got)
	}
	// putting an unconfirmed envelope after confirmed must NOT downgrade
	dn := sampleEnvelope(IntentCovenantAdvanceUnconfirmed, 0xab, false, 0, now.Add(2*time.Second))
	dn.TargetTxID = env.TargetTxID
	if err := s.Put(dn); err != nil {
		t.Fatalf("Put downgrade: %v", err)
	}
	got, _ = s.Get(env.TargetTxID)
	if !got.Confirmed {
		t.Fatalf("downgrade was applied")
	}
	// delete
	if err := s.Delete(env.TargetTxID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = s.Get(env.TargetTxID)
	if got != nil {
		t.Fatalf("expected nil after delete")
	}
}

func TestMemoryStoreIterate(t *testing.T) {
	s := NewMemoryStore()
	t0 := time.Unix(1700000000, 0).UTC()
	envs := []*Envelope{
		sampleEnvelope(IntentBridgeDeposit, 0x01, true, 10, t0),
		sampleEnvelope(IntentBridgeDeposit, 0x02, true, 11, t0.Add(time.Second)),
		sampleEnvelope(IntentInboxSubmission, 0x03, false, 0, t0.Add(2*time.Second)),
	}
	for _, e := range envs {
		if err := s.Put(e); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	var seen []byte
	if err := s.Iterate(IntentBridgeDeposit, func(e *Envelope) bool {
		seen = append(seen, e.Header.Intent)
		return true
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("intent filter, want 2 got %d", len(seen))
	}
	seen = nil
	_ = s.Iterate(0, func(e *Envelope) bool { seen = append(seen, e.Header.Intent); return true })
	if len(seen) != 3 {
		t.Fatalf("all intents, want 3 got %d", len(seen))
	}
}

func TestLevelStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d, err := db.NewLevelDB(filepath.Join(dir, "beef"), 16, 16)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	defer d.Close()
	s := NewLevelStore(d)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	env := sampleEnvelope(IntentBridgeDeposit, 0x55, true, 200, now)
	if err := s.Put(env); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(env.TargetTxID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("nil get")
	}
	if got.BlockHeight != 200 || !got.Confirmed {
		t.Fatalf("bad envelope: %+v", got)
	}

	var visited int
	if err := s.Iterate(IntentBridgeDeposit, func(e *Envelope) bool {
		visited++
		return true
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if visited != 1 {
		t.Fatalf("visited %d, want 1", visited)
	}
}

func TestEnvelopeStoredCodec(t *testing.T) {
	now := time.Unix(1700000000, 12345).UTC()
	env := sampleEnvelope(IntentCovenantAdvanceConfirmed, 0xcc, true, 9, now)
	enc, err := env.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := DecodeStoredEnvelope(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec.Header != env.Header {
		t.Fatalf("header mismatch")
	}
	if !dec.ReceivedAt.Equal(env.ReceivedAt) {
		t.Fatalf("recv mismatch %v vs %v", dec.ReceivedAt, env.ReceivedAt)
	}
}
