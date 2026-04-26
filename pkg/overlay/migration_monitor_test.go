package overlay

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// buildMigrationOpReturn assembles a full OP_RETURN script matching the
// format the rollup contracts emit:
//
//	0x00 0x6a 0x4e <4-byte LE length> "BSVM\x03" || newScriptHash || newAnfHash
func buildMigrationOpReturn(newScriptHash, newAnfHash types.Hash) []byte {
	payload := make([]byte, 0, MigrationOpReturnPayloadSize)
	payload = append(payload, MigrationOpReturnMagic...)
	payload = append(payload, newScriptHash[:]...)
	payload = append(payload, newAnfHash[:]...)

	out := make([]byte, 0, 7+len(payload))
	out = append(out, 0x00, 0x6a, 0x4e)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(payload)))
	out = append(out, lenBytes...)
	out = append(out, payload...)
	return out
}

func mustHash(s string) types.Hash {
	first := sha256.Sum256([]byte(s))
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}

func TestMigrationMonitor_NoMigrationOnSameScript(t *testing.T) {
	genesisScript := []byte("genesis-script-bytes")
	mm := NewMigrationMonitor(genesisScript, nil)

	rec, err := mm.Observe(genesisScript, nil)
	if err != nil {
		t.Fatalf("unexpected error on same-script observe: %v", err)
	}
	if rec != nil {
		t.Fatal("expected no migration record when script is unchanged")
	}
}

func TestMigrationMonitor_DetectsValidMigration(t *testing.T) {
	genesisScript := []byte("genesis-script-bytes")
	newScript := []byte("the-new-covenant-script")
	newScriptHash := mustHash(string(newScript))
	newAnfHash := mustHash("anf-payload-of-new-script")
	opReturn := buildMigrationOpReturn(newScriptHash, newAnfHash)

	var logged *MigrationRecord
	mm := NewMigrationMonitor(genesisScript, MigrationLoggerFunc(func(rec MigrationRecord) {
		copy := rec
		logged = &copy
	}))

	rec, err := mm.Observe(newScript, opReturn)
	if err != nil {
		t.Fatalf("expected migration to parse, got error: %v", err)
	}
	if rec == nil {
		t.Fatal("expected a migration record")
	}
	if rec.NewScriptHash != newScriptHash {
		t.Errorf("script hash mismatch: got %x, want %x", rec.NewScriptHash, newScriptHash)
	}
	if rec.NewAnfHash != newAnfHash {
		t.Errorf("anf hash mismatch: got %x, want %x", rec.NewAnfHash, newAnfHash)
	}
	if logged == nil {
		t.Fatal("expected logger callback to fire")
	}
	if mm.CurrentScriptHash() != newScriptHash {
		t.Error("expected previous script hash to advance to new script")
	}
}

func TestMigrationMonitor_RejectsScriptChangeWithNonMigrationOpReturn(t *testing.T) {
	genesisScript := []byte("genesis-script-bytes")
	newScript := []byte("the-new-covenant-script")

	// Build an OP_RETURN that carries the BSVM\x02 advance magic
	// instead of \x03.
	advancePayload := append([]byte("BSVM\x02"), make([]byte, 64)...)
	hdr := []byte{0x00, 0x6a, 0x4e}
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(advancePayload)))
	opReturn := append(append(hdr, lenBytes...), advancePayload...)

	mm := NewMigrationMonitor(genesisScript, nil)

	_, err := mm.Observe(newScript, opReturn)
	if err == nil {
		t.Fatal("expected an error when script changed but OP_RETURN is not a migration")
	}
	if !errors.Is(err, ErrNotMigrationOpReturn) {
		t.Errorf("expected wrapped ErrNotMigrationOpReturn, got %v", err)
	}
	// previousScriptHash must NOT advance — the next Observe should
	// still see the divergence.
	if mm.CurrentScriptHash() != mustHash(string(genesisScript)) {
		t.Error("previousScriptHash should not advance on a malformed migration")
	}
}

func TestMigrationMonitor_RejectsHashMismatch(t *testing.T) {
	genesisScript := []byte("genesis-script-bytes")
	newScript := []byte("the-new-covenant-script")
	wrongHash := mustHash("a-different-script")
	newAnfHash := mustHash("anf-payload")
	opReturn := buildMigrationOpReturn(wrongHash, newAnfHash)

	mm := NewMigrationMonitor(genesisScript, nil)

	_, err := mm.Observe(newScript, opReturn)
	if err == nil {
		t.Fatal("expected an error when OP_RETURN script hash doesn't match observed script")
	}
}

func TestParseMigrationOpReturn_AcceptsBarePayload(t *testing.T) {
	scriptHash := mustHash("script")
	anfHash := mustHash("anf")
	payload := append([]byte{}, MigrationOpReturnMagic...)
	payload = append(payload, scriptHash[:]...)
	payload = append(payload, anfHash[:]...)

	rec, err := ParseMigrationOpReturn(payload)
	if err != nil {
		t.Fatalf("expected bare payload to parse, got %v", err)
	}
	if rec.NewScriptHash != scriptHash {
		t.Errorf("script hash mismatch")
	}
	if rec.NewAnfHash != anfHash {
		t.Errorf("anf hash mismatch")
	}
}

func TestParseMigrationOpReturn_RejectsWrongMagic(t *testing.T) {
	payload := append([]byte("BSVM\x02"), make([]byte, 64)...)
	_, err := ParseMigrationOpReturn(payload)
	if !errors.Is(err, ErrNotMigrationOpReturn) {
		t.Errorf("expected ErrNotMigrationOpReturn, got %v", err)
	}
}

func TestParseMigrationOpReturn_RejectsTruncated(t *testing.T) {
	payload := append([]byte{}, MigrationOpReturnMagic...)
	payload = append(payload, make([]byte, 31)...) // 31 bytes, not 64
	_, err := ParseMigrationOpReturn(payload)
	if err == nil {
		t.Fatal("expected error on truncated payload")
	}
	if errors.Is(err, ErrNotMigrationOpReturn) {
		t.Errorf("expected length error, not magic error: %v", err)
	}
}
