package overlay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// MigrationOpReturnMagic is the BSVM magic prefix carried in the
// migration tx's OP_RETURN payload. See spec 10 "Covenant Migration":
//
//	BSVM\x03 || hash256(newCovenantScript) || newCovenantAnfHash
//
// (8 + 32 + 32 = 72 bytes). \x03 follows the existing scheme:
// \x00 = genesis manifest, \x01 = genesis, \x02 = advance, \x03 = migration.
var MigrationOpReturnMagic = []byte("BSVM\x03")

// MigrationOpReturnPayloadSize is the length of the BSVM migration
// payload (magic + newScriptHash + newAnfHash).
const MigrationOpReturnPayloadSize = len("BSVM\x03") + 32 + 32

// MigrationRecord is the parsed contents of a migration OP_RETURN
// payload.
type MigrationRecord struct {
	NewScriptHash types.Hash // hash256 of the new covenant locking script
	NewAnfHash    types.Hash // hash256 of the published new ANF JSON
}

// ParseMigrationOpReturn validates and parses a migration OP_RETURN
// payload. Accepts either the full OP_RETURN script (with the
// OP_FALSE / OP_RETURN / pushdata header) or the bare payload
// (magic + 64 bytes). Returns ErrNotMigrationOpReturn if the magic
// prefix doesn't match.
func ParseMigrationOpReturn(data []byte) (*MigrationRecord, error) {
	payload := stripOpReturnHeader(data)
	if len(payload) < len(MigrationOpReturnMagic) {
		return nil, ErrNotMigrationOpReturn
	}
	if string(payload[:len(MigrationOpReturnMagic)]) != string(MigrationOpReturnMagic) {
		return nil, ErrNotMigrationOpReturn
	}
	if len(payload) != MigrationOpReturnPayloadSize {
		return nil, fmt.Errorf("migration op_return: expected %d bytes, got %d",
			MigrationOpReturnPayloadSize, len(payload))
	}
	rec := &MigrationRecord{}
	copy(rec.NewScriptHash[:], payload[len(MigrationOpReturnMagic):len(MigrationOpReturnMagic)+32])
	copy(rec.NewAnfHash[:], payload[len(MigrationOpReturnMagic)+32:])
	return rec, nil
}

// ErrNotMigrationOpReturn is returned by ParseMigrationOpReturn when the
// supplied bytes do not carry the BSVM migration magic prefix. Callers
// can use errors.Is to distinguish this from a malformed-but-tagged
// payload.
var ErrNotMigrationOpReturn = errors.New("not a BSVM migration OP_RETURN")

// MigrationLogger is the interface MigrationMonitor uses to surface
// observed migrations. The overlay node provides a slog-backed
// implementation; tests can plug in a recorder.
type MigrationLogger interface {
	LogMigration(rec MigrationRecord)
}

// MigrationMonitor watches covenant advances for locking-script changes
// and surfaces migration events. It is intentionally narrow: detection
// and OP_RETURN parsing only. Recompiling the new ANF and verifying it
// against the new locking script is a re-deploy step handled outside
// this watcher.
type MigrationMonitor struct {
	mu sync.Mutex

	// previousScriptHash is the hash256 of the most recently observed
	// covenant locking script. Updated on every Observe call.
	previousScriptHash types.Hash

	// logger receives migration events; nil disables logging.
	logger MigrationLogger
}

// NewMigrationMonitor constructs a MigrationMonitor seeded with the
// genesis covenant locking script's hash256.
func NewMigrationMonitor(genesisScript []byte, logger MigrationLogger) *MigrationMonitor {
	return &MigrationMonitor{
		previousScriptHash: hash256(genesisScript),
		logger:             logger,
	}
}

// Observe is called for every covenant advance the overlay sees on BSV.
// newScript is the locking script of the covenant output in the advance
// tx (whatever the spending tx wrote into output 0). opReturn is the
// raw OP_RETURN script from the same tx (for migrations the BSVM\x03
// payload; for normal advances the BSVM\x02 batchData payload).
//
// Observe returns:
//   - (rec, nil) when a migration was detected, the OP_RETURN parsed,
//     and the script hash bound by the OP_RETURN matches hash256 of the
//     new locking script.
//   - (nil, nil) when newScript matches the previously observed script
//     hash (i.e. a normal advance, no migration).
//   - (nil, err) when a script-hash change WAS observed but the
//     OP_RETURN failed to parse or didn't bind to the new script. The
//     caller should treat this as a critical mismatch — the on-chain
//     covenant has been replaced but the migration publication is
//     malformed.
func (m *MigrationMonitor) Observe(newScript []byte, opReturn []byte) (*MigrationRecord, error) {
	newHash := hash256(newScript)

	m.mu.Lock()
	defer m.mu.Unlock()

	if newHash == m.previousScriptHash {
		return nil, nil
	}

	rec, parseErr := ParseMigrationOpReturn(opReturn)
	if parseErr != nil {
		// The script changed but the OP_RETURN doesn't carry a
		// migration tag. Don't update previousScriptHash so the next
		// Observe call still flags the divergence.
		return nil, fmt.Errorf("covenant script changed but OP_RETURN is not a migration: %w", parseErr)
	}
	if rec.NewScriptHash != newHash {
		return nil, fmt.Errorf(
			"migration OP_RETURN binds script hash %x but observed script hashes to %x",
			rec.NewScriptHash[:], newHash[:])
	}

	m.previousScriptHash = newHash
	if m.logger != nil {
		m.logger.LogMigration(*rec)
	}
	return rec, nil
}

// CurrentScriptHash returns the hash256 of the most recently observed
// covenant locking script. Useful for debug surfaces.
func (m *MigrationMonitor) CurrentScriptHash() types.Hash {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.previousScriptHash
}

// stripOpReturnHeader strips a leading OP_FALSE / OP_RETURN / pushdata
// preamble (matching the format the rollup contracts emit) and returns
// the bare payload. If no recognised preamble is present, the input is
// returned unchanged so callers can pass either form.
//
// Recognised preambles (matching contracts/rollup_*.runar.go):
//
//	0x00 0x6a 0x4e <4-byte LE length> <payload>      // OP_PUSHDATA4
//	0x00 0x6a 0x4d <2-byte LE length> <payload>      // OP_PUSHDATA2
//	0x00 0x6a 0x4c <1-byte length>    <payload>      // OP_PUSHDATA1
//	0x00 0x6a <1-byte length 0x01-0x4b> <payload>     // direct push
func stripOpReturnHeader(data []byte) []byte {
	if len(data) < 3 {
		return data
	}
	if data[0] != 0x00 || data[1] != 0x6a {
		return data
	}
	rest := data[2:]
	if len(rest) == 0 {
		return data
	}
	switch op := rest[0]; {
	case op == 0x4e: // OP_PUSHDATA4
		if len(rest) < 5 {
			return data
		}
		l := binary.LittleEndian.Uint32(rest[1:5])
		end := 5 + int(l)
		if end > len(rest) {
			return data
		}
		return rest[5:end]
	case op == 0x4d: // OP_PUSHDATA2
		if len(rest) < 3 {
			return data
		}
		l := binary.LittleEndian.Uint16(rest[1:3])
		end := 3 + int(l)
		if end > len(rest) {
			return data
		}
		return rest[3:end]
	case op == 0x4c: // OP_PUSHDATA1
		if len(rest) < 2 {
			return data
		}
		l := int(rest[1])
		end := 2 + l
		if end > len(rest) {
			return data
		}
		return rest[2:end]
	case op >= 0x01 && op <= 0x4b: // direct push
		l := int(op)
		end := 1 + l
		if end > len(rest) {
			return data
		}
		return rest[1:end]
	}
	return data
}

// migrationLoggerFunc adapts a plain function to the MigrationLogger
// interface so callers can pass a closure without declaring a type.
type migrationLoggerFunc func(MigrationRecord)

func (f migrationLoggerFunc) LogMigration(rec MigrationRecord) { f(rec) }

// MigrationLoggerFunc returns a MigrationLogger that calls fn for every
// observed migration.
func MigrationLoggerFunc(fn func(MigrationRecord)) MigrationLogger {
	return migrationLoggerFunc(fn)
}

// hash256 reuses the helper defined in inbox_monitor.go (same package).
// Both files compute SHA-256(SHA-256(x)) — the same as BSV OP_HASH256.
