package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// liveReloadKey enumerates the runtime-mutable config keys
// admin_setConfig will accept. The set is intentionally tiny: every
// entry is something a key-applier function can apply to live state
// without restarting the daemon. Per spec 15 §"Configuration",
// non-whitelisted keys should be rejected with a clear "restart
// required" message.
//
// Adding a new entry requires:
//
//  1. defining + wiring an applier function;
//  2. unit-testing the applier against valid + invalid inputs;
//  3. verifying the persisted override is picked up on the next
//     restart so the runtime change survives a reboot.
const (
	// LiveReloadKeyLogLevel — slog default level. Valid values:
	// "debug", "info", "warn", "error" (case-insensitive). Persisted
	// to the override sidecar; restored on restart.
	LiveReloadKeyLogLevel = "log_level"
)

// liveReloadKeys returns the canonical sorted list of whitelisted
// keys. Sorted so error messages list keys in a stable order
// regardless of map-iteration nondeterminism.
func liveReloadKeys(reg map[string]liveReloadEntry) []string {
	keys := make([]string, 0, len(reg))
	for k := range reg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// liveReloadApplier is the per-key applier closure invoked by
// SetConfig when a whitelisted key is updated. The applier validates
// the value, applies it to live state, and returns the
// canonicalised string form that gets persisted to the override
// sidecar.
type liveReloadApplier func(value json.RawMessage) (canonical string, err error)

// liveReloadEntry pairs an applier with its admin-facing
// description, used for both error messages and operator docs.
type liveReloadEntry struct {
	apply       liveReloadApplier
	description string
}

// LiveReloader owns the per-key applier registry and persists the
// resulting overrides to a sidecar JSON file (admin_overrides.json
// inside the daemon's datadir). Persistence guarantees that a
// runtime change survives a restart — the daemon-side bootstrap
// reads the same file via LoadAdminOverrides.
//
// The reloader is safe for concurrent use: the registry is
// constructed at boot and never mutated after; the persistence file
// is guarded by a mutex.
type LiveReloader struct {
	registry  map[string]liveReloadEntry
	overrides map[string]string
	mu        sync.Mutex
	persistTo string // path to admin_overrides.json; "" disables persistence
}

// NewLiveReloader constructs an empty reloader bound to persistTo
// (passing "" disables persistence — useful for tests). Use the
// Register* helpers to install per-key appliers before exposing the
// reloader to admin_setConfig.
func NewLiveReloader(persistTo string) *LiveReloader {
	return &LiveReloader{
		registry:  make(map[string]liveReloadEntry),
		overrides: make(map[string]string),
		persistTo: persistTo,
	}
}

// RegisterLogLevel wires the log_level key to the supplied
// LogStreamer. The applier accepts "debug", "info", "warn", "error"
// (case-insensitive) and routes to LogStreamer.SetLevel — which
// requires a LevelVar to have been attached during setupLogging
// (see cmd/bsvm/main.go).
func (r *LiveReloader) RegisterLogLevel(streamer *LogStreamer) {
	r.register(LiveReloadKeyLogLevel, "slog default level (debug|info|warn|error)", func(value json.RawMessage) (string, error) {
		var level string
		if err := json.Unmarshal(value, &level); err != nil {
			return "", fmt.Errorf("expected string, got %s", strings.TrimSpace(string(value)))
		}
		lvl, err := parseSlogLevel(level)
		if err != nil {
			return "", err
		}
		if streamer == nil {
			return "", errors.New("log streamer not configured on this daemon")
		}
		if err := streamer.SetLevel(lvl); err != nil {
			return "", err
		}
		return strings.ToLower(level), nil
	})
}

// register installs an applier under the given key. Never call this
// after the reloader has been published to AdminAPI — the registry is
// expected to be immutable post-boot.
func (r *LiveReloader) register(key, description string, apply liveReloadApplier) {
	r.registry[key] = liveReloadEntry{apply: apply, description: description}
}

// Apply is the entry point invoked by admin_setConfig. It validates
// the key against the whitelist, runs the applier, persists the
// canonicalised override on success, and returns a structured
// response suitable for the JSON-RPC reply.
//
// Non-whitelisted keys yield an error of the form:
//
//	admin_setConfig: key %q requires restart (not in live-reload
//	whitelist; whitelisted keys: [...])
//
// — operators reading the raw error see exactly which keys CAN be
// hot-applied, which is the spec-15 contract for the "Restart
// Required" admin-UI hint.
func (r *LiveReloader) Apply(key string, value json.RawMessage) (map[string]interface{}, error) {
	entry, ok := r.registry[key]
	if !ok {
		return nil, fmt.Errorf(
			"admin_setConfig: key %q requires restart (not in live-reload whitelist; whitelisted keys: %v)",
			key, liveReloadKeys(r.registry),
		)
	}
	canonical, err := entry.apply(value)
	if err != nil {
		return nil, fmt.Errorf("admin_setConfig: invalid value for %q: %w", key, err)
	}
	r.mu.Lock()
	r.overrides[key] = canonical
	persisted := false
	var persistErr error
	if r.persistTo != "" {
		persistErr = r.writeOverridesLocked()
		persisted = persistErr == nil
	}
	r.mu.Unlock()
	resp := map[string]interface{}{
		"success":   true,
		"key":       key,
		"value":     canonical,
		"persisted": persisted,
	}
	if persistErr != nil {
		// Non-fatal: the runtime change took effect, but the override
		// won't survive a restart. Surface so operators can fix
		// permissions / disk space.
		resp["persistError"] = persistErr.Error()
	}
	return resp, nil
}

// Whitelist returns the sorted list of currently-registered live-
// reload keys. Used by the explorer UI to render the "Restart
// Required" hint per field.
func (r *LiveReloader) Whitelist() []string {
	return liveReloadKeys(r.registry)
}

// Description returns the human-readable description of a
// whitelisted key, or empty if the key isn't registered. Used by the
// operator-facing admin RPC docs.
func (r *LiveReloader) Description(key string) string {
	entry, ok := r.registry[key]
	if !ok {
		return ""
	}
	return entry.description
}

// writeOverridesLocked persists the override map to the configured
// sidecar file. Must be called with r.mu held.
func (r *LiveReloader) writeOverridesLocked() error {
	if r.persistTo == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.persistTo), 0o755); err != nil {
		return fmt.Errorf("ensure datadir for admin_overrides: %w", err)
	}
	data, err := json.MarshalIndent(r.overrides, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal admin_overrides: %w", err)
	}
	tmp := r.persistTo + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write admin_overrides: %w", err)
	}
	if err := os.Rename(tmp, r.persistTo); err != nil {
		return fmt.Errorf("rename admin_overrides: %w", err)
	}
	return nil
}

// LoadAdminOverrides reads the override sidecar and returns the
// key/value map. Returns (nil, nil) if the file does not exist —
// fresh installs and operators who never used admin_setConfig get a
// no-op. Errors only when the file exists but is unreadable / invalid.
//
// Daemon bootstrap calls this AFTER loading the TOML config and
// applies each override on top of the parsed values. The applier is
// the daemon's responsibility — the loader only resurfaces the raw
// strings.
func LoadAdminOverrides(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

// parseSlogLevel parses a level string into slog.Level. Accepts
// "debug", "info", "warn", "error" (case-insensitive). Returns an
// error for unknown values; the caller surfaces it through the
// admin_setConfig response.
func parseSlogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (allowed: debug|info|warn|error)", s)
	}
}
