package rpc

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiveReloader_LogLevelApplies verifies that a whitelisted key
// routes through its applier and the supplied LogStreamer's level
// changes accordingly.
func TestLiveReloader_LogLevelApplies(t *testing.T) {
	streamer := NewLogStreamer(nil, 16)
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	streamer.AttachLevelVar(lv)

	r := NewLiveReloader("")
	r.RegisterLogLevel(streamer)

	resp, err := r.Apply("log_level", json.RawMessage(`"debug"`))
	if err != nil {
		t.Fatalf("Apply: unexpected err = %v", err)
	}
	if got, want := resp["success"], true; got != want {
		t.Fatalf("response.success = %v, want %v", got, want)
	}
	if got, want := resp["value"], "debug"; got != want {
		t.Fatalf("response.value = %v, want %v", got, want)
	}
	if got := lv.Level(); got != slog.LevelDebug {
		t.Fatalf("level after apply = %v, want %v", got, slog.LevelDebug)
	}
}

// TestLiveReloader_NonWhitelistedKeyRejected verifies that a key
// outside the registry returns the spec-mandated structured error
// listing the whitelisted keys.
func TestLiveReloader_NonWhitelistedKeyRejected(t *testing.T) {
	streamer := NewLogStreamer(nil, 16)
	lv := new(slog.LevelVar)
	streamer.AttachLevelVar(lv)
	r := NewLiveReloader("")
	r.RegisterLogLevel(streamer)

	_, err := r.Apply("min_gas_price", json.RawMessage(`"2000000000"`))
	if err == nil {
		t.Fatal("expected error for non-whitelisted key")
	}
	msg := err.Error()
	if !strings.Contains(msg, `key "min_gas_price"`) {
		t.Errorf("error missing key reference: %v", err)
	}
	if !strings.Contains(msg, "requires restart") {
		t.Errorf("error missing 'requires restart' phrase: %v", err)
	}
	if !strings.Contains(msg, "log_level") {
		t.Errorf("error missing whitelisted-keys list (expected log_level): %v", err)
	}
}

// TestLiveReloader_InvalidValueRejected verifies that a whitelisted
// key with a malformed value surfaces a clear validation error and
// does NOT mutate the underlying LogStreamer level.
func TestLiveReloader_InvalidValueRejected(t *testing.T) {
	streamer := NewLogStreamer(nil, 16)
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelWarn)
	streamer.AttachLevelVar(lv)
	r := NewLiveReloader("")
	r.RegisterLogLevel(streamer)

	tests := []struct {
		name    string
		value   string
		wantSub string
	}{
		{"unknown level", `"verbose"`, `unknown log level "verbose"`},
		{"non-string", `42`, "expected string"},
		{"empty string", `""`, "unknown log level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.Apply("log_level", json.RawMessage(tt.value))
			if err == nil {
				t.Fatalf("expected error for value=%s", tt.value)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q missing %q", err.Error(), tt.wantSub)
			}
			if got := lv.Level(); got != slog.LevelWarn {
				t.Errorf("level mutated despite invalid value: got %v, want %v", got, slog.LevelWarn)
			}
		})
	}
}

// TestLiveReloader_PersistsOverrides verifies that successful applies
// write through to the configured sidecar file and that
// LoadAdminOverrides round-trips them.
func TestLiveReloader_PersistsOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_overrides.json")

	streamer := NewLogStreamer(nil, 16)
	lv := new(slog.LevelVar)
	streamer.AttachLevelVar(lv)
	r := NewLiveReloader(path)
	r.RegisterLogLevel(streamer)

	resp, err := r.Apply("log_level", json.RawMessage(`"warn"`))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, want := resp["persisted"], true; got != want {
		t.Errorf("persisted = %v, want %v", got, want)
	}

	overrides, err := LoadAdminOverrides(path)
	if err != nil {
		t.Fatalf("LoadAdminOverrides: %v", err)
	}
	if got, want := overrides["log_level"], "warn"; got != want {
		t.Errorf("overrides[log_level] = %q, want %q", got, want)
	}
}

// TestLoadAdminOverrides_MissingFileIsNoop verifies that the loader
// treats a non-existent sidecar as "no overrides yet" — fresh
// installs and operators who never used admin_setConfig must not get
// a boot error.
func TestLoadAdminOverrides_MissingFileIsNoop(t *testing.T) {
	overrides, err := LoadAdminOverrides(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadAdminOverrides: unexpected err = %v", err)
	}
	if overrides != nil {
		t.Errorf("overrides = %v, want nil", overrides)
	}
}

// TestLiveReloader_NoStreamerWired verifies that registering
// log_level against a nil streamer surfaces a clear error so
// operators don't silently lose admin_setConfig calls.
func TestLiveReloader_NoStreamerWired(t *testing.T) {
	r := NewLiveReloader("")
	r.RegisterLogLevel(nil) // explicit nil streamer
	_, err := r.Apply("log_level", json.RawMessage(`"info"`))
	if err == nil {
		t.Fatal("expected error when log streamer not configured")
	}
	if !strings.Contains(err.Error(), "log streamer not configured") {
		t.Errorf("error %q missing expected phrase", err.Error())
	}
}

// TestLogStreamer_SetLevelWithoutAttach verifies that calling
// SetLevel before AttachLevelVar surfaces a clear error rather than
// silently no-opping.
func TestLogStreamer_SetLevelWithoutAttach(t *testing.T) {
	s := NewLogStreamer(nil, 16)
	if err := s.SetLevel(slog.LevelDebug); err == nil {
		t.Fatal("expected error when no LevelVar attached")
	}
	if _, ok := s.CurrentLevel(); ok {
		t.Errorf("CurrentLevel() ok=true with no LevelVar attached")
	}
}

// TestAdminAPI_SetConfig_NoReloader verifies the legacy fallback:
// a daemon that never wired a LiveReloader still gets a clear
// "restart required" error rather than panicking on a nil pointer.
func TestAdminAPI_SetConfig_NoReloader(t *testing.T) {
	a := &AdminAPI{}
	_, err := a.SetConfig("log_level", json.RawMessage(`"debug"`))
	if err == nil {
		t.Fatal("expected error when no reloader configured")
	}
	if !strings.Contains(err.Error(), "live-reload registry not configured") {
		t.Errorf("error %q missing expected phrase", err.Error())
	}
}

// TestAdminAPI_SetConfig_WhitelistedKey verifies the happy path
// through the AdminAPI surface (not just the LiveReloader directly).
func TestAdminAPI_SetConfig_WhitelistedKey(t *testing.T) {
	streamer := NewLogStreamer(nil, 16)
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	streamer.AttachLevelVar(lv)
	r := NewLiveReloader("")
	r.RegisterLogLevel(streamer)

	a := &AdminAPI{}
	a.SetLiveReloader(r)

	resp, err := a.SetConfig("log_level", json.RawMessage(`"error"`))
	if err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if got, want := resp["success"], true; got != want {
		t.Errorf("success = %v, want %v", got, want)
	}
	if lv.Level() != slog.LevelError {
		t.Errorf("level = %v, want LevelError", lv.Level())
	}
}
