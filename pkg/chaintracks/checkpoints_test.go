package chaintracks

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestDefaultCheckpointsParse(t *testing.T) {
	cps := DefaultCheckpoints()
	if len(cps) == 0 {
		t.Fatal("expected at least one checkpoint")
	}
	for _, c := range cps {
		if c.Hash == ([32]byte{}) {
			t.Errorf("checkpoint %d has zero hash", c.Height)
		}
	}
	// Genesis must be height 0 and the canonical Bitcoin/BSV genesis hash.
	if cps[0].Height != 0 {
		t.Fatalf("first checkpoint height = %d want 0", cps[0].Height)
	}
	want := MustReverseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	if cps[0].Hash != want {
		t.Fatalf("genesis checkpoint hash mismatch:\n got %s\nwant %s",
			hex.EncodeToString(cps[0].Hash[:]), hex.EncodeToString(want[:]))
	}
}

func TestEnforceCheckpointsAcceptsCorrect(t *testing.T) {
	cp := Checkpoint{Height: 1000, Hash: mkHash(0xab)}
	h := &BlockHeader{Height: 1000, Hash: mkHash(0xab)}
	if err := EnforceCheckpoints(h, []Checkpoint{cp}); err != nil {
		t.Fatalf("correct checkpoint rejected: %v", err)
	}
}

func TestEnforceCheckpointsRejectsMismatch(t *testing.T) {
	cp := Checkpoint{Height: 1000, Hash: mkHash(0xab)}
	h := &BlockHeader{Height: 1000, Hash: mkHash(0xcd)}
	err := EnforceCheckpoints(h, []Checkpoint{cp})
	if !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("expected ErrCheckpointMismatch, got %v", err)
	}
}

func TestEnforceCheckpointsRejectsBelow(t *testing.T) {
	cps := []Checkpoint{
		{Height: 100, Hash: mkHash(0x10)},
		{Height: 1000, Hash: mkHash(0xab)},
	}
	h := &BlockHeader{Height: 50, Hash: mkHash(0xff)}
	err := EnforceCheckpoints(h, cps)
	if !errors.Is(err, ErrBelowCheckpoint) {
		t.Fatalf("expected ErrBelowCheckpoint, got %v", err)
	}
}

func TestEnforceCheckpointsAllowsHigher(t *testing.T) {
	cps := []Checkpoint{{Height: 100, Hash: mkHash(0x10)}}
	h := &BlockHeader{Height: 200, Hash: mkHash(0xff)}
	if err := EnforceCheckpoints(h, cps); err != nil {
		t.Fatalf("higher header should pass: %v", err)
	}
}

func TestEnforceCheckpointsNilDisables(t *testing.T) {
	h := &BlockHeader{Height: 1, Hash: mkHash(0x99)}
	if err := EnforceCheckpoints(h, nil); err != nil {
		t.Fatalf("nil checkpoints should disable enforcement: %v", err)
	}
}

func TestMustReverseHex(t *testing.T) {
	got := MustReverseHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	want := [32]byte{
		0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
		0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
		0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	}
	if got != want {
		t.Fatalf("reverse mismatch: got %x want %x", got, want)
	}
}
