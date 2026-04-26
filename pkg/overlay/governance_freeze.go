package overlay

import (
	"errors"
	"strings"
)

// IsBatcherPausedErr reports whether err originates from a paused
// batcher. Matches both the new sentinel-wrapped form and the legacy
// "batcher is paused" message so the test stays robust regardless of
// which error path produced it.
func IsBatcherPausedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBatcherPaused) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "batcher is paused") ||
		strings.Contains(msg, "shard frozen")
}
