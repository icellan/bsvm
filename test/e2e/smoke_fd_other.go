//go:build !linux

package e2e

import "errors"

// readDirImpl is a stub for non-Linux platforms. The smoke test treats
// a -1 result from openFDCount as "platform doesn't expose FDs", so
// the assertion silently skips. macOS doesn't expose /proc, and
// shelling out to lsof would slow the test by seconds for no gain.
func readDirImpl(_ string) ([]string, error) {
	return nil, errors.New("readDirImpl: not supported on this platform")
}
