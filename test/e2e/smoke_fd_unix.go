//go:build linux

package e2e

import "os"

// readDirImpl returns the names of every entry in path, using
// os.ReadDir. Linux build only — /proc/self/fd is the canonical FD
// sample point.
func readDirImpl(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
