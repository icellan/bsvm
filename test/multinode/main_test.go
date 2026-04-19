//go:build multinode

package multinode

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		// Skip silently if Docker is not available.
		os.Exit(0)
	}

	// Build the test image.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", "bsvm:test", "../..")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cancel()
		panic("failed to build bsvm:test: " + err.Error())
	}
	cancel()

	os.Exit(m.Run())
}
