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

	// Build the test image using the build script (handles runar deps
	// and parent-directory build context).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	cmd := exec.CommandContext(ctx, "bash", "docker/build.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cancel()
		panic("failed to build bsvm:test: " + err.Error())
	}
	cancel()

	os.Exit(m.Run())
}
