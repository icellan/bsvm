//go:build multinode

// Package multinode provides a Docker-based test harness for running a
// multi-node BSVM cluster. It manages Docker Compose lifecycle and
// provides helpers for interacting with individual nodes.
package multinode

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// DockerCluster manages a Docker Compose cluster of BSVM nodes.
type DockerCluster struct {
	composeDir string
	nodeCount  int
	t          testing.TB
}

// NewDockerCluster creates a new DockerCluster pointing at the docker-compose
// directory relative to this source file.
func NewDockerCluster(t testing.TB) *DockerCluster {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine source file path")
	}
	composeDir := filepath.Join(filepath.Dir(thisFile), "docker")

	return &DockerCluster{
		composeDir: composeDir,
		nodeCount:  3,
		t:          t,
	}
}

// Start brings up the Docker Compose cluster. It calls docker compose up -d
// and waits for all containers to report healthy.
func (dc *DockerCluster) Start(ctx context.Context) error {
	cmd := dc.composeCmd(ctx, "up", "-d", "--wait")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up: %w\n%s", err, out)
	}
	return nil
}

// Stop tears down the Docker Compose cluster, removing volumes.
func (dc *DockerCluster) Stop(ctx context.Context) error {
	cmd := dc.composeCmd(ctx, "down", "-v", "--remove-orphans")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose down: %w\n%s", err, out)
	}
	return nil
}

// NodeRPC returns the JSON-RPC URL for the given node index (1-based).
func (dc *DockerCluster) NodeRPC(nodeIndex int) string {
	if nodeIndex < 1 || nodeIndex > dc.nodeCount {
		dc.t.Fatalf("node index %d out of range [1, %d]", nodeIndex, dc.nodeCount)
	}
	port := 28544 + nodeIndex // node1=28545, node2=28546, node3=28547
	return fmt.Sprintf("http://localhost:%d", port)
}

// KillNode forcibly stops a single node container.
func (dc *DockerCluster) KillNode(ctx context.Context, nodeIndex int) error {
	name := dc.containerName(nodeIndex)
	cmd := exec.CommandContext(ctx, "docker", "kill", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker kill %s: %w\n%s", name, err, out)
	}
	return nil
}

// StartNode restarts a previously killed node container.
func (dc *DockerCluster) StartNode(ctx context.Context, nodeIndex int) error {
	name := dc.containerName(nodeIndex)
	cmd := exec.CommandContext(ctx, "docker", "start", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker start %s: %w\n%s", name, err, out)
	}
	return nil
}

// WaitAllNodesReady polls eth_blockNumber on every node until all respond
// successfully or the context is cancelled.
func (dc *DockerCluster) WaitAllNodesReady(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for nodes to become ready: %w", ctx.Err())
		case <-ticker.C:
			allReady := true
			for i := 1; i <= dc.nodeCount; i++ {
				_, err := GetBlockNumber(ctx, dc.NodeRPC(i))
				if err != nil {
					allReady = false
					break
				}
			}
			if allReady {
				return nil
			}
		}
	}
}

// projectName is the Docker Compose project name. Using an explicit name
// prevents collision with other compose stacks (e.g. the bsv-evm devnet
// stack whose default project name is also directory-derived).
const projectName = "bsvm-test-multinode"

// composeCmd constructs a docker compose command targeting the cluster's
// compose directory with an explicit project name.
func (dc *DockerCluster) composeCmd(ctx context.Context, args ...string) *exec.Cmd {
	fullArgs := append([]string{
		"compose",
		"-p", projectName,
		"-f", filepath.Join(dc.composeDir, "docker-compose.yml"),
	}, args...)
	return exec.CommandContext(ctx, "docker", fullArgs...)
}

// containerName returns the Docker container name for a given node index.
// Matches the container_name in docker-compose.yml.
func (dc *DockerCluster) containerName(nodeIndex int) string {
	return fmt.Sprintf("bsvm-test-mn-node%d", nodeIndex)
}
