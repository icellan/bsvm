package prover

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/icellan/bsvm/pkg/types"
)

// VerifyProof verifies an SP1 proof locally. In production, verification
// happens on-chain in the BSV covenant. This function is for testing and
// local validation.
//
// For mock proofs (identified by the "MOCK_SP1_PROOF" marker), verification
// always succeeds. For real proofs, the host-bridge binary is invoked with
// a --verify flag.
func VerifyProof(proof *Proof, expectedVKHash types.Hash, config *Config) error {
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}

	// Mock proofs always verify successfully.
	if bytes.Equal(proof.Data, []byte("MOCK_SP1_PROOF")) {
		return nil
	}

	// Verify VK hash matches.
	if proof.VKHash != expectedVKHash {
		return fmt.Errorf("vk hash mismatch: got %s, want %s", proof.VKHash.Hex(), expectedVKHash.Hex())
	}

	// Verify public values are well-formed.
	encoded := proof.PublicValues.Encode()
	if len(encoded) != PublicValuesSize {
		return fmt.Errorf("invalid public values size: %d", len(encoded))
	}

	// If no config or no host bridge binary, we can only do structural checks.
	if config == nil || config.HostBridgeBinary == "" {
		return fmt.Errorf("host bridge binary not configured for proof verification")
	}

	return verifyViaHostBridge(proof, config)
}

// verifyViaHostBridge invokes the host-bridge binary with --verify to
// perform cryptographic proof verification.
func verifyViaHostBridge(proof *Proof, config *Config) error {
	ctx := context.Background()
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	// Serialize the proof for the host bridge.
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return fmt.Errorf("serializing proof for verification: %w", err)
	}

	cmd := exec.CommandContext(ctx, config.HostBridgeBinary, "--verify")
	cmd.Stdin = bytes.NewReader(proofJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("proof verification failed: %w, stderr: %s", err, stderr.String())
	}

	// Parse verification result.
	var result struct {
		Valid bool   `json:"valid"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return fmt.Errorf("parsing verification result: %w", err)
	}
	if !result.Valid {
		return fmt.Errorf("proof verification failed: %s", result.Error)
	}

	return nil
}
