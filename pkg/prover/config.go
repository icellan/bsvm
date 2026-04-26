package prover

import (
	"time"

	"github.com/icellan/bsvm/pkg/proofmode"
)

// ProverMode determines how proofs are generated (who computes the proof).
// This is orthogonal to ProofMode: ProverMode picks the execution backend
// (local subprocess / network / mock), while ProofMode picks the
// verification math (FRI / Groth16-generic / Groth16-witness).
type ProverMode int

const (
	// ProverLocal runs the SP1 prover locally via a subprocess.
	ProverLocal ProverMode = iota
	// ProverNetwork uses the SP1 prover network (remote).
	ProverNetwork
	// ProverMock skips proving and returns a dummy proof (testing only).
	ProverMock
)

// String returns a human-readable name for the prover mode.
func (m ProverMode) String() string {
	switch m {
	case ProverLocal:
		return "local"
	case ProverNetwork:
		return "network"
	case ProverMock:
		return "mock"
	default:
		return "unknown"
	}
}

// ProofMode is re-exported from pkg/proofmode so callers that already
// import pkg/prover can refer to the enum without an extra import. The
// enum identifies which on-chain verification path a proof is for.
type ProofMode = proofmode.ProofMode

// Re-exported ProofMode constants.
const (
	ProofModeFRI       = proofmode.FRI
	ProofModeGroth16   = proofmode.Groth16
	ProofModeGroth16WA = proofmode.Groth16WA
)

// Config holds the SP1 prover configuration.
type Config struct {
	// Mode determines how proofs are generated (local, network, or mock).
	Mode ProverMode

	// ProofMode determines which on-chain verification path the produced
	// proofs target (FRI, Groth16-generic, Groth16-witness). This is
	// orthogonal to Mode: Mode picks the backend, ProofMode picks the math.
	ProofMode ProofMode

	// HostBridgeBinary is the path to the bsvm-host-bridge Rust binary
	// that translates between JSON and SP1's bincode format.
	HostBridgeBinary string

	// GuestELFPath is the path to the compiled SP1 guest ELF program.
	GuestELFPath string

	// NetworkURL is the SP1 prover network URL (used in network mode).
	NetworkURL string

	// Timeout is the maximum proving time before the prover aborts.
	Timeout time.Duration

	// SP1ProofMode specifies the SP1 proof envelope format ("compressed",
	// "core", or "groth16") that is passed to the host bridge. This is
	// distinct from ProofMode: SP1ProofMode picks the proof encoding,
	// ProofMode picks the on-chain verification contract.
	SP1ProofMode string
}

// DefaultConfig returns a Config suitable for local development and testing.
func DefaultConfig() Config {
	return Config{
		Mode:         ProverMock,
		ProofMode:    ProofModeFRI,
		Timeout:      10 * time.Minute,
		SP1ProofMode: "compressed",
	}
}
