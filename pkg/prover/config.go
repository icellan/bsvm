package prover

import "time"

// ProverMode determines how proofs are generated.
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

// Config holds the SP1 prover configuration.
type Config struct {
	// Mode determines how proofs are generated (local, network, or mock).
	Mode ProverMode

	// HostBridgeBinary is the path to the bsvm-host-bridge Rust binary
	// that translates between JSON and SP1's bincode format.
	HostBridgeBinary string

	// GuestELFPath is the path to the compiled SP1 guest ELF program.
	GuestELFPath string

	// NetworkURL is the SP1 prover network URL (used in network mode).
	NetworkURL string

	// Timeout is the maximum proving time before the prover aborts.
	Timeout time.Duration

	// ProofMode specifies the SP1 proof type: "compressed", "core", or "groth16".
	ProofMode string
}

// DefaultConfig returns a Config suitable for local development and testing.
func DefaultConfig() Config {
	return Config{
		Mode:      ProverMock,
		Timeout:   10 * time.Minute,
		ProofMode: "compressed",
	}
}
