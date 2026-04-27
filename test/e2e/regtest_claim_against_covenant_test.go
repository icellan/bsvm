// Package e2e — scaffolded harness that drives a withdrawal claim
// against the COMPILED bridge covenant (Rúnar locking script + Mode 1
// SP1 verifier replay). Currently t.Skip'd because the prerequisites
// have not landed in this worktree yet.
//
// What this test will exercise once the prerequisites land:
//
//  1. Compile the bridge covenant Rúnar script via runar-go
//     (pkg/covenant/contracts/bridge_*.runar.go) into a real Bitcoin
//     locking script.
//  2. Funded by a BSV regtest fee wallet (test/regtest/funding) the
//     bridge UTXO is created on-regtest with the compiled locking
//     script and a BridgeMonitor.SetBridgeUTXO sets the in-memory
//     state.
//  3. The TestWithdrawalClaim_E2E happy path is replayed, but the
//     mock broadcaster is replaced with a real
//     covenant.BroadcastClient pointed at the regtest node + ARC.
//  4. The claim tx is broadcast for real; assertions cover (a) the
//     regtest mempool sees the tx, (b) after a single block the user's
//     L1 P2PKH balance reflects the CSV-locked output (after maturity).
//
// Until the listed TODOs are done, run with -tags ” to skip; the test
// short-circuits with t.Skip so it is visible in `go test ./...` output
// but does not gate CI.
//
// TODOs to enable this test:
//   - pkg/covenant/contracts/bridge_*.runar.go: ensure CompileBridgeCovenant
//     returns a serialisable locking script + the matching state-machine
//     witness layout.
//   - pkg/bridge/monitor.go: BridgeMonitor.SetBridgeUTXO accessor (sibling EE).
//   - pkg/bridge: ChainDBWithdrawalScanner + ChainDBAdvanceFinder
//     production impls (siblings AA + EE) so we can drop the
//     staticScanner / staticAdvanceFinder used by the in-process harness.
//   - test/regtest: regtest BSV node fixture + fee-wallet funding helper.
//   - covenant.BroadcastClient pointed at the regtest ARC: the harness
//     needs to wait for ARC's "MINED" tx status before the claim is
//     considered confirmed.
//   - cmd/bsvm/withdrawal_wiring.go: daemon-side withdrawer wiring so the
//     overlay node automatically drives ProcessFinalizedWithdrawalsLoop;
//     this test would observe the broadcast through the wired path.
//   - Mode 1 verifier setup: SP1 VerifyingKeyHash pinned in the bridge
//     covenant script must match the prover's compiled VK; without
//     this the regtest claim will fail with a verifier-rejection error.
//
// Authors of those changes: please remove the t.Skip below and run
// `go test ./test/e2e/... -run TestWithdrawalClaimAgainstCovenant -count=1`
// against a regtest fixture to verify.
package e2e

import "testing"

// TestWithdrawalClaimAgainstCovenant is the placeholder for the full
// regtest claim flow. It is intentionally skipped while the
// prerequisites listed in the file-level docstring are outstanding.
func TestWithdrawalClaimAgainstCovenant(t *testing.T) {
	t.Skip("requires runar covenant compile + Mode 1 verifier setup; see file header")
}
