// Package e2e — keccak256 indirection used by the withdrawal-claim
// harness. Split out so the test file does not have to import the
// pkg/crypto package directly inline (keeps the long test file
// self-contained at the top).
package e2e

import "github.com/icellan/bsvm/pkg/crypto"

// cryptoKeccak256 is a thin wrapper over pkg/crypto.Keccak256 used by
// the withdrawal-claim harness when reconstructing the
// WithdrawalInitiated topic from receipts.
func cryptoKeccak256(data []byte) []byte { return crypto.Keccak256(data) }
