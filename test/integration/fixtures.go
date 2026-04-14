//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"runar-integration/helpers"
)

// ---------------------------------------------------------------------------
// Shared fixtures for the rollup covenant integration tests
// ---------------------------------------------------------------------------
//
// These helpers used to live inline in rollup_full_test.go. That file was
// written against the old dual-mode rollup contract and has been replaced
// by rollup_basefold_test.go + rollup_groth16_test.go. The shared
// deterministic fixture builders (Merkle proof, public-values encoding,
// proof/batch data generators) are factored out here so they can be reused
// by both per-mode test files AND by continuous_proving_regtest_test.go.
//
// This file is tagged with the `integration` build tag so it is only
// compiled when running the BSV regtest integration suite.

// rollupContractPath points at the new Basefold rollup contract source.
// The old dual-mode rollup.runar.go has been deleted; this path is
// preserved for continuous_proving_regtest_test.go which still references
// it until the parallel broadcast-client rework catches up.
const rollupContractPath = "pkg/covenant/contracts/rollup_basefold.runar.go"

// Per-advance fixture sizes. Mirror the original rollup_full_test.go
// values — big enough to exercise realistic TX sizes on regtest.
const (
	proofBlobSize   = 165_000 // ~165 KB SP1 STARK proof
	batchDataSize   = 20_000  // ~20 KB compressed batch
	merkleDepth     = 20      // FRI query depth / Merkle tree depth
	merkleLeafIndex = 7
)

// hexGenProofBlob returns a deterministic hex-encoded proof blob of the
// given byte size. The bytes are derived from a SHA256 chain seeded by the
// input byte so every (seed, size) pair is stable across runs.
func hexGenProofBlob(seed byte, size int) string {
	data := make([]byte, size)
	h := sha256.Sum256([]byte{seed})
	for i := 0; i < size; i += 32 {
		end := i + 32
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
		h = sha256.Sum256(h[:])
	}
	return hex.EncodeToString(data)
}

// hexGenBatchData returns a deterministic hex-encoded batch data blob of
// the given size, bound to the provided pre/post state roots so different
// transitions produce different blobs.
func hexGenBatchData(preStateRoot, newStateRoot string, size int) string {
	base, _ := hex.DecodeString(preStateRoot + newStateRoot)
	data := make([]byte, size)
	copy(data, base)
	h := sha256.Sum256(base)
	for i := len(base); i < size; i += 32 {
		end := i + 32
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
		h = sha256.Sum256(h[:])
	}
	return hex.EncodeToString(data)
}

// buildHexDepth20Proof constructs a valid depth-merkleDepth Merkle proof
// without materializing the full 2^depth leaf tree. Each sibling at depth
// d is sha256(depth || (idx^1)), which lets us reconstruct a root that
// matches the on-chain MerkleRootSha256 verifier.
func buildHexDepth20Proof(leafHex string, index int) (proofHex, rootHex string) {
	var siblings []string
	current := leafHex
	idx := index
	for d := 0; d < merkleDepth; d++ {
		sibling := hexSha256(hex.EncodeToString([]byte{byte(d), byte(idx ^ 1)}))
		siblings = append(siblings, sibling)
		if idx&1 == 0 {
			current = hexSha256(current + sibling)
		} else {
			current = hexSha256(sibling + current)
		}
		idx >>= 1
	}
	p := ""
	for _, s := range siblings {
		p += s
	}
	return p, current
}

// fullPVNum2binHexLE encodes an int64 as `size` little-endian bytes and
// returns the hex. Matches the on-chain Num2Bin primitive used to bake the
// chain ID into the public values blob.
func fullPVNum2binHexLE(v int64, size int) string {
	buf := make([]byte, size)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	return hex.EncodeToString(buf[:size])
}

// buildFullPV constructs the 272-byte public values blob expected by the
// Basefold / Groth16 rollup contracts. The layout is:
//
//	[0..32]    preStateRoot
//	[32..64]   postStateRoot
//	[64..96]   hash256(proofBlob)
//	[96..104]  zero padding
//	[104..136] hash256(batchData)
//	[136..144] chainId (little-endian, 8 bytes)
//	[144..272] zero-filled reserved slots (four 32-byte chunks)
func buildFullPV(preStateRoot, postStateRoot, batchDataHex, proofBlobHex string, cid int64) string {
	z32 := hexZeros32()
	z8 := "0000000000000000"
	proofHash := hexHash256(proofBlobHex)
	batchDataHash := hexHash256(batchDataHex)
	chainIdBytes := fullPVNum2binHexLE(cid, 8)

	return preStateRoot + postStateRoot + proofHash + z8 +
		batchDataHash + chainIdBytes + z32 + z32 + z32 + z32
}

// Fixed Merkle fixture shared between every test that deploys the rollup
// covenant. The contract's SP1VerifyingKeyHash readonly slot is baked to
// fullMerkleRootHex at deploy time, and every AdvanceState call supplies
// fullMerkleLeafHex / fullMerkleProofHex / merkleLeafIndex as its Merkle
// inclusion witness.
var (
	fullMerkleLeafHex  string
	fullMerkleProofHex string
	fullMerkleRootHex  string
)

func init() {
	fullMerkleLeafHex = hexSha256("00")
	fullMerkleProofHex, fullMerkleRootHex = buildHexDepth20Proof(fullMerkleLeafHex, merkleLeafIndex)
}

// fullGetTxSize returns the raw-transaction byte size for a txid by
// asking the Bitcoin node via getrawtransaction. On RPC failure the helper
// logs a warning and returns 0 so callers can continue reporting metrics
// without aborting the test.
func fullGetTxSize(t *testing.T, txid string) int {
	t.Helper()
	result, rpcErr := helpers.RPCCall("getrawtransaction", txid)
	if rpcErr != nil {
		t.Logf("warning: RPC error for %s: %v", txid, rpcErr)
		return 0
	}
	var h string
	if err := json.Unmarshal(result, &h); err != nil {
		t.Logf("warning: unmarshal error for %s: %v", txid, err)
		return 0
	}
	return len(h) / 2
}
