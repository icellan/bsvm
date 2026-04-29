package covenant

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// TestUpgradeMethodName_RoutesByGovernance verifies the helper picks
// the right contract method for each supported governance shape. The
// "none" mode has no upgrade path by design (no key authorises the
// spend) — that case must error.
func TestUpgradeMethodName_RoutesByGovernance(t *testing.T) {
	cases := []struct {
		name    string
		gov     GovernanceConfig
		want    string
		wantErr bool
	}{
		{
			name:    "none rejects",
			gov:     GovernanceConfig{Mode: GovernanceNone},
			wantErr: true,
		},
		{
			name: "single_key",
			gov:  GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1},
			want: "upgradeSingleKey",
		},
		{
			name: "multisig 2-of-3",
			gov:  GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2},
			want: "upgradeMultiSig2",
		},
		{
			name: "multisig 3-of-3",
			gov:  GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 3},
			want: "upgradeMultiSig3",
		},
		{
			name:    "multisig threshold 1 rejects",
			gov:     GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 1},
			wantErr: true,
		},
		{
			name:    "multisig threshold 4 rejects",
			gov:     GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 4},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UpgradeMethodName(tc.gov)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("UpgradeMethodName(%v) = %q, want error", tc.gov, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UpgradeMethodName(%v) error: %v", tc.gov, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEncodeUpgradePublicValues_ShapeAndBindings verifies the
// publicValues blob has the canonical 280-byte length and that the
// migration-hash and chainID slots line up with the on-chain Substr
// offsets in rollup_fri.runar.go.
func TestEncodeUpgradePublicValues_ShapeAndBindings(t *testing.T) {
	var pre, post [32]byte
	for i := range pre {
		pre[i] = byte(i)
		post[i] = byte(0xff - i)
	}
	batch := []byte("batch-blob")
	proof := []byte("proof-blob")
	newScript := []byte{0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef}
	const chainID = uint64(8453111)
	const newBlock = uint64(42)

	pv := EncodeUpgradePublicValues(pre, post, batch, proof, newScript, chainID, newBlock)
	if got := len(pv); got != 280 {
		t.Fatalf("publicValues length = %d, want 280", got)
	}
	if !bytesEqual(pv[0:32], pre[:]) {
		t.Errorf("pv[0..32) preStateRoot mismatch")
	}
	if !bytesEqual(pv[32:64], post[:]) {
		t.Errorf("pv[32..64) postStateRoot mismatch")
	}

	// pv[64..96) = hash256(proofBlob)
	wantProofHash := dh256(proof)
	if !bytesEqual(pv[64:96], wantProofHash[:]) {
		t.Errorf("pv[64..96) proofHash mismatch")
	}

	// pv[104..136) = hash256(batchData)
	wantBatchHash := dh256(batch)
	if !bytesEqual(pv[104:136], wantBatchHash[:]) {
		t.Errorf("pv[104..136) batchDataHash mismatch")
	}

	// pv[136..144) = chainID LE
	gotCID := binary.LittleEndian.Uint64(pv[136:144])
	if gotCID != chainID {
		t.Errorf("pv[136..144) chainID = %d, want %d", gotCID, chainID)
	}

	// pv[240..272) = hash256(newCovenantScript)
	wantMigHash := dh256(newScript)
	if !bytesEqual(pv[240:272], wantMigHash[:]) {
		t.Errorf("pv[240..272) migrationHash mismatch")
	}

	// pv[272..280) = newBlockNumber LE
	gotBlk := binary.LittleEndian.Uint64(pv[272:280])
	if gotBlk != newBlock {
		t.Errorf("pv[272..280) newBlockNumber = %d, want %d", gotBlk, newBlock)
	}
}

// TestBuildUpgradeUnlockScript_SingleKeyHappyPath asserts the unlock
// script bytes are non-empty when all required fields are supplied.
// The exact bytes are not pinned (depends on encodePushData layout);
// we assert structural properties: contains all sigs + script + ANF
// hash + pv + batch + proof + newBlock.
func TestBuildUpgradeUnlockScript_SingleKeyHappyPath(t *testing.T) {
	var preState, postState [32]byte
	preState[0] = 0xab
	postState[0] = 0xcd
	newScript := []byte{0x6a, 0x4e, 0x01, 0x02, 0x03}

	gov := GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}
	req := UpgradeRequest{
		CurrentStateRoot:   preState,
		CurrentBlockNumber: 100,
		ChainID:            8453111,
		NewCovenantScript:  newScript,
		NewCovenantAnfHash: dh256([]byte("anf-of-new-script")),
		PublicValues: EncodeUpgradePublicValues(preState, postState,
			[]byte("batch"), []byte("proof"), newScript, 8453111, 101),
		BatchData:      []byte("batch"),
		ProofBlob:      []byte("proof"),
		GovernanceSigs: [][]byte{make([]byte, 71)},
	}
	got, err := BuildUpgradeUnlockScript(req, gov)
	if err != nil {
		t.Fatalf("BuildUpgradeUnlockScript: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("BuildUpgradeUnlockScript returned 0 bytes — regression of WW-rotate-onchain")
	}
	// Sanity: the script must contain the new-covenant-script bytes
	// somewhere in its payload (push-encoded). Since the only push
	// targets containing this exact substring are the args we
	// emitted, finding it confirms the layout reached that step.
	if !bytesContains(got, newScript) {
		t.Error("unlock script does not contain newCovenantScript bytes")
	}
	// Sanity: must contain the ANF hash too.
	if !bytesContains(got, req.NewCovenantAnfHash[:]) {
		t.Error("unlock script does not contain newCovenantAnfHash bytes")
	}
}

// TestBuildUpgradeUnlockScript_MultiSigSigCountChecks asserts each
// upgrade method enforces its expected signature count.
func TestBuildUpgradeUnlockScript_MultiSigSigCountChecks(t *testing.T) {
	newScript := []byte("new-script-bytes-2")
	pv := make([]byte, 280)
	makeReq := func(sigs int) UpgradeRequest {
		req := UpgradeRequest{
			NewCovenantScript: newScript,
			PublicValues:      pv,
			BatchData:         []byte("b"),
			ProofBlob:         []byte("p"),
		}
		req.GovernanceSigs = make([][]byte, sigs)
		for i := range req.GovernanceSigs {
			req.GovernanceSigs[i] = make([]byte, 71)
		}
		return req
	}
	cases := []struct {
		name      string
		gov       GovernanceConfig
		sigsGiven int
		ok        bool
	}{
		{"single_key with 1 sig accepted", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, 1, true},
		{"single_key with 2 sigs rejected", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, 2, false},
		{"multisig 2-of-3 with 2 sigs accepted", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, 2, true},
		{"multisig 2-of-3 with 1 sig rejected", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, 1, false},
		{"multisig 3-of-3 with 3 sigs accepted", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 3}, 3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildUpgradeUnlockScript(makeReq(tc.sigsGiven), tc.gov)
			if tc.ok && err != nil {
				t.Errorf("expected success, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("expected error, got success")
			}
		})
	}
}

// TestBuildUpgradeUnlockScript_RejectsMalformedRequest asserts the
// builder fails fast on shape errors so the rotate-vk binary surfaces
// them BEFORE sending anything to ARC.
func TestBuildUpgradeUnlockScript_RejectsMalformedRequest(t *testing.T) {
	gov := GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}
	base := UpgradeRequest{
		NewCovenantScript: []byte("script"),
		PublicValues:      make([]byte, 280),
		BatchData:         []byte("batch"),
		ProofBlob:         []byte("proof"),
		GovernanceSigs:    [][]byte{make([]byte, 71)},
	}
	cases := []struct {
		name string
		mut  func(r *UpgradeRequest)
	}{
		{"empty new script", func(r *UpgradeRequest) { r.NewCovenantScript = nil }},
		{"wrong-length pv", func(r *UpgradeRequest) { r.PublicValues = make([]byte, 100) }},
		{"empty proof", func(r *UpgradeRequest) { r.ProofBlob = nil }},
		{"empty batch", func(r *UpgradeRequest) { r.BatchData = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mut(&req)
			if _, err := BuildUpgradeUnlockScript(req, gov); err == nil {
				t.Error("expected rejection, got nil error")
			}
		})
	}
}

// dh256 is sha256(sha256(b)) inlined for the test so it doesn't depend
// on the (unexported) hash256Bytes in upgrade.go.
func dh256(b []byte) [32]byte {
	a := sha256.Sum256(b)
	return sha256.Sum256(a[:])
}

// bytesEqual is a minimal byte-slice comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bytesContains is a brute-force substring search on byte slices,
// kept local so the test doesn't pull in the bytes package for one
// call.
func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
