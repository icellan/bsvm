package covenant

import "testing"

// TestFreezeMethodName_RoutesByGovernance verifies the helper picks
// the right contract method for each supported governance shape.
// Mirrors TestUpgradeMethodName_RoutesByGovernance.
func TestFreezeMethodName_RoutesByGovernance(t *testing.T) {
	cases := []struct {
		name    string
		gov     GovernanceConfig
		want    string
		wantErr bool
	}{
		{"none rejects", GovernanceConfig{Mode: GovernanceNone}, "", true},
		{"single_key", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, "freezeSingleKey", false},
		{"multisig 2-of-3", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, "freezeMultiSig2", false},
		{"multisig 3-of-3", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 3}, "freezeMultiSig3", false},
		{"multisig threshold 1 rejects", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 1}, "", true},
		{"multisig threshold 4 rejects", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 4}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FreezeMethodName(tc.gov)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("FreezeMethodName(%v) = %q, want error", tc.gov, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FreezeMethodName(%v) error: %v", tc.gov, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnfreezeMethodName_RoutesByGovernance mirrors the freeze test.
func TestUnfreezeMethodName_RoutesByGovernance(t *testing.T) {
	cases := []struct {
		name    string
		gov     GovernanceConfig
		want    string
		wantErr bool
	}{
		{"none rejects", GovernanceConfig{Mode: GovernanceNone}, "", true},
		{"single_key", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, "unfreezeSingleKey", false},
		{"multisig 2-of-3", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, "unfreezeMultiSig2", false},
		{"multisig 3-of-3", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 3}, "unfreezeMultiSig3", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnfreezeMethodName(tc.gov)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("UnfreezeMethodName(%v) = %q, want error", tc.gov, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnfreezeMethodName(%v) error: %v", tc.gov, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildFreezeUnlockScript_HappyPath asserts the builder emits
// non-empty unlock bytes containing all supplied signatures.
func TestBuildFreezeUnlockScript_HappyPath(t *testing.T) {
	gov := GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}
	sig1 := make([]byte, 71)
	for i := range sig1 {
		sig1[i] = 0xab
	}
	sig2 := make([]byte, 71)
	for i := range sig2 {
		sig2[i] = 0xcd
	}
	got, err := BuildFreezeUnlockScript([][]byte{sig1, sig2}, gov)
	if err != nil {
		t.Fatalf("BuildFreezeUnlockScript: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("BuildFreezeUnlockScript returned 0 bytes")
	}
	if !bytesContains(got, sig1) {
		t.Error("unlock script missing sig1")
	}
	if !bytesContains(got, sig2) {
		t.Error("unlock script missing sig2")
	}
}

// TestBuildFreezeUnlockScript_RejectsWrongSigCount asserts the
// builder enforces exactly Threshold sigs per governance shape.
func TestBuildFreezeUnlockScript_RejectsWrongSigCount(t *testing.T) {
	cases := []struct {
		name      string
		gov       GovernanceConfig
		sigsGiven int
		ok        bool
	}{
		{"single_key 1 sig accepted", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, 1, true},
		{"single_key 0 sigs rejected", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, 0, false},
		{"single_key 2 sigs rejected", GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}, 2, false},
		{"multisig 2-of-3 2 sigs accepted", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, 2, true},
		{"multisig 2-of-3 1 sig rejected", GovernanceConfig{Mode: GovernanceMultiSig, Threshold: 2}, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := make([][]byte, tc.sigsGiven)
			for i := range sigs {
				sigs[i] = make([]byte, 71)
			}
			_, err := BuildFreezeUnlockScript(sigs, tc.gov)
			if tc.ok && err != nil {
				t.Errorf("expected success, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("expected error, got success")
			}
		})
	}
}

// TestBuildUnfreezeUnlockScript_HappyPath mirrors freeze.
func TestBuildUnfreezeUnlockScript_HappyPath(t *testing.T) {
	gov := GovernanceConfig{Mode: GovernanceSingleKey, Threshold: 1}
	sig := make([]byte, 71)
	for i := range sig {
		sig[i] = 0xee
	}
	got, err := BuildUnfreezeUnlockScript([][]byte{sig}, gov)
	if err != nil {
		t.Fatalf("BuildUnfreezeUnlockScript: %v", err)
	}
	if !bytesContains(got, sig) {
		t.Error("unlock script missing sig")
	}
}
