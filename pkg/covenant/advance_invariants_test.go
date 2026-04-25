package covenant

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
)

// advance_invariants_test.go — step-4 compiled-script invariants.
//
// These tests walk the compiled Rúnar ANF IR (CompiledCovenant.ANF) and
// pin structural properties of every rollup variant's advanceState path
// and governance paths. They back the plan's step-4 requirement:
//
//   - exactly one internal OP_PUSH_TX preimage-validation signature check,
//   - correct hashOutputs extraction from the sighash preimage,
//   - correct output binding including the data output,
//   - correct public-value extraction at spec offsets,
//   - no user/governance authorization signature check in advanceState,
//   - symmetric: governance paths DO carry a checkSig / checkMultiSig.
//
// Rúnar auto-injects a continuation-hash check in every stateful method
// via paired `computeStateOutput` + `extractOutputHash` calls — these
// are the ANF-level fingerprint of the OP_PUSH_TX preimage-validation
// chain. Asserting their counts pins the hashOutputs / output-binding
// invariants without needing a full BSV script disassembler.

// anfMethodFeatures aggregates the structural observations we make about
// a single compiled method body.
type anfMethodFeatures struct {
	Name             string
	CheckSigCount    int
	CheckMultiSig    int
	ExtractOutHash   int
	ComputeStateOut  int
	AddDataOutput    int
	SubstrCount      int
	SubstrSlots      []substrSlot // (start, length) tuples, where resolvable
	Hash256Count     int
	BuildChangeCount int
}

// substrSlot records a (start, length) pair extracted from a substr call,
// where both arguments resolve to load_const integer bindings. Unknown /
// non-constant arguments are recorded as -1.
type substrSlot struct {
	Start  int64
	Length int64
}

// extractAnfFeatures parses CompiledCovenant.ANF (JSON-marshaled
// ir.ANFProgram) and returns one feature bundle per method, keyed by the
// method's lowercase name.
func extractAnfFeatures(t *testing.T, anf []byte) map[string]*anfMethodFeatures {
	t.Helper()

	var doc struct {
		Methods []struct {
			Name string                   `json:"name"`
			Body []map[string]interface{} `json:"body"`
		} `json:"methods"`
	}
	if err := json.Unmarshal(anf, &doc); err != nil {
		t.Fatalf("unmarshal ANF: %v", err)
	}

	out := make(map[string]*anfMethodFeatures, len(doc.Methods))
	for _, m := range doc.Methods {
		// Build a name -> value map for every binding in the method so we
		// can resolve load_const references when a substr arg points at
		// another binding.
		consts := make(map[string]int64, len(m.Body))
		collectConsts(m.Body, consts)

		f := &anfMethodFeatures{Name: m.Name}
		walkBody(m.Body, f, consts)
		out[m.Name] = f
	}
	return out
}

// collectConsts populates `out` with every load_const binding whose raw
// JSON value is a non-negative integer small enough to fit in int64.
// Other binding kinds (bin_op, call, ...) are ignored.
func collectConsts(body []map[string]interface{}, out map[string]int64) {
	for _, b := range body {
		name, _ := b["name"].(string)
		v, _ := b["value"].(map[string]interface{})
		if v == nil {
			continue
		}
		// Recurse into conditional / loop nested bodies.
		for _, sub := range []string{"then", "else", "body"} {
			if nested, ok := v[sub].([]interface{}); ok {
				recur := make([]map[string]interface{}, 0, len(nested))
				for _, n := range nested {
					if nm, ok := n.(map[string]interface{}); ok {
						recur = append(recur, nm)
					}
				}
				collectConsts(recur, out)
			}
		}
		if kind, _ := v["kind"].(string); kind == "load_const" && name != "" {
			if raw, ok := v["value"]; ok {
				switch n := raw.(type) {
				case float64:
					out[name] = int64(n)
				}
			}
		}
	}
}

// walkBody recursively accumulates feature counts into f.
func walkBody(body []map[string]interface{}, f *anfMethodFeatures, consts map[string]int64) {
	for _, b := range body {
		v, _ := b["value"].(map[string]interface{})
		if v == nil {
			continue
		}
		kind, _ := v["kind"].(string)
		switch kind {
		case "add_data_output":
			f.AddDataOutput++
		case "call":
			fn, _ := v["func"].(string)
			switch fn {
			case "checkSig":
				f.CheckSigCount++
			case "checkMultiSig":
				f.CheckMultiSig++
			case "extractOutputHash":
				f.ExtractOutHash++
			case "computeStateOutput":
				f.ComputeStateOut++
			case "hash256":
				f.Hash256Count++
			case "buildChangeOutput":
				f.BuildChangeCount++
			case "substr":
				f.SubstrCount++
				args, _ := v["args"].([]interface{})
				slot := substrSlot{Start: -1, Length: -1}
				if len(args) >= 3 {
					if s, ok := args[1].(string); ok {
						if c, ok := consts[s]; ok {
							slot.Start = c
						}
					}
					if l, ok := args[2].(string); ok {
						if c, ok := consts[l]; ok {
							slot.Length = c
						}
					}
				}
				f.SubstrSlots = append(f.SubstrSlots, slot)
			}
		}
		for _, sub := range []string{"then", "else", "body"} {
			if nested, ok := v[sub].([]interface{}); ok {
				recur := make([]map[string]interface{}, 0, len(nested))
				for _, n := range nested {
					if nm, ok := n.(map[string]interface{}); ok {
						recur = append(recur, nm)
					}
				}
				walkBody(recur, f, consts)
			}
		}
	}
}

// rollupFixture is a compiled covenant plus the compiled ANF, produced
// once per rollup mode for the step-4 structural tests.
type rollupFixture struct {
	Name string
	ANF  map[string]*anfMethodFeatures
}

// buildRollupFixtures compiles all three rollup variants under a common
// governance config and returns their extracted ANF features. The shared
// governance config is 2-of-3 multisig so every multisig method variant
// is actually reachable; single-key variants are exercised separately
// below.
func buildRollupFixtures(t *testing.T) []rollupFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping compile-heavy step-4 invariant tests in short mode")
	}

	govMulti := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 2,
	}

	vk := []byte("step4-invariant-vk")
	chainID := uint64(8453111)

	fri, err := CompileFRIRollup(vk, chainID, govMulti)
	if err != nil {
		t.Fatalf("compile fri: %v", err)
	}
	groth16, err := CompileGroth16Rollup(vk, chainID, govMulti, deterministicGroth16VK())
	if err != nil {
		t.Fatalf("compile groth16: %v", err)
	}
	groth16WA, err := CompileGroth16WARollup(vk, chainID, govMulti, bsvmTestSP1VKPath(t))
	if err != nil {
		t.Fatalf("compile groth16WA: %v", err)
	}

	return []rollupFixture{
		{Name: "fri", ANF: extractAnfFeatures(t, fri.ANF)},
		{Name: "groth16", ANF: extractAnfFeatures(t, groth16.ANF)},
		{Name: "groth16WA", ANF: extractAnfFeatures(t, groth16WA.ANF)},
	}
}

// ---------------------------------------------------------------------------
// Step 4.1 — advanceState has NO user/governance auth signature check.
// ---------------------------------------------------------------------------

// TestAdvance_NoAuthSignatureCheck pins that advanceState's compiled ANF
// contains zero checkSig and zero checkMultiSig calls for every rollup
// mode. The SP1 STARK proof is the sole advance authorization; any
// future patch that adds a governance signature to the advance path
// fails this test.
func TestAdvance_NoAuthSignatureCheck(t *testing.T) {
	for _, fx := range buildRollupFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			adv := fx.ANF["advanceState"]
			if adv == nil {
				t.Fatal("advanceState method missing from compiled ANF")
			}
			if adv.CheckSigCount != 0 {
				t.Errorf("advanceState must contain 0 checkSig calls, got %d", adv.CheckSigCount)
			}
			if adv.CheckMultiSig != 0 {
				t.Errorf("advanceState must contain 0 checkMultiSig calls, got %d", adv.CheckMultiSig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Step 4.2 — advanceState carries exactly one continuation-hash /
// hashOutputs binding (Rúnar's OP_PUSH_TX preimage-validation pair).
// ---------------------------------------------------------------------------

// TestAdvance_SingleOpPushTxBinding pins that advanceState's compiled ANF
// contains exactly one Rúnar-injected continuation-hash binding, which is
// the ANF fingerprint of the OP_PUSH_TX preimage-validation check: one
// computeStateOutput (builds the expected hashOutputs image) paired with
// one extractOutputHash (reads hashOutputs out of the sighash preimage).
// More than one would mean a duplicated preimage check; zero would mean
// no output binding at all and the covenant would accept arbitrary tx
// shapes.
func TestAdvance_SingleOpPushTxBinding(t *testing.T) {
	for _, fx := range buildRollupFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			adv := fx.ANF["advanceState"]
			if adv == nil {
				t.Fatal("advanceState method missing from compiled ANF")
			}
			if adv.ComputeStateOut != 1 {
				t.Errorf("advanceState must contain exactly 1 computeStateOutput call, got %d", adv.ComputeStateOut)
			}
			if adv.ExtractOutHash != 1 {
				t.Errorf("advanceState must contain exactly 1 extractOutputHash call, got %d", adv.ExtractOutHash)
			}
			if adv.BuildChangeCount != 1 {
				t.Errorf("advanceState must contain exactly 1 buildChangeOutput call, got %d", adv.BuildChangeCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Step 4.3 — advanceState emits exactly one spec-12 OP_RETURN data output.
// ---------------------------------------------------------------------------

// TestAdvance_SingleDataOutput pins the F07 data-availability invariant:
// Mode 2 / Mode 3 rollup advanceState methods emit exactly one
// add_data_output binding, which is the BSVM\x02 || batchData OP_RETURN.
// The continuation-hash check (TestAdvance_SingleOpPushTxBinding)
// cryptographically requires the on-chain tx to carry this output
// verbatim. Zero add_data_outputs would mean batchData is not on-chain;
// more than one would mean an extra data output is bound into the tx
// shape without a reason.
//
// All three modes now emit exactly one data output for the spec-12
// OP_RETURN(BSVM\x02) batch envelope. The runar-go SDK's
// BuildCallTransaction resolves AddDataOutput ANF bindings at call
// time (R9 / RUNAR-SDK-DATA-OUTPUTS.md), so the on-chain tx carries
// the data output verbatim and hashOutputs matches the compiled
// continuation-hash constant.
func TestAdvance_SingleDataOutput(t *testing.T) {
	for _, fx := range buildRollupFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			adv := fx.ANF["advanceState"]
			if adv == nil {
				t.Fatal("advanceState method missing from compiled ANF")
			}
			if adv.AddDataOutput != 1 {
				t.Errorf("advanceState must contain exactly 1 add_data_output binding, got %d",
					adv.AddDataOutput)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Step 4.4 — advanceState extracts public values at the spec-12 offsets.
// ---------------------------------------------------------------------------

// TestAdvance_PublicValueOffsets pins that advanceState's substr calls
// cover exactly the spec-12 slots:
//   - [0..32)    preStateRoot
//   - [32..64)   postStateRoot
//   - [104..136) batchDataHash
//   - [136..144) chainId (little-endian 8 bytes)
//   - [272..280) blockNumber (little-endian 8 bytes)
//
// The offsets are encoded as load_const bindings resolved from the ANF
// name graph. A regression that reshuffles the slots (e.g. reads batch
// hash from offset 64) or drops any of them fails this test.
func TestAdvance_PublicValueOffsets(t *testing.T) {
	want := []substrSlot{
		{Start: 0, Length: 32},
		{Start: 32, Length: 32},
		{Start: 104, Length: 32},
		{Start: 136, Length: 8},
		{Start: 272, Length: 8},
	}
	for _, fx := range buildRollupFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			adv := fx.ANF["advanceState"]
			if adv == nil {
				t.Fatal("advanceState method missing from compiled ANF")
			}
			if adv.SubstrCount != len(want) {
				t.Fatalf("advanceState must contain exactly %d substr calls, got %d",
					len(want), adv.SubstrCount)
			}
			if err := assertSubstrSlotsMatch(adv.SubstrSlots, want); err != nil {
				t.Errorf("public-value offsets: %v", err)
			}
		})
	}
}

// assertSubstrSlotsMatch returns nil iff `got` contains exactly the
// (start, length) tuples in `want`, ignoring order. -1 in a got-slot
// means one of the substr args could not be resolved to a load_const
// integer — treated as a mismatch.
func assertSubstrSlotsMatch(got, want []substrSlot) error {
	if len(got) != len(want) {
		return fmt.Errorf("slot count: got %d, want %d", len(got), len(want))
	}
	sortSlots := func(s []substrSlot) []substrSlot {
		c := append([]substrSlot(nil), s...)
		sort.Slice(c, func(i, j int) bool {
			if c[i].Start != c[j].Start {
				return c[i].Start < c[j].Start
			}
			return c[i].Length < c[j].Length
		})
		return c
	}
	gs := sortSlots(got)
	ws := sortSlots(want)
	for i := range ws {
		if gs[i] != ws[i] {
			return fmt.Errorf("slot %d: got {start:%d,len:%d}, want {start:%d,len:%d}",
				i, gs[i].Start, gs[i].Length, ws[i].Start, ws[i].Length)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Step 4.5 — governance paths DO have a signature check AND do NOT emit a
// data output. Symmetric guardrails for step 4.1 / 4.3: the advance path
// is sig-free with exactly one OP_RETURN; governance paths are sig-gated
// with zero OP_RETURNs.
// ---------------------------------------------------------------------------

// TestGovernance_PathsCarrySignatureCheck pins that every governance
// method (freeze / unfreeze / upgrade × single-key / 2-of-3 / 3-of-3)
// contains exactly one checkSig or checkMultiSig call. Zero would mean
// governance was unsignable — shard would be permanently active or
// permanently frozen. More than one would mean duplicated auth paths
// and is likely a codegen bug.
func TestGovernance_PathsCarrySignatureCheck(t *testing.T) {
	// (name suffix, expected single-key or multisig gate)
	singleKeyMethods := []string{"freezeSingleKey", "unfreezeSingleKey", "upgradeSingleKey"}
	multiSigMethods := []string{
		"freezeMultiSig2", "freezeMultiSig3",
		"unfreezeMultiSig2", "unfreezeMultiSig3",
		"upgradeMultiSig2", "upgradeMultiSig3",
	}
	for _, fx := range buildRollupFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			for _, name := range singleKeyMethods {
				m := fx.ANF[name]
				if m == nil {
					t.Errorf("%s missing from compiled ANF", name)
					continue
				}
				if m.CheckSigCount != 1 {
					t.Errorf("%s must contain exactly 1 checkSig, got %d", name, m.CheckSigCount)
				}
				if m.CheckMultiSig != 0 {
					t.Errorf("%s must NOT contain checkMultiSig, got %d", name, m.CheckMultiSig)
				}
				if m.AddDataOutput != 0 {
					t.Errorf("%s must NOT emit a data output, got %d", name, m.AddDataOutput)
				}
			}
			for _, name := range multiSigMethods {
				m := fx.ANF[name]
				if m == nil {
					t.Errorf("%s missing from compiled ANF", name)
					continue
				}
				if m.CheckMultiSig != 1 {
					t.Errorf("%s must contain exactly 1 checkMultiSig, got %d", name, m.CheckMultiSig)
				}
				if m.CheckSigCount != 0 {
					t.Errorf("%s must NOT contain checkSig, got %d", name, m.CheckSigCount)
				}
				if m.AddDataOutput != 0 {
					t.Errorf("%s must NOT emit a data output, got %d", name, m.AddDataOutput)
				}
			}
		})
	}
}
