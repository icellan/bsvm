# U: Runar API Pinning + Smoke Check

Author: agent-a5a853b4cf5c1dec5 (U-runar-api-pinning)
Date: 2026-04-26
Branch: `worktree-agent-a5a853b4cf5c1dec5`

## Pinned versions

`go.mod`:

```
github.com/icellan/runar/compilers/go v0.0.0
github.com/icellan/runar/packages/runar-go v0.3.2
runar-integration v0.0.0-00010101000000-000000000000
```

With local replace directives:

```
github.com/icellan/runar/compilers/go => ../runar/compilers/go
github.com/icellan/runar/packages/runar-go => ../runar/packages/runar-go
runar-integration => ../runar/integration/go
```

The `compilers/go` and `runar-integration` modules are local-replace
ONLY (no published version). This is part of the per-CLAUDE.md rule
"Never edit sibling repos (runar, etc.); hand off via spec md at
bsv-evm root." Operators reproduce a build by checking out the
sibling `runar` repo at the matching tag.

The sibling runar repo is at HEAD `5c448cc` (`fix(conformance,sdk):
manifest-driven conformance + array_literal goldens + ANF interpreter
parity test`) at the time of this audit.

---

## Runar API surface BSVM imports

Three packages, three families of usage. Spread across **38** Go files
under `pkg/`, `cmd/`, and `test/integration/`.

### Family 1: `runar` package (`packages/runar-go`)

This is the contract-author DSL plus runtime-side off-chain helpers.
BSVM uses the following identifiers (every one cross-checked against
`/Users/siggioskarsson/gitcheckout/runar/packages/runar-go/`
implementations):

| BSVM import | Runar source | Status |
|-------------|--------------|--------|
| `runar.Assert` | `runar.go:223` | confirmed |
| `runar.AssertGroth16WitnessAssisted` | `bn254witness/...` | confirmed |
| `runar.AssertGroth16WitnessAssistedWithMSM` | `bn254witness/...` | confirmed |
| `runar.Bigint` | `runar.go:56` (= int64) | confirmed |
| `runar.BigintBig` | `runar.go:66` (= *big.Int) | confirmed |
| `runar.BigintBigEqual`, `BigintBigLess`, `BigintBigMod` | `runar.go` | confirmed |
| `runar.Bin2Num`, `Bin2NumBig` | `runar.go` | confirmed |
| `runar.Bn254FieldNeg`, `Bn254FieldNegP` | `bn254.go` | confirmed |
| `runar.Bn254G1`, `Bn254G1Add`, `Bn254G1AddP`, `Bn254G1Negate`, `Bn254G1NegateP`, `Bn254G1OnCurveP`, `Bn254G1ScalarMulBigP`, `Bn254G1ScalarMulP`, `Bn254MultiPairing4` | `bn254.go` | confirmed |
| `runar.BuildP2PKHScript` | `sdk_script_utils.go` | confirmed |
| `runar.ByteString` | `runar.go:76` | confirmed |
| `runar.CallOptions` | `sdk_types.go` | confirmed |
| `runar.Cat` | `runar.go` | confirmed |
| `runar.CheckMultiSig`, `CheckSig` | `runar.go` | confirmed |
| `runar.DeployOptions` | `sdk_types.go` | confirmed |
| `runar.EncodePushData` | `sdk_script_utils.go` | confirmed |
| `runar.EstimateDeployFee` | `sdk_*.go` | confirmed |
| `runar.ExtractLocktime` | `runar.go` | confirmed |
| `runar.ExtractStateFromScript` | `sdk_script_utils.go` | confirmed |
| `runar.FindLastOpReturn` | `sdk_script_utils.go` | confirmed |
| `runar.FromTxId` | `sdk_contract.go` | confirmed |
| `runar.Groth16PublicInput`, `Groth16Verify` | `bn254witness/*` | confirmed |
| `runar.Hash256` | `runar.go` | confirmed |
| `runar.KbFieldAdd`, `KbFieldInv`, `KbFieldMul`, `KbFieldSub` | `runar.go` | confirmed |
| `runar.Len` | `runar.go` | confirmed |
| **`runar.MatchesArtifact`** | `sdk_script_utils.go:187` | **confirmed (smoke test exercises)** |
| `runar.MerkleRootSha256` | `runar.go` | confirmed |
| `runar.NewExternalSigner`, `NewLocalSigner` | `sdk_provider.go` | confirmed |
| `runar.NewRunarContract` | `sdk_contract.go:43` | confirmed |
| `runar.Num2Bin` | `runar.go` | confirmed |
| `runar.Point` | `runar.go` | confirmed |
| `runar.Provider` | `sdk_provider.go` | confirmed |
| `runar.PubKey` | `runar.go:79` (= ByteString) | confirmed |
| `runar.ReverseBytes` | `runar.go` | confirmed |
| `runar.RunarArtifact` | `sdk_types.go:184` | confirmed |
| `runar.RunarContract` | `sdk_contract.go` | confirmed |
| `runar.SelectUtxos` | `sdk_*.go` | confirmed |
| `runar.Sha256` | `runar.go` | confirmed |
| `runar.Sig`, `Signer` | `runar.go` | confirmed |
| `runar.SmartContract`, `StatefulSmartContract` | `runar.go:153` | confirmed |
| `runar.Substr` | `runar.go` | confirmed |
| `runar.TransactionData` | `sdk_types.go` | confirmed |
| `runar.TxOutput` | `sdk_types.go` | confirmed |
| `runar.UTXO` | `sdk_types.go` | confirmed |
| **`runar.VerifySP1FRI`** | `runar.go:325` | **confirmed (smoke test exercises) — see "Mode 1 codegen status" below** |

### Family 2: `compilers/go/compiler` (gocompiler)

| BSVM import | Runar source | Status |
|-------------|--------------|--------|
| `gocompiler.Artifact` | `compiler/types.go` | confirmed |
| **`gocompiler.CompileFromSource`** | `compiler/compiler.go:361` | **confirmed (smoke test exercises symbol)** |
| `gocompiler.CompileFromIRBytes` | `compiler/compiler.go:146` | confirmed |
| `gocompiler.CompileOptions` | `compiler/options.go` | confirmed |

### Family 3: `bn254witness` (Groth16 helpers)

| BSVM import | Status |
|-------------|--------|
| `bn254witness.GenerateWitness` | confirmed |
| `bn254witness.LoadSP1PublicInputs` | confirmed |
| `bn254witness.LoadSP1VKFromFile` | confirmed |
| `bn254witness.ParseSP1RawProof` | confirmed |
| `bn254witness.Proof` | confirmed |
| `bn254witness.VerifyingKey` | confirmed |
| `bn254witness.Witness` | confirmed |

---

## Mode 1 codegen status (`runar.VerifySP1FRI`)

This is the API the project leans on most — Mode 1 of the rollup
covenant calls `runar.VerifySP1FRI` four times (in `AdvanceState`,
plus the freeze/unfreeze/upgrade governance branches). See
`pkg/covenant/contracts/rollup_fri.runar.go:121, 307, 366, 421`.

**Off-chain Go runtime** (`runar/packages/runar-go/runar.go:325-330`):

```go
func VerifySP1FRI(proofBlob ByteString, publicValues ByteString, sp1VKeyHash ByteString) bool {
    _ = proofBlob
    _ = publicValues
    _ = sp1VKeyHash
    return true
}
```

The Go-side function is a stub that always returns true. This is the
same pattern Rúnar uses for `VerifyRabinSig`, `VerifyWOTS`,
`VerifySLHDSA_SHA2_*` — all "real on-chain, mock off-chain" pairs
documented in `runar/packages/runar-go/README.md` §11.1.

**On-chain codegen body** (the part that actually matters for
Mode 1):

`runar/compilers/go/codegen/sp1_fri.go:135` —
`func (ctx *loweringContext) lowerVerifySP1FRI(...)` is the dispatch
entry point. Its docstring (lines 116-122) reads:

> Status: the full Steps 1-11 verifier algorithm is implemented and
> validated end-to-end in compilers/go/codegen/sp1_fri_test.go
> (TestSp1FriVerifier_AcceptsMinimalGuestFixture exercises every emit
> helper against the canonical Plonky3 KoalaBear FRI fixture; on-chain
> alpha/zeta/alpha_fri/all-betas/query-indexes/per-query reduced-opening/
> OOD-equality match the off-chain Go reference at
> packages/runar-go/sp1fri/ byte-for-byte; the script VM accepts).

**This is current.** When BSVM compiles
`pkg/covenant/contracts/rollup_fri.runar.go` via
`gocompiler.CompileFromSource`, the resulting locking script DOES
contain the full SP1 v6.0.2 STARK / FRI verifier body. We confirmed
via `go test -run TestCompileFRIRollup_WithVerifyingKey -count=1
./pkg/covenant/` (PASS, 1.20s).

**Caveat for spec auditors**: the doc
`runar/docs/sp1-fri-verifier.md` is a STALE document. Its §8
"Implementation status" section still reads "stack-lowering is
deferred ... attempt to compile a contract calling
runar.VerifySP1FRI fails cleanly". This is no longer true (codegen
landed in `EmitFullSP1FriVerifierBody`). Audit-trail readers
encountering that doc should cross-reference
`runar/compilers/go/codegen/sp1_fri.go` source. **NOT a BSVM
problem to fix** (per CLAUDE.md "no cross-repo edits"); flagging for
operator awareness so they can ask the runar maintainers to refresh
the doc.

---

## Smoke test

`pkg/covenant/runar_api_smoke_test.go` (NEW in this commit). Three
subtests, runtime ~0.00s:

1. `MatchesArtifact_signature`: calls
   `runar.MatchesArtifact(&RunarArtifact{}, "deadbeef")` — exercises
   the actual implementation with a non-nil empty artifact and a
   clearly-not-matching hex script. Asserts `false` is returned.
2. `VerifySP1FRI_signature`: calls
   `runar.VerifySP1FRI(zero, zero, zero)` — exercises the off-chain
   Go runtime stub. Asserts `true` is returned (the documented stub
   contract).
3. `CompileFromSource_symbol_present`: takes the function pointer
   `gocompiler.CompileFromSource` to confirm the symbol exists at
   the import path. Doesn't actually compile anything (that's
   covered by the existing `TestCompileFRIRollup*` tests in
   `compile_test.go`).

The test is intentionally minimal. Its sole purpose is to break loudly
at PR time if a runar bump renames or removes any of the three APIs.
A signature-shape change fails compilation; a behaviour change fails
the assertion. Either way: a broken bump cannot land silently.

This test runs in `go test -short` mode (no `testing.Short()` skip)
because it has no compile cost. Total runtime measured at ~0.00s
on the smoke run.

Test exit:

```
=== RUN   Test_RunarAPISmoke
=== RUN   Test_RunarAPISmoke/MatchesArtifact_signature
=== RUN   Test_RunarAPISmoke/VerifySP1FRI_signature
=== RUN   Test_RunarAPISmoke/CompileFromSource_symbol_present
--- PASS: Test_RunarAPISmoke (0.00s)
PASS
```

---

## What's NOT covered

The smoke test is **import surface only**. It does NOT verify:

- `runar.VerifySP1FRI` codegen body correctness — covered by Rúnar's
  own `TestSp1FriVerifier_AcceptsMinimalGuestFixture` and end-to-end
  by BSVM's Mode 1 regtest (out-of-scope for this fast smoke).
- `gocompiler.CompileFromSource` end-to-end correctness — covered by
  `TestCompileFRIRollup_WithVerifyingKey` and friends, which actually
  compile real `.runar.go` contracts. Those are slower (~1.2s each)
  and gated on the gocompiler being available.
- BN254 / Groth16 cryptographic correctness — covered by the
  `groth16_*_test.go` family in `pkg/covenant/`.
- ARC / chaintracks / BEEF surfaces — those are independent of runar
  and not part of this audit.

---

## Recommendations

1. **Keep the smoke test runnable in `-short` mode.** The whole point
   of this guard is fast-fail on a runar bump.
2. **When bumping the runar replace target** (e.g., picking up a new
   sibling-repo HEAD), run `go test -short -run Test_RunarAPISmoke
   ./pkg/covenant/` BEFORE running the rest of the suite. If the
   smoke test fails to compile or assert, the bump is rejected; no
   further investigation needed.
3. **Cross-reference this doc when adding new runar imports.**
   Append the new identifier to the table in Family 1 (or 2 / 3 if
   it's a different package) and add a corresponding subtest to
   `Test_RunarAPISmoke`.
4. **Don't edit Rúnar.** If a Rúnar API is missing or broken, file an
   issue against the runar repo and wait for the fix to land; do not
   edit `../runar/` from within the bsvm tree (CLAUDE.md rule).

---

## Action taken in this commit

- New file: `pkg/covenant/runar_api_smoke_test.go` (3 subtests,
  ~85 LOC).
- New file: `docs/decisions/U-runar-api-pinning.md` (this document).
- No changes to existing code paths.
- Smoke test runs and passes against the current runar HEAD
  (`5c448cc`).
