# Rúnar handoff — SDK `BuildCallTransaction` must emit `addDataOutput` payloads as real tx outputs (R7 follow-up)

Status: open request from the BSVM team. Follow-up to the R7 closeout in
`RUNAR-ISSUES.md` (DSL / compiler side delivered; tx-builder side missing).

BSVM repo: https://github.com/icellan/bsvm
Rúnar repo path (local convention): `~/gitcheckout/runar/`

## 1. Problem

A stateful Rúnar method that calls `c.AddDataOutput(satoshis, scriptBytes)`
compiles correctly: the generated locking script's auto-injected
continuation-hash check expects the spending tx to carry a data output with
the declared script bytes, per the grammar at
`runar/spec/grammar.md:728` —

> `hashOutputs(txPreimage) == hash256([state outputs] || [data outputs] || changeOutput)`

But `RunarContract.Call` → `PrepareCall` → `BuildCallTransaction` currently
emits only `[state outputs] || changeOutput`. The tx is broadcast, the
script evaluator recomputes `hashOutputs`, finds no data outputs, the
concatenation no longer matches the compile-time continuation-hash
constant, and the script fails with:

```
Script evaluated without error but finished with a false/empty top stack element
```

Every Rúnar contract that uses `AddDataOutput` is therefore unspendable in
practice. BSVM's Mode 1 / Mode 2 / Mode 3 rollup covenants all want an
OP_RETURN batch-data output on every `advanceState` call, and today Mode 1
has the call removed (test `rollup_fri_f07_test.go:37` asserts zero data
outputs) while Mode 2 emits via `AddDataOutput(...)` into the continuation
hash but the tx lacks the actual output. Mode 3 has the call commented out
for the same reason.

Concrete evidence in BSVM:

- `pkg/covenant/contracts/rollup_fri.runar.go:91-105` — explanatory comment
  describing this limitation.
- `pkg/covenant/contracts/rollup_fri_f07_test.go:7-41` — test fixture
  asserting zero data outputs, with header referencing the SDK gap.
- `pkg/covenant/contracts/rollup_groth16_wa.runar.go:185-190` —
  `AddDataOutput` call site commented out.

## 2. Root cause inside runar-go

```
packages/runar-go/sdk_calling.go:12-17   BuildCallOptions struct
packages/runar-go/sdk_calling.go:46-181  BuildCallTransaction
packages/runar-go/sdk_contract.go:580-606 PrepareCall builds BuildCallOptions
packages/runar-go/runar.go:146-213        StatefulSmartContract + AddDataOutput + DataOutputs()
packages/runar-go/anf_interpreter.go:327  "on-chain-only" skip list incl. add_data_output
```

Three specific gaps:

1. `BuildCallOptions` (sdk_calling.go:12-17) has no field for data outputs.
2. `BuildCallTransaction` (sdk_calling.go:46-181) iterates contract
   outputs, then emits change — no data-output loop, no fee accounting for
   data outputs, no size-estimate contribution.
3. `PrepareCall` (sdk_contract.go:580-606) never populates a data-output
   slice on `BuildCallOptions`, so even if the field existed it would stay
   empty. The ANF interpreter at `anf_interpreter.go:327` explicitly skips
   `add_data_output` as "on-chain-only," so there is no execution-time path
   that resolves the method-parameter arguments (e.g. `batchData`) to
   concrete data-output bytes.

## 3. Required change

### 3.1 API — extend `BuildCallOptions`

```go
// packages/runar-go/sdk_calling.go
type BuildCallOptions struct {
    // existing fields …
    ContractOutputs          []ContractOutput
    AdditionalContractInputs []AdditionalContractInput

    // NEW: data outputs in declaration order, to be inserted between
    // the last contract (state) output and the change output. Satoshis
    // MUST match the satoshi value declared in the source-level
    // addDataOutput() call so the continuation hash matches. Script
    // bytes MUST be the exact locking script declared at the source
    // level after substituting the method's resolved parameter values.
    DataOutputs              []ContractOutput
}
```

`ContractOutput` (sdk_calling.go:20-24) is already the right shape —
`Script` + `Satoshis`. Reuse it; no new type is needed.

### 3.2 `BuildCallTransaction` — emit data outputs + fee accounting

Append an emission loop **after** the contract-outputs loop at
`sdk_calling.go:155-161` and **before** the change output at
`sdk_calling.go:163-174`:

```go
// After: for _, co := range contractOutputs { tx.AddOutput(...) }
for _, do := range dataOutputs {
    ls, _ := sdkscript.NewFromHex(do.Script)
    tx.AddOutput(&transaction.TransactionOutput{
        Satoshis:      uint64(do.Satoshis),
        LockingScript: ls,
    })
}
// Then emit change as today
```

Extend fee estimation (`sdk_calling.go:102-114`) to include data-output
bytes in `outputsSize`:

```go
for _, do := range dataOutputs {
    outputsSize += 8 + varIntByteSize(len(do.Script)/2) + len(do.Script)/2
}
```

Add data-output satoshis to the `contractOutputSats` tally
(`sdk_calling.go:85-88`) so change is computed correctly when a data
output carries satoshis > 0 (typically 0 for OP_RETURN but the API must
support non-zero).

### 3.3 `PrepareCall` — resolve & forward data outputs

`PrepareCall` (sdk_contract.go:580-606) builds `BuildCallOptions`. It must
now also populate `DataOutputs` by executing the method's `add_data_output`
intrinsics with the caller's resolved argument values in source order.

Preferred design: teach the ANF interpreter to execute `add_data_output`
rather than skip it. Two minimal steps:

1. Remove `"add_data_output"` from the skip list at
   `anf_interpreter.go:327`.
2. Add a case that evaluates the two arguments (a bigint satoshi value and
   a ByteString script value — both are plain `anfEvalCall` values after
   arg resolution) and appends to the contract instance's
   `dataOutputs` via a public accessor or a method-local pointer into
   the contract state. The existing Go-native invocation path already
   populates `dataOutputs` because `AddDataOutput` is called directly in
   method bodies during Go test execution; the ANF interpretation path
   just needs to do the same.

After method interpretation completes during `PrepareCall`, read the
recorded data outputs off the contract instance (public accessor already
exists: `StatefulSmartContract.DataOutputs()` at `runar.go:205`) and
convert to `ContractOutput` entries:

```go
// packages/runar-go/sdk_contract.go — inside PrepareCall, around line 582
if statefulCtr, ok := c.instance.(interface{ DataOutputs() []OutputSnapshot }); ok {
    for _, snap := range statefulCtr.DataOutputs() {
        // snap.Values[0] is the ByteString script per AddDataOutput impl
        scriptBytes := snap.Values[0].(ByteString)
        buildOpts.DataOutputs = append(buildOpts.DataOutputs, ContractOutput{
            Script:   hex.EncodeToString(scriptBytes),
            Satoshis: snap.Satoshis,
        })
    }
}
```

(`c.instance` is illustrative — use whatever handle to the contract
struct `PrepareCall` currently holds. The important property is that
`AddDataOutput` calls on the live contract instance during method
invocation populate `dataOutputs`, and `DataOutputs()` surfaces them.)

### 3.4 Fallback API (optional, non-blocking)

If automatic ANF-driven resolution is out of scope for this change, expose
a `CallOptions.DataOutputs []ContractOutput` field so BSVM can pass the
data outputs explicitly:

```go
// packages/runar-go/sdk_contract.go — CallOptions
type CallOptions struct {
    // existing fields …
    Groth16WAWitness *bn254.WitnessBundle
    DataOutputs      []ContractOutput // NEW (optional fallback API)
}
```

`PrepareCall` then forwards `options.DataOutputs` into
`buildOpts.DataOutputs` verbatim. This is acceptable as an interim shim
while the ANF-driven path lands.

## 4. Acceptance tests

Add to `packages/runar-go/sdk_test.go` (following the existing
`TestBuildCallTransaction_*` naming convention):

1. **`TestBuildCallTransaction_DataOutputsOrder`** — given one state
   output, two data outputs (with OP_RETURN payloads), and a change
   output, assert the tx outputs appear in the order
   `[state, data0, data1, change]`.

2. **`TestBuildCallTransaction_DataOutputsFeeEstimate`** — build the
   same tx with and without data outputs; assert the change amount
   decreases by the data-output byte size × fee rate, within 1-sat
   tolerance for varint rounding.

3. **`TestBuildCallTransaction_ContinuationHashMatches`** — compile a
   minimal stateful contract that calls `AddDataOutput(0, OP_RETURN "x")`,
   build the call tx via `RunarContract.Call`, recompute the BIP-143
   `hashOutputs` over the resulting tx's outputs, and assert it matches
   the locking script's continuation-hash constant for that method. This
   is the end-to-end acceptance test — the one the BSVM rollup covenants
   actually need.

4. **`TestBuildCallTransaction_DataOutputsWithNonZeroSats`** — supply a
   data output with 1,000 satoshis, assert change is reduced by that
   amount, and assert the data output in the tx carries the declared
   value.

5. **Regression test** that existing contracts without `AddDataOutput`
   calls continue to produce three outputs or fewer (state + optional
   change, no stray data outputs). All existing
   `TestBuildCallTransaction_*` tests in sdk_test.go must still pass.

## 5. Versioning / release

1. Land the above under a new Rúnar release tag. Suggest
   `v0.X.Y+data-outputs` or whatever the team's convention is; communicate
   the tag to BSVM when cut.
2. BSVM updates `go.mod` on its side, re-enables `c.AddDataOutput(...)`
   in `pkg/covenant/contracts/rollup_fri.runar.go` and
   `rollup_groth16_wa.runar.go`, flips the
   `TestFRIRollup_F07_NoOpReturn` assertion at
   `pkg/covenant/contracts/rollup_fri_f07_test.go:37` to expect exactly
   one `BSVM\x02`-prefixed data output, and runs its regtest harness to
   confirm the on-chain acceptance path.

## 6. Out of scope for this request

- No change to the existing `AddOutput` / `AddRawOutput` / `Outputs()` API.
- No change to the continuation-hash construction (already correct — the
  grammar and compiler are the authoritative source).
- No change to Groth16 / Groth16-WA pairing paths (R1–R8 already
  delivered).
- Bitcoin Script compiler byte-level output unchanged — this is a host
  SDK change only.

## 7. Contacts

Ping the BSVM team on this repo's issue tracker when the Rúnar release
lands, or drop a note into `RUNAR-ISSUES.md` on the BSVM side under a new
row `R9 — SDK data-output emission`.
