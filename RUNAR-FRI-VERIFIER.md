# Rúnar handoff — production-scale SP1 FRI verifier for Mode 1 mainnet eligibility (Gate 0a Full)

Status: open request from the BSVM team. Follows on from the existing
BasefoldVerifier PoC at
`runar/integration/go/contracts/BasefoldVerifier.runar.go`.

BSVM repo: https://github.com/icellan/bsvm
Rúnar repo path (local convention): `~/gitcheckout/runar/`

Related specs:
- `spec/09-IMPLEMENTATION-ORDER.md:82-90` — Gate 0a Full, Mode 1 mainnet
  guardrail.
- `spec/13-RUNAR-REQUIREMENTS.md:568-672` — Gate 0a Full design + script-size
  targets.
- `spec/12-SECURITY-MODEL.md` — condition C1 (proof validity).

## 1. Problem

BSVM's Mode 1 rollup covenant (`pkg/covenant/contracts/rollup_fri.runar.go`)
is explicitly a **trust-minimized FRI bridge** — it binds state roots, chain
id, block number, and batch hash via public-value slots but does NOT verify
the SP1 FRI proof on-chain. A `PrepareGenesis` guardrail rejects mainnet +
`VerifyFRI` until the on-chain FRI verifier lands. Mode 1 is test-net /
experimental only today.

External review (Swift Steele, 2026-04-24) identified this as a P0 soundness
gap: without on-chain verification, a malicious prover can commit an invalid
state transition and only off-chain governance freeze catches it.

The Runar team has all the primitives needed to close this gap:

- KoalaBear field ops validated on regtest (`runar.KbFieldAdd/Sub/Mul/Inv`,
  9–477 bytes each). Source: `spec/13-RUNAR-REQUIREMENTS.md:548-557`.
- KoalaBear quartic extension ops (`runar.KbExt4Mul0..3`, `runar.KbExt4Inv0..3`),
  interpreter-validated.
- Poseidon2 KoalaBear permutation + compression + Merkle root, native Bitcoin
  Script codegen: `runar/compilers/go/codegen/poseidon2_koalabear.go`,
  `poseidon2_merkle.go`, DSL hook `runar.MerkleRootPoseidon2KB` /
  `MerkleRootPoseidon2KBv` (variadic). Mock validated against Plonky3
  p3-koala-bear 0.5.2 vectors.
- FRI colinearity check over BabyBear Ext4 (72/72 regtest vectors). Needs to
  be re-run for KoalaBear Ext4 but the algebra is identical.

A **proof-of-concept** verifier assembled from these primitives exists at
`runar/integration/go/contracts/BasefoldVerifier.runar.go` (355 lines). It
implements the full Basefold/STARK verification algorithm (sumcheck → PoW →
FRI queries → Merkle openings → folding → final polynomial check). The
companion test `runar/integration/go/basefold_test.go` confirms the contract
compiles through the full Runar frontend (parse → validate → typecheck → ANF
lowering).

What is **missing** for BSVM mainnet Mode 1:

1. **Production-scale parameters.** The PoC uses
   `numQueries=2, merkleDepth=4, sumcheckRounds=4, numPolynomials=2` —
   appropriate for feasibility demonstration but not for the ~100-bit
   security target. Production parameters (per `spec/13:592`) must target
   `numQueries≈100`, `merkleDepth≈20`, `sumcheckRounds=log₂(trace_length)`,
   and the actual SP1 v6.0.2 AIR polynomial count.
2. **Compiled script size measurement on regtest.** The PoC test only checks
   compilation succeeds. The `spec/13:611` targets are script < 2 MB (hard
   limit 10 MB), peak stack < 500 (hard limit 1,000), execution < 500 ms
   (hard limit 1 s). Production-scale measurements are not yet available.
3. **SP1 proof format parser.** The PoC takes the verifier's ~350 inputs as
   direct method parameters. BSVM's `FRIRollupContract.AdvanceState` can't
   pass 350 scalars — it receives a single `proofBlob` byte-string. Either
   the verifier contract needs a byte-stream-parsing entry point (unpacks
   `proofBlob` into the scalar grid), or the Runar DSL needs a way to inline
   another contract's method as a subroutine so BSVM's covenant can embed
   it.
4. **Fiat-Shamir transcript.** The PoC accepts the challenges as inputs
   (Section 3 sumcheck rounds have `sc0R0..3`, `sc1R0..3`, etc. — challenge
   scalars from the transcript). Production verification must **derive**
   these challenges on-chain from the proof's committed polynomials via
   Poseidon2 sponge absorption, not accept them from the prover's unlocking
   script (an attacker would forge them trivially).
5. **Complete negative-test coverage on regtest.** Per `spec/13:619`: bad
   Merkle path, bad folding, bad final polynomial, wrong public values,
   wrong VK, truncated proof, wrong-program proof, all-zeros proof. All must
   reject on regtest.

## 2. What BSVM needs from Runar

### 2.1 Production-scale `Verify` method

Extend `BasefoldVerifier.Verify` to the production parameter set, or provide
a `VerifySP1FRIProduction` twin. Target per `spec/13:611`:

| Metric           | Target           | Hard limit |
|------------------|------------------|------------|
| Script size      | < 2 MB           | 10 MB      |
| Peak stack depth | < 500            | 1,000      |
| Execution time   | < 500 ms         | 1 s        |

Measurement: deploy to BSV regtest, execute a real SP1 v6.0.2 proof from
`bsv-evm/tests/sp1/evm_proof.bin` (when the EVM guest proof fixture is
regenerated against KoalaBear — see `spec/13:657-668`). Report measured
script size, peak stack depth, and execution time to BSVM.

If targets are exceeded by >3×, fall back per `spec/13:634`:
1. Reduce security parameter (fewer queries, e.g., 64 or 16 instead of 100).
2. Use SP1 proof composition (recursive proving).
3. Split FRI verification across multiple BSV transactions.
4. Replace FRI with STARK-to-SNARK wrapping (Groth16) — changes trust
   model.

Execute fallbacks in order, trying each before moving to the next.

### 2.2 On-chain Fiat-Shamir challenge derivation

Replace the PoC's challenge-as-parameter design with challenges derived
inside the contract via Poseidon2 sponge absorption of the prover's
commitments. The transcript is:

```
H.absorb(commitRoot)         // Step 1: polynomial commitment absorb
batchAlpha = H.squeeze()
H.absorb(batchedEvals)       // Step 2: batched evaluation absorb
sc0R = H.squeeze()
H.absorb(sc0Poly)            // Step 3 round 0
sc1R = H.squeeze()
…
H.absorb(friCommitRoot)
foldAlpha = H.squeeze()
H.absorb(queryOpenings)
queryIndices = H.squeeze_indices()
```

The absorption + squeeze primitives are straightforward on top of
`EmitPoseidon2KBPermute` / `EmitPoseidon2KBCompress`. A dedicated
`Poseidon2Transcript` DSL struct would be ergonomic; alternatively
expose `runar.PoseidonSqueezeIndices(state, count)` / 
`runar.PoseidonAbsorb(state, bytes)` as top-level DSL helpers.

Producer-side Fiat-Shamir already happens inside SP1 v6.0.2 during proving;
the verifier replay is the on-chain counterpart of the SP1 verifier's
`FiatShamirChallenger` (see the SP1 recursion-compiler crate for reference
transcript code).

### 2.3 SP1 proof format parser — byte-stream entry point

The BSVM covenant receives `proofBlob runar.ByteString` in
`FRIRollupContract.AdvanceState`. Today `proofBlob` is `_ = proofBlob` — 
discarded. To wire the verifier in, the AdvanceState method needs to call
a single entry point that:

- Takes `proofBlob` + `publicValues` + the pinned SP1 verifying key hash.
- Parses `proofBlob` bytes into the internal scalar grid (polynomial
  commitments, sumcheck polynomials, FRI query openings, Merkle paths,
  final polynomial).
- Runs the on-chain Fiat-Shamir transcript over the parsed commitments.
- Verifies sumcheck, PoW, FRI queries, folding, final polynomial.
- Returns success or `OP_VERIFY`-fails the script.

One API option:

```go
// In runar-go — top-level DSL function
func VerifySP1FRI(
    proofBlob   runar.ByteString,
    publicValues runar.ByteString,
    sp1VKeyHash runar.ByteString,
) // panics (OP_VERIFY) on invalid proof; returns on valid
```

`sp1VKeyHash` is the covenant's readonly `c.SP1VerifyingKeyHash` field.

The byte-level proof layout must follow `docs/sp1-proof-format.md` (see
spec 13:664) — the serialized SP1 STARK proof from the SP1 SDK. The parser
is purely mechanical offset/length work once that layout is pinned.

### 2.4 Negative-test suite on regtest

Per `spec/13:619-631`, the following corruptions must reject when submitted
against the production-scale verifier on regtest:

| Test                  | Corruption                                      |
|-----------------------|-------------------------------------------------|
| Bad Merkle path       | Flip one byte in a sibling hash                 |
| Bad folding           | Change one FRI query evaluation                 |
| Bad final polynomial  | Change the final constant poly value            |
| Wrong public values   | Change `pre_state_root` in public values        |
| Wrong verifying key   | Use VK from a different guest program           |
| Truncated proof       | Remove the last 100 bytes                       |
| Wrong program proof   | Proof for minimal guest, VK for EVM guest       |
| All-zeros proof       | 200 KB of zeros                                 |

All must fail `OP_VERIFY` on regtest. Report failure modes to BSVM so Mode 1
covenant diagnostics can surface the right error.

## 3. What BSVM will do in response

Once Runar delivers §2.1–2.4:

1. `go.mod` bump to the Runar release tag.
2. Remove `_ = proofBlob` from `FRIRollupContract.AdvanceState` at
   `pkg/covenant/contracts/rollup_fri.runar.go` and add
   `runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash)`
   ahead of the public-values bindings.
3. Drop the `publicValues` caller-supplied parameter — the verifier now
   extracts committed public values from the proof. This is a deliberate
   ABI break: attacker can no longer forge pv.
4. Remove the `PrepareGenesis` mainnet guardrail for Mode 1
   (`pkg/covenant/compile.go` / `pkg/shard/...`).
5. Add a negative test per C1–C7 on top of the existing
   `TestFRIRollup_Reject*` family, feeding corrupted proof blobs.
6. Re-run `ethereum/tests/VMTests/GeneralStateTests` to confirm dual-EVM
   parity (Go EVM vs revm-in-SP1) under the production proof generation
   path.
7. Update `whitepaper/bsvm-whitepaper.tex:294,319-337` and
   `whitepaper/bsvm-security-model.tex:192-212` from "trust-minimized FRI
   bridge" to "on-chain FRI verifier" language, and remove the Mode 1
   mainnet blocker note.

## 4. Not in scope for this request

- No change to Mode 2 (Groth16) or Mode 3 (Groth16-WA) verification. They
  stay on BN254 pairing paths.
- No change to the `BSVM\x02` OP_RETURN DA envelope (delivered in R9 /
  `RUNAR-SDK-DATA-OUTPUTS.md`).
- No change to SP1 guest program internals — those are upstream
  (Succinct Labs) deliverables.
- No change to the on-chain Poseidon2-to-SHA-256 transcoding envisioned by
  older spec text — the Runar Poseidon2 codegen verifies Merkle paths
  natively on-chain, so no host-side transcoding is needed.
  (`spec/09-IMPLEMENTATION-ORDER.md:75-80` and `CLAUDE.md` mention the
  transcoder; those notes are stale relative to Runar's current
  capabilities.)

## 5. Sequencing / releases

- Suggested Runar release tag: `v0.X.Y+fri-verifier`.
- Spec doc that ships alongside the release: `docs/sp1-proof-format.md`
  (byte-level layout) and `docs/fri-verifier-measurements.md` (regtest
  script size / stack / timing). BSVM needs both to wire up §3.
- Ping BSVM via `RUNAR-ISSUES.md` with a new row
  `R10 — production SP1 FRI verifier + AdvanceState entry point` when
  a candidate release is ready for BSVM uptake.

## 6. Contacts

BSVM-side owner for this integration: see `CLAUDE.md` in the bsv-evm
repo root for the on-boarding notes. Open questions, API shape feedback,
and proof-format ambiguity go into `RUNAR-ISSUES.md` on the BSVM side.
