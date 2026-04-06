# Spec 13: What BSVM Needs from Rúnar

## Context

BSVM builds four Bitcoin Script artifacts with the Rúnar Go compiler:
a state covenant, a bridge covenant, an inbox covenant, and an SP1 FRI
verifier. This document describes what each artifact does, what maps to
existing Rúnar capabilities, and what new work is required.

The Go compiler already supports stateful contracts, covenant recursion
via OP_PUSH_TX, Hash256/SHA256, secp256k1 EC math, WOTS+/SLH-DSA
verification, arithmetic, comparisons, byte manipulation, and
multi-output patterns. Most of the basic building blocks exist.

The gaps are: Baby Bear field arithmetic, Merkle proof verification,
cross-covenant output introspection, and the SP1 FRI verifier itself.

---

## The Four Artifacts

### 1. State Covenant

**Purpose**: Guard the L2 state root as a UTXO chain. Each L2 batch
spends the current covenant UTXO and creates a new one. Only advances
with a valid STARK proof of correct EVM execution.

**State**: `stateRoot` (32-byte hash), `blockNumber` (uint64).

**Single method `advanceState`**:
1. Check block number increments by 1
2. Verify SP1 STARK proof (FRI verification — the hard part)
3. Extract pre/post state roots from proof's public values, verify
   pre-state matches current covenant state
4. Enforce output 0 recreates this covenant with new state
5. Enforce output 1 is an OP_RETURN with batch data

**What already works in Rúnar**:
- `StatefulSmartContract` with mutable `ByteString` and `Bigint` state
- `runar:"readonly"` property for the SP1 verifying key (embedded at compile time)
- Arithmetic (`+`) for block number increment
- Equality comparison (`===`) for state root checks
- `Substr(data, offset, 32)` to extract bytes from public values
- Covenant recursion (auto-injected state continuation via OP_PUSH_TX)
- Output enforcement via `ExtractOutputHash` + `Hash256` comparison

**What's new**:
- **SP1Verify**: The FRI verification subroutine (see section 4 below)
- **OP_RETURN prefix enforcement**: The current covenant pattern
  enforces outputs by comparing `hashOutputs` from the sighash
  preimage. For the state covenant, we also need to verify that
  output 1's script starts with a specific OP_RETURN prefix
  (`BSVM\x02`). This can be done by including the expected output in
  the hashOutputs comparison, but the prover must construct the
  complete output data including the OP_RETURN. This is feasible with
  existing primitives (`Cat` + `Hash256` + `ExtractOutputHash`).

---

### 2. Bridge Covenant

**Purpose**: Hold locked BSV. Release it when presented with proof that
a withdrawal was executed on L2. No operator key.

**State**: `balance` (uint64), `withdrawalNonce` (uint64).

**Methods**:

`deposit`: Anyone can lock BSV. Verify output recreates the covenant
with increased balance. No signature or proof needed.

`withdraw`:
1. Check nonce increments (prevents replay)
2. Compute `hash256(bsvAddress || amount_uint64_be || nonce_uint64_be)`
3. Verify this hash is in the batch's `withdrawalRoot` via SHA256
   Merkle inclusion proof. The `withdrawalRoot` is a STARK public value
   committed by the SP1 guest program — it covers the full EVM execution
   that produced the withdrawal. No Keccak-256 or Ethereum MPT
   verification is needed in Script.
4. Verify the `withdrawalRoot` comes from a confirmed state covenant
   advance (cross-covenant output reference — read the OP_RETURN batch
   data from the referenced tx and extract the root)
5. Pay the correct amount to the user's BSV address
6. Update balance and nonce

`refund`: Return BSV from stale deposits after 144 BSV blocks.

**What already works in Rúnar**:
- Stateful contract with `Bigint` state
- `+`, `-` for balance and nonce arithmetic
- `===`, `>` for comparisons
- `Hash256()` for the withdrawal hash
- `SHA256()` for Merkle inclusion verification
- `Cat()` for building hash preimages
- `Num2Bin(value, 8)` for uint64-to-bytes conversion (big-endian)
- `Hash160()` + manual P2PKH script construction for pay-to-address
- `ExtractLocktime(preimage)` for BSV block height (refund timeout)
- `Substr()` for extracting the withdrawalRoot from OP_RETURN data
- Output enforcement via hashOutputs

**What's new**:
- **SHA256 Merkle proof verification**: Verify a withdrawal hash is in
  a binary SHA256 Merkle tree. The tree is built by the SP1 guest (max
  depth 16). Each level is `SHA256(left || right)` — ~3 opcodes per
  level, 16 levels = ~50 opcodes total. This is trivial with existing
  Rúnar primitives (`SHA256`, `Cat`, bounded `for` loops). No Keccak
  or Ethereum MPT verification is needed — the STARK proof covers that.
- **Cross-covenant output read**: The bridge reads the state covenant's
  OP_RETURN from a *different* BSV transaction — not the current one.
  OP_PUSH_TX only introspects the current spending transaction. Reading
  another transaction's output requires the unlocking script to include
  a serialized reference to the other tx's output, and the covenant
  to verify it (e.g., by checking its script hash). This is a new
  pattern — the unlocking script provides the referenced output data
  as a parameter, and the covenant hashes it and compares against a
  known script hash. **See "New Primitives" below.**

---

### 3. Inbox Covenant

**Purpose**: Censorship escape hatch. Anyone submits EVM transactions
directly to BSV. The state covenant forces their inclusion within N
advances.

**State**: `txQueueHash` (32-byte root), `txCount` (uint64).

**Method `submit`**:
1. Hash the submitted EVM transaction
2. Append to queue: `newRoot = Hash256(oldRoot || txHash)`
3. Increment count
4. Store full tx in OP_RETURN output

**What already works in Rúnar**:
- Everything. Hash chain append is just `Hash256(Cat(oldRoot, txHash))`.
  State management, output enforcement, and OP_RETURN all work with
  existing primitives.

**What's new**: The inbox covenant uses the hash chain approach (`newRoot = SHA256(oldRoot || txHash)`), which requires only existing Rúnar primitives (SHA256, concatenation, state management). The `MerkleAppend` primitive referenced in Spec 10 is an OPTIONAL optimization — the hash chain is the default implementation. If `MerkleAppend` is later added to Rúnar, the inbox can be upgraded to use it for O(log n) inclusion proofs instead of O(n) hash chain verification.

---

### 4. SP1 FRI Verifier

**Purpose**: Verify SP1 STARK proofs in Bitcoin Script. This is the
make-or-break component. If it doesn't fit within BSV constraints, the
architecture must be redesigned.

**What it does**: Takes a serialized SP1 proof, public values, and a
verifying key. Returns valid/invalid.

The FRI verification algorithm:
1. Deserialize proof (Merkle roots, query responses, coefficients)
2. Recompute Fiat-Shamir challenges via SHA256 hash chain
3. For each of ~30 queries across ~20 FRI rounds:
   - Verify Merkle proof of queried position (SHA256 hashing)
   - Check the folding equation (Baby Bear field arithmetic)
4. Verify final polynomial evaluation
5. Check DEEP-ALI polynomial identity
6. Verify public values and verifying key match

**What already works in Rúnar**:
- `SHA256` (single hash, used for FRI Merkle commitments)
- `Hash256` (double hash, used for Fiat-Shamir if needed)
- Bounded `for` loops (unrolled — FRI rounds and queries are fixed)
- `Substr` for byte extraction from proof data
- `Bin2Num` / `Num2Bin` for encoding conversions
- All BSV arithmetic opcodes (`OP_ADD`, `OP_SUB`, `OP_MUL`, `OP_DIV`, `OP_MOD`)

**What's new — this is the big gap**:

**Baby Bear field arithmetic**: SP1 uses the Baby Bear prime field
(p = 2^31 - 2^27 + 1 = 2013265921). The FRI verifier needs:

- `fieldAdd(a, b)` = `(a + b) % p`
- `fieldSub(a, b)` = `(a - b + p) % p`
- `fieldMul(a, b)` = `(a * b) % p`
- `fieldInv(a)` = `a^(p-2) % p` via Fermat's little theorem

Add, sub, mul are each 2-3 opcodes (`OP_ADD OP_MOD` etc.). Inversion
is expensive — ~62 squarings and multiplications via binary
exponentiation. This is the single most expensive operation in the
entire verifier.

These operations are analogous to what the EC codegen module already
does for secp256k1 field arithmetic (`ecFieldAdd`, `ecFieldMul`,
`ecFieldInv` in `codegen/ec.go`), but over a much smaller prime.
The implementation pattern is identical — the prime is just different.

**A Baby Bear codegen module** (similar in structure to `codegen/ec.go`
but for p = 2013265921) would provide field operations as inlined
opcode sequences. The FRI verifier calls these in loops.

**Merkle proof verification for FRI**: Each FRI query requires
verifying a Merkle authentication path (~20 SHA256 hashes). This is
the same primitive the bridge covenant needs, but using SHA256 instead
of Hash256. A built-in or a loop-based pattern handles both.

**Script size estimate**: Based on the existing SLH-DSA codegen
(200-900 KB for SPHINCS+ verification, which also involves many hash
operations and tree traversals), the FRI verifier is expected to be
in the 700 KB - 1.5 MB range. Well within BSV's limits.

### FRI Verifier Algorithm Outline

The FRI (Fast Reed-Solomon Interactive Oracle Proof) verifier in Bitcoin Script performs the following steps. This is compiled from Rúnar's Go DSL into Bitcoin Script opcodes.

**Overview**: The verifier checks that a committed polynomial is close to a Reed-Solomon codeword over the Baby Bear field (p = 2^31 - 2^27 + 1 = 2013265921).

**Algorithm steps**:

1. **Deserialize proof**: Extract from unlocking script:
   - Committed Merkle roots for each FRI layer (log2(degree) layers)
   - Query indices (derived from Fiat-Shamir transcript)
   - Query responses (polynomial evaluations + Merkle authentication paths)

2. **Verify Fiat-Shamir challenges**: Recompute all verifier challenges by hashing the transcript:
   ```
   For each layer i:
     alpha_i = SHA256(transcript || "alpha" || i) mod p
   Query indices = SHA256(transcript || "queries") mod domain_size
   ```
   SHA256 is used (not Keccak) because BSV has native OP_SHA256.

3. **Verify FRI folding**: For each query index q and each layer i:
   ```
   // Verify the folding from layer i to layer i+1
   f_even = (response[q] + response[q + half]) / 2
   f_odd  = (response[q] - response[q + half]) / (2 * omega^q)
   folded = f_even + alpha_i * f_odd
   
   // folded must equal the response at the next layer
   assert folded == next_layer_response[q / 2]
   ```
   All arithmetic is in Baby Bear field (mod p).

4. **Verify Merkle authentication paths**: For each query, verify that the claimed evaluation is consistent with the committed Merkle root:
   ```
   For each layer i, query q:
     leaf = SHA256(response[q])
     Verify MerklePath(leaf, merkle_root_i, authentication_path)
   ```

5. **Verify final layer**: The final FRI layer is a constant polynomial. Verify it equals the claimed value.

**Operation counts** (estimated per query, 32 queries):
| Operation | Count per query | Total (32 queries) |
|-----------|----------------|-------------------|
| Baby Bear mul | ~60 | ~1,920 |
| Baby Bear add | ~40 | ~1,280 |
| Baby Bear inv | ~4 | ~128 |
| SHA256 | ~20 | ~640 |
| Merkle verify | ~10 paths | ~320 paths |

**Script size estimate**: 700 KB – 1.5 MB depending on:
- Number of FRI layers (log2 of polynomial degree)
- Number of queries (security parameter, typically 32)
- Unrolling vs. looping (Bitcoin Script has no loops — all iterations are unrolled)

**Execution time estimate**: < 1 second on modern BSV nodes (dominated by SHA256 operations, which are hardware-accelerated).

---

## New Primitives Needed

Three things that don't exist in Rúnar today:

### A. Baby Bear Field Arithmetic

A codegen module for the Baby Bear prime field, analogous to the
existing EC codegen module (`codegen/ec.go`) but for:

```
p = 2^31 - 2^27 + 1 = 2013265921
```

Operations: `fieldAdd`, `fieldSub`, `fieldMul`, `fieldInv`.

The existing EC module already implements modular field arithmetic
over secp256k1's 256-bit prime using `OP_ADD`, `OP_MUL`, `OP_MOD`.
Baby Bear is a 31-bit prime — the same opcode patterns, smaller
numbers, much faster execution.

**Inversion optimization**: For this specific prime, an addition chain
shorter than generic binary exponentiation may exist. Finding one
would measurably reduce script size since inversion is called hundreds
of times during FRI verification.

### Baby Bear Field Implementation Strategy

The Baby Bear field (p = 2013265921 = 2^31 - 2^27 + 1) fits in 31 bits. Bitcoin Script operates on 32-bit signed integers (with some operations supporting larger), so Baby Bear elements fit in a single stack element.

**Arithmetic implementation**:

- **Addition**: `OP_ADD OP_DUP <p> OP_GREATERTHANOREQUAL OP_IF <p> OP_SUB OP_ENDIF` (5 opcodes)
- **Subtraction**: `OP_SUB OP_DUP 0 OP_LESSTHAN OP_IF <p> OP_ADD OP_ENDIF` (5 opcodes)
- **Multiplication**: Baby Bear elements are up to ~2×10^9. Their product is up to ~4×10^18, which exceeds 32-bit signed integer range but fits in 64-bit. BSV (post-Genesis) restored big number arithmetic — `OP_MUL` operates on arbitrary-precision integers, not just 32-bit values. The product is reduced mod p using: `OP_DUP <p> OP_DIV <p> OP_MUL OP_SUB` (Barrett reduction, ~6 opcodes). **Gate 0a MUST verify** that `OP_MUL` handles 31-bit × 31-bit inputs correctly on the target BSV node software (SV Node or Teranode). If any BSV implementation restricts `OP_MUL` operand size, the fallback is schoolbook multiplication on 16-bit halves (~20 opcodes).
- **Inversion**: Extended Euclidean algorithm or Fermat's little theorem (`a^(p-2) mod p`). Using a square-and-multiply chain: ~300 opcodes per inversion. Inversions are expensive — the FRI verifier should batch them where possible.

**Rúnar codegen module**: The Baby Bear module provides:
```go
// In runar-go DSL
bb := runar.BabyBear()
bb.Add(a, b)      // a + b mod p
bb.Sub(a, b)      // a - b mod p
bb.Mul(a, b)      // a * b mod p
bb.Inv(a)          // a^(-1) mod p
bb.Pow(a, exp)     // a^exp mod p (square-and-multiply)
```

Each operation compiles to the opcodes shown above. The module is the FIRST implementation target — it must be complete and tested before the FRI verifier is built on top of it.

### B. Merkle Proof Verification

Verify a leaf's inclusion in a SHA256 Merkle tree given an
authentication path. This is used by:
- The **FRI verifier** (~30 times per proof, SHA256 trees)
- The **bridge covenant** (withdrawal inclusion, SHA256 tree)

The algorithm is a loop:

```
current = leaf
for each (sibling, direction) in proof:
    if direction == left:
        current = SHA256(sibling || current)
    else:
        current = SHA256(current || sibling)
assert(current == root)
```

Rúnar already has bounded for loops (unrolled), SHA256, Cat, and
conditionals. This can be implemented as:
- A **contract-level pattern** using existing primitives (larger script,
  loop unrolled to max depth)
- Or a **built-in function** that the codegen emits as an optimized
  opcode sequence (smaller script)

Either works. The built-in is preferred for the FRI verifier where
Merkle verification is called ~30 times per proof.

**For bridge withdrawals**: The SP1 guest program builds a binary SHA256
Merkle tree of all withdrawal hashes in the batch (max depth 16). The
bridge covenant verifies inclusion using a simple SHA256 Merkle proof —
~3 opcodes per level, 16 levels = ~50 opcodes. This is trivial.

**For FRI verification**: FRI query responses are verified against
SHA256 Merkle commitments (~20 levels per query, ~30 queries). The
contract-level loop pattern works, unrolled to 20 iterations per
verification.

**No Keccak-256 in Script**: The bridge does NOT verify Ethereum MPT
proofs in Script. The STARK proof covers the full EVM execution
including all Keccak-256 MPT operations. The bridge only verifies
withdrawal inclusion in a SHA256 Merkle tree built by the SP1 guest
and committed as a STARK public value. All Script-level hashing uses
SHA256 (native OP_SHA256).

### C. Cross-Covenant Output Reference

The bridge covenant needs to read the state covenant's output from a
different BSV transaction. This is NOT introspection of the current
transaction (which OP_PUSH_TX handles) — it's verification of data
from another transaction.

**Pattern**: The unlocking script includes the referenced transaction's
output as a parameter. The covenant:
1. Hashes the provided output data
2. Compares the hash against a known state covenant script hash
3. Extracts the state root from the output's data section
4. Verifies it matches the claimed state root

This is achievable with existing primitives (`Hash256`, `Substr`,
`===`) plus a new calling convention where the referenced output data
is passed as a method parameter. No new opcodes needed — just a
documented pattern for how to encode and verify cross-covenant
references.

**Cross-covenant reference encoding**: The unlocking script includes the referenced transaction's relevant output as a serialized parameter:

```
Parameter format: RLP([
    referencedTxID:   bytes32,    // BSV txid of the referenced covenant tx
    outputIndex:      uint32,     // vout of the referenced output
    outputScript:     bytes,      // full locking script of the referenced output
    outputValue:      uint64      // satoshi value
])
```

The covenant verifies this reference by:
1. Hashing the claimed output script and comparing against the known covenant script hash
2. Extracting the state root from the output script's data pushes
3. Verifying the referenced txid has sufficient BSV confirmations (via the sighash preimage's `nLockTime` or `nSequence` fields)

This pattern works with existing Rúnar primitives — `m.Param()`, `m.SHA256()`, `m.RequireEqual()`, and sighash introspection.

---

## Validation Gates

These must pass before BSVM proceeds past Milestone 2.

### Gate 0a Primitive Validation: CONFIRMED

The following primitives have been validated on BSV regtest with a
full state covenant contract (`bsvm/pkg/covenant/contracts/rollup.runar.go`):

| Primitive | Status | Details |
|---|---|---|
| Baby Bear field multiplication (`OP_MUL` with 31-bit operands) | **CONFIRMED** | `bbFieldMul(a, b)` produces correct results on-chain |
| SHA-256 Merkle proof verification (depth 20) | **CONFIRMED** | ~300 opcodes unrolled, matches FRI query depth |
| hash256 batch data binding (`OP_HASH256`) | **CONFIRMED** | 165 KB proof blob hashed on-chain |
| ByteString comparisons (`OP_EQUAL`) | **CONFIRMED** | 32-byte hash comparisons work correctly |
| Public values extraction (`substr` at spec offsets) | **CONFIRMED** | 272-byte blob parsed on-chain |
| Chain ID verification (`num2bin` + byte comparison) | **CONFIRMED** | Cross-shard replay prevention works |
| Stateful UTXO chain (25+ consecutive spends) | **CONFIRMED** | No degradation over long chains |
| Multi-method contract with `checkSig` governance | **CONFIRMED** | freeze/unfreeze/upgrade + advanceState coexist |
| 186 KB transactions | **CONFIRMED** | Execute in ~88ms per advance on regtest |

**Transaction size**: Each covenant advance is **186 KB** (165 KB proof blob +
20 KB batch data + 640 bytes Merkle proof + contract overhead). This matches
the spec 12 estimate of ~216 KB (the remaining ~30 KB is the FRI verifier
locking script, which is a placeholder in the current contract).

**Execution time**: Each advance executes in **~88ms** on BSV regtest,
including mining. 25 consecutive 186 KB advances complete in 2.2 seconds.

These results confirm that all primitives required for the full FRI
verifier work on BSV. The remaining Gate 0a work is building the actual
FRI verifier from these proven primitives and measuring the compiled
script size.

### Gate 0a Full: Can the FRI verifier run on BSV?

Build the SP1 FRI verifier using Rúnar. This is the Rúnar project's
main deliverable for BSVM. The verifier is a contract method that
takes serialized proof data as unlocking script parameters and
verifies the FRI protocol on-chain.

**Prerequisites**: The FRI verifier depends on primitives already
confirmed working on BSV (see Gate 0a Primitive Validation above),
plus any additional hash functions SP1 requires:
- Baby Bear field arithmetic (confirmed)
- SHA-256 Merkle proof verification (confirmed)
- Poseidon2 permutation — **REQUIRED if SP1 uses Poseidon2 for FRI
  commitments**. Check SP1 v4.1.1 source first. If Poseidon2 is
  needed, implement a Rúnar codegen module for it before building the
  FRI verifier.

**Implementation steps**:

1. Obtain the FRI verification trace from Gate 0b step 4 (spec 09) —
   the step-by-step log of every field operation, hash, and comparison
   during verification of a real SP1 proof. This trace is the
   specification for the Rúnar verifier.

2. Implement each verification step as Rúnar DSL code:
   - Fiat-Shamir challenge derivation (hash transcript → field elements)
   - For each FRI query: Merkle inclusion check + colinearity/folding
     equation in Baby Bear extension field
   - Final polynomial evaluation check
   - Opening value verification against AIR constraints

3. Compile to Bitcoin Script. Measure script size.

4. Deploy to BSV regtest. Test with the real SP1 proof from Gate 0b.

**Targets**:

| Metric | Target | Hard limit (>3× = redesign) |
|---|---|---|
| Script size | < 2 MB | 10 MB |
| Peak stack depth | < 500 | 1,000 |
| Execution time | < 500 ms | 1 second |

**Negative tests** (each is as important as positive tests):

| Test | Corruption | Expected |
|---|---|---|
| Bad Merkle path | Flip one byte in a Merkle sibling | Reject |
| Bad folding | Change one FRI query evaluation | Reject |
| Bad final polynomial | Change the final constant poly value | Reject |
| Wrong public values | Change pre_state_root in public values | Reject |
| Wrong verifying key | Use VK from a different guest program | Reject |
| Truncated proof | Remove the last 100 bytes | Reject |
| Wrong program proof | Proof for minimal guest, VK for EVM guest | Reject |
| All-zeros proof | 200 KB of zeros | Reject |

A verifier that accepts invalid proofs is worse than no verifier.

**Fallback plan** (if the FRI verifier exceeds 3× target):

1. Reduce security parameter (fewer queries, e.g., 16 instead of 100)
2. Use SP1 proof composition (recursive proving, available in SP1 v4+)
3. Split FRI verification across multiple BSV transactions
4. Replace FRI with STARK-to-SNARK wrapping (Groth16, changes trust model)

Execute fallbacks in order. Each is tried before moving to the next.

### Gate 0b: Full round-trip

Generate a real SP1 proof and verify it on BSV regtest. This is the
end-to-end validation. See spec 09 Milestone 0 for the detailed
step-by-step procedure.

**Measurements**:

| Metric | Acceptable | Marginal | Unacceptable |
|---|---|---|---|
| Proof size | < 200 KB | 200-500 KB | > 500 KB |
| Verifier script size | < 5 MB | 5-10 MB | > 10 MB |
| Verification time | < 1s | 1-3s | > 3s |

**Deliverables**:

- `tests/sp1/minimal_proof.bin` — serialized proof for minimal guest
- `tests/sp1/minimal_vk.bin` — verifying key
- `tests/sp1/evm_proof.bin` — proof for single EVM transfer
- `tests/sp1/evm_vk.bin` — verifying key for EVM guest
- `tests/sp1/evm_public_values.bin` — 272-byte public values
- `docs/sp1-proof-format.md` — byte-level proof structure
- `docs/sp1-fri-parameters.md` — exact FRI parameters from SP1 v4.1.1
- `docs/sp1-verification-trace.md` — step-by-step verification with actual values
- FRI verifier compiled Script size, stack depth, and execution time
- All negative tests passing on regtest

**Checkpoint**: Gate 0b passes. The FRI verifier accepts real SP1
proofs and rejects all invalid proofs on BSV regtest within the
acceptable thresholds. Proceed to Milestone 3.

---

## Rúnar DSL Subroutine Reference

The following subroutines are referenced in Specs 10, 12, and 13. They are implemented as Rúnar Go DSL methods that compile to Bitcoin Script:

| Subroutine | Signature | Description |
|------------|-----------|-------------|
| `m.Verify(vk, proof)` | `([]byte, []byte)` | Runs FRI verification of SP1 proof against verifying key |
| `m.ExtractPublicValues(proof)` | `([]byte) → []byte` | Extracts the public values segment from the proof |
| `m.ExtractBytes32(data, offset)` | `([]byte, int) → []byte` | Extracts 32 bytes at the given offset |
| `m.ExtractUint64(data, offset)` | `([]byte, int) → uint64` | Extracts 8 bytes as big-endian uint64 |
| `m.RequireEqual(a, b)` | `(any, any)` | Script fails (OP_VERIFY) if a != b |
| `m.RequireOutputScript(idx, script)` | `(int, []byte)` | Verifies output at index has the given script (via hashOutputs) |
| `m.RequireOutputValue(idx, sats)` | `(int, uint64)` | Verifies output at index has the given satoshi value |
| `m.OpReturnPrefix(prefix)` | `([]byte) → []byte` | Returns an OP_RETURN script starting with the given prefix |
| `m.GreaterThan(a, b)` | `(uint64, uint64)` | Script fails if a <= b |
| `m.SHA256(data)` | `([]byte) → []byte` | Computes SHA256 hash (native OP_SHA256) |
| `m.RequireSHA256MerkleProof(leaf, root, proof)` | `([]byte, []byte, [][]byte)` | Verifies leaf inclusion in a binary SHA256 Merkle tree via authentication path |
| `m.GetState(key)` | `(string) → any` | Reads covenant state from the spending transaction's input |
| `m.SetState(key, val)` | `(string, any)` | Sets covenant state in the output |
| `m.RequireReferencedOutput(script, data)` | `([]byte, []byte)` | Verifies a referenced tx output matches script and contains data |
| `m.CSVPrefix(delay)` | `(uint32) → []byte` | Emits `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP` script prefix for relative timelocks |
| `m.IfElse(cond, ifFn, elseFn)` | `(bool, func, func)` | Compiles to `OP_IF ... OP_ELSE ... OP_ENDIF` conditional execution |
| `m.CurrentBlockHeight()` | `() → uint64` | Extracts current BSV block height from `nLockTime` in sighash preimage |
| `c.SelfScript()` | `() → []byte` | Returns the current covenant's own locking script (for self-reference verification) |
| `m.LessThan(a, b)` | `(uint64, uint64) → bool` | Compares two values; compiles to `OP_LESSTHAN` |
| `m.LessOrEqual(a, b)` | `(uint64, uint64) → bool` | Compares two values; compiles to `OP_LESSTHANOREQUAL` |
| `m.And(a, b)` | `(bool, bool) → bool` | Logical AND; compiles to `OP_BOOLAND` |
| `m.Or(a, b)` | `(bool, bool) → bool` | Logical OR; compiles to `OP_BOOLOR` |
| `m.Add(a, b)` | `(uint64, uint64) → uint64` | Arithmetic addition; compiles to `OP_ADD` |
| `m.SighashField(name)` | `(string) → []byte` | Extracts a named field from the OP_PUSH_TX sighash preimage (e.g., `"hashOutputs"`, `"nLockTime"`) |
| `m.SerialiseOutput(sats, script)` | `(uint64, []byte) → []byte` | Serialises a BSV output (8-byte LE value + varint scriptLen + script) for hashOutputs computation |
| `m.Hash256(data)` | `([]byte) → []byte` | Double-SHA256 hash: `SHA256(SHA256(data))` — native `OP_HASH256` |
| `m.PushData(data)` | `([]byte) → []byte` | Wraps data with appropriate OP_PUSHDATA prefix for Script embedding |
| `m.P2PKH(addrHash)` | `([]byte) → []byte` | Constructs a standard P2PKH script: `OP_DUP OP_HASH160 <addrHash> OP_EQUALVERIFY OP_CHECKSIG` |
| `m.Uint64ToBytes(val)` | `(uint64) → []byte` | Converts uint64 to 8-byte big-endian byte string; compiles to `Num2Bin(val, 8)` |
| `c.Prop(name)` | `(string) → any` | Reads a compile-time immutable property embedded in the covenant script |

These are NOT built-in Bitcoin opcodes — they are Rúnar DSL abstractions that compile to sequences of Bitcoin Script opcodes. The compilation is deterministic: the same Rúnar source always produces the same Bitcoin Script.

---

## What BSVM Does NOT Need from Rúnar

- **Keccak256 in Script**: Not needed. The STARK proof covers all EVM
  execution including Keccak-256 MPT operations. The bridge covenant
  verifies withdrawals via a SHA256 Merkle tree (built by the SP1 guest),
  not via Ethereum MPT proofs. All Script-level hashing uses SHA256.
- **Ethereum MPT verification in Script**: Not needed. The bridge
  previously required Keccak-256 MPT verification to prove withdrawal
  existence in the state trie. This is replaced by the STARK-derived
  withdrawal root approach: the SP1 guest commits a SHA256 Merkle root
  of all withdrawal hashes as a public value, and the bridge verifies
  inclusion against this root using native OP_SHA256.
- **Elliptic curve beyond secp256k1**: STARKs are hash-based.
- **New DSL syntax**: The existing `.runar.go` format works.
- **New type system features**: `Bigint` and `ByteString` cover all needs.
- **Contract-to-contract calls**: Not needed. Cross-covenant is via
  output enforcement, not function calls.

---

## Summary

| What BSVM needs | Rúnar status |
|---|---|
| Stateful covenant contracts | **Exists** — `StatefulSmartContract` |
| Immutable compile-time props | **Exists** — `runar:"readonly"` |
| Covenant recursion | **Exists** — auto-injected via OP_PUSH_TX |
| Hash256 / SHA256 | **Exists** — built-in functions |
| Byte concatenation, slicing | **Exists** — `Cat`, `Substr` |
| Arithmetic, comparisons | **Exists** — all operators |
| Uint64-to-bytes | **Exists** — `Num2Bin(v, 8)` |
| Output enforcement | **Exists** — hashOutputs comparison |
| BSV block height | **Exists** — `ExtractLocktime` |
| Multi-output | **Exists** — `AddOutput` |
| P2PKH construction | **Exists** — manual via `Hash160` + `Cat` |
| Baby Bear field arithmetic | **NEW** — codegen module needed |
| SHA256 Merkle proof verification | **NEW** — loop pattern (trivial with existing primitives) |
| Cross-covenant output read | **NEW** — calling convention + pattern |
| SP1 FRI verifier | **NEW** — the main deliverable |
| Keccak-256 / Ethereum MPT in Script | **NOT NEEDED** — STARK proof covers it |
