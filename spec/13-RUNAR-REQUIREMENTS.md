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
2. Recompute Fiat-Shamir challenges via Poseidon2 hash chain
3. For each of ~30 queries across ~20 FRI rounds:
   - Verify Merkle proof of queried position (SHA256 hashing)
   - Check the folding equation (Baby Bear field arithmetic)
4. Verify final polynomial evaluation
5. Check DEEP-ALI polynomial identity
6. Verify public values and verifying key match

**What already works in Rúnar**:
- Poseidon2 over Baby Bear (for FRI Merkle commitments — NOT SHA-256)
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

**Measured primitive script sizes** (locking script, compiled Bitcoin Script on BSV regtest):

| Primitive | Locking Script |
|---|---|
| Baby Bear add | 9 bytes |
| Baby Bear sub | 21 bytes |
| Baby Bear mul | 9 bytes |
| Baby Bear inv | 477 bytes |
| Ext4 mul (all 4 components) | 509 bytes |
| Ext4 inv (all 4 components) | 3.1 KB |
| Merkle proof (depth 20) | 482 bytes |
| FRI colinearity check | 1,742 bytes |

These are dramatically smaller than the initial SLH-DSA-based estimate
of 700 KB - 1.5 MB. The full FRI verifier script size depends on the
number of queries and FRI layers (all unrolled), but the primitive
sizes suggest the full verifier will be well under the 2 MB target.

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
     alpha_i = Poseidon2(transcript || layer_data) mod p
   Query indices = Poseidon2(transcript || "queries") mod domain_size
   ```
   Poseidon2 over Baby Bear is used (SP1's hardcoded hash function).

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
     leaf = Poseidon2Compress(response[q])
     Verify Poseidon2MerklePath(leaf, merkle_root_i, authentication_path)
   ```
   All Merkle trees use Poseidon2 compression (NOT SHA-256).

5. **Verify final layer**: The final FRI layer is a constant polynomial. Verify it equals the claimed value.

**Operation counts** (estimated per query, 100 queries — confirmed by Gate 0b):
| Operation | Count per query | Total (100 queries) | Measured script per op |
|-----------|----------------|-------------------|----------------------|
| Baby Bear mul | ~60 | ~6,000 | 9 bytes |
| Baby Bear add | ~40 | ~4,000 | 9 bytes |
| Baby Bear inv | ~4 | ~400 | 477 bytes |
| Poseidon2 compress | ~19 | ~1,900 | ~30-50KB (subroutine) |
| Poseidon2 Merkle path | ~19 levels | ~1,900 levels | uses compress subroutine |

**Script size estimate**: The full FRI verifier size depends on the
number of FRI layers, queries (all unrolled), and the Poseidon2
permutation subroutine size. With 100 queries × ~19 Poseidon2
compressions each = ~1,900 Poseidon2 calls, the Poseidon2
permutation dominates script size. If the permutation compiles to
~30-50KB as a subroutine, the total verifier is estimated at **1-5MB**.
This is larger than the original SHA-256 estimate but within BSV's
limits (4GB max script). Gate 0a Full must measure the actual size.

**Measured regtest timing** (per-vector deploy + call, single-threaded):
| Operation | Time per vector |
|---|---|
| Baby Bear add/sub/mul | ~1.2 s |
| Baby Bear inv | ~4.0 s |
| Merkle proof (depth 3-10) | ~1.4 s |
| FRI colinearity check | ~1.3 s |

These are deploy+call round-trip times per test vector, not per-operation
execution times within a script. In-script execution of individual
operations is sub-millisecond.

---

## New Primitives (Status)

Four primitives are required for the FRI verifier and bridge covenant.
Two are complete and validated (Baby Bear arithmetic, SHA-256 Merkle
proofs). One (Poseidon2) is newly required based on Gate 0b findings.
The fourth (cross-covenant output reference) is needed for the bridge
covenant but not the FRI verifier.

### A. Baby Bear Field Arithmetic — COMPLETE

Implemented as a Rúnar codegen module for the Baby Bear prime field,
analogous to the existing EC codegen module (`codegen/ec.go`) but for:

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
- **Multiplication**: Baby Bear elements are up to ~2×10^9. Their product is up to ~4×10^18, which exceeds 32-bit signed integer range but fits in 64-bit. BSV (post-Genesis) restored big number arithmetic — `OP_MUL` operates on arbitrary-precision integers, not just 32-bit values. The product is reduced mod p using: `OP_DUP <p> OP_DIV <p> OP_MUL OP_SUB` (Barrett reduction, ~6 opcodes). **CONFIRMED**: `OP_MUL` handles 31-bit × 31-bit inputs correctly on BSV regtest (253 test vectors, all passing). Locking script: 9 bytes.
- **Inversion**: Extended Euclidean algorithm or Fermat's little theorem (`a^(p-2) mod p`). Using a square-and-multiply chain: ~300 opcodes per inversion. **CONFIRMED**: 163 test vectors passing on regtest. Locking script: 477 bytes.

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

Each operation compiles to the opcodes shown above. The module is
complete and tested: 829 base field vectors + 295 extension field
vectors, all passing on BSV regtest. Extension field operations (degree-4
over Baby Bear) compile to 509 bytes (ext4 mul) and 3.1 KB (ext4 inv).

### B. Merkle Proof Verification — COMPLETE (SHA-256 variant)

Verify a leaf's inclusion in a SHA256 Merkle tree given an
authentication path. This is used by:
- The **bridge covenant** (withdrawal inclusion, SHA256 tree)
- BSVM-specific data bindings (NOT for FRI — see Poseidon2 below)

The built-in approach was implemented. **Measured**: 72 valid inclusion
proofs and 38 rejection proofs, all passing on BSV regtest. Locking
script sizes: 107 bytes (depth 3), 237 bytes (depth 10), 482 bytes
(depth 20).

**For bridge withdrawals**: The SP1 guest program builds a binary SHA256
Merkle tree of all withdrawal hashes in the batch (max depth 16). The
bridge covenant verifies inclusion using a simple SHA256 Merkle proof —
~3 opcodes per level, 16 levels = ~50 opcodes. This is trivial.

**For FRI verification**: FRI query responses are verified against
**Poseidon2** Merkle commitments (NOT SHA-256). See section D below.
The SHA-256 Merkle primitive is NOT used for FRI.

**No Keccak-256 in Script**: The bridge does NOT verify Ethereum MPT
proofs in Script. The STARK proof covers the full EVM execution
including all Keccak-256 MPT operations. The bridge only verifies
withdrawal inclusion in a SHA256 Merkle tree built by the SP1 guest
and committed as a STARK public value.

### D. Poseidon2 over Baby Bear — REQUIRED (Gate 0b confirmed)

SP1 hardcodes BabyBearPoseidon2 as its STARK configuration. All FRI
Merkle commitments and Fiat-Shamir challenge derivation use the
Poseidon2 permutation over Baby Bear field elements. There is no
SHA256 alternative in SP1.

The FRI verifier needs:

```go
// In runar-go DSL
p2 := runar.Poseidon2BabyBear()
p2.Permute(state [16]BabyBear) [16]BabyBear
p2.Compress(left [8]BabyBear, right [8]BabyBear) [8]BabyBear
```

**Poseidon2 parameters** (from Plonky3/SP1):
- Width: 16 Baby Bear elements
- Rate: 8, Capacity: 8
- Sbox: x^7 (degree 7)
- External rounds: 8 (4 initial + 4 final)
- Internal rounds: 13
- Digest: first 8 elements of the output state (32 bytes)
- Compression: write both 8-element inputs into the 16-element state
  (left into positions 0-7, right into positions 8-15), apply the full
  permutation, take the first 8 elements as the output digest
- Round constants: from Plonky3's `p3-poseidon2` crate, specific to
  Baby Bear with these parameters

**Implementation in Bitcoin Script**: The Poseidon2 permutation is
purely algebraic — it uses only Baby Bear field multiplications and
additions (already proven on BSV). Each external round: matrix multiply
(MDS) + sbox (x^7) on all 16 elements + constant addition. Each
internal round: matrix multiply (diagonal) + sbox on element 0 only +
constant addition.

**Script size estimate**: ~30-50KB for the permutation subroutine.
Each FRI query requires ~19 Poseidon2 calls (one per Merkle tree
level). With 100 FRI queries, that's ~1,900 Poseidon2 calls total.
The permutation code is a subroutine (called repeatedly, not
duplicated), but the data flow (pushing 16 inputs, calling the
subroutine, reading 8 outputs) adds overhead per call.

**Test vectors**: MUST be generated from Plonky3's `p3-poseidon2`
crate with SP1's exact Baby Bear parameters before implementing the
Rúnar codegen module. At minimum:
- 100+ permutation vectors (random inputs → expected outputs)
- 50+ compression vectors (two 8-element digests → compressed digest)
- Verify against a reference Poseidon2 implementation

**Gate 0a dependency**: The Poseidon2 codegen module MUST be complete
and tested before the FRI verifier can be assembled. This is the
FIRST implementation target for Gate 0a Full.

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
| SHA-256 Merkle proof verification (depth 20) | **CONFIRMED** | ~300 opcodes unrolled, used for bridge (NOT FRI — FRI uses Poseidon2) |
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

Additionally, the FRI building blocks have been independently validated
with Plonky3-generated test vectors on BSV regtest:

| Primitive | Vectors | Locking Script | Status |
|---|---|---|---|
| Baby Bear add | 187 | 9 bytes | All pass on regtest |
| Baby Bear sub | 226 | 21 bytes | All pass on regtest |
| Baby Bear mul | 253 | 9 bytes | All pass on regtest |
| Baby Bear inv | 163 | 477 bytes | All pass on regtest |
| Ext4 mul (4 components) | 226 | 509 bytes | All pass interpreter |
| Ext4 inv (4 components) | 69 | 3.1 KB | All pass interpreter |
| Merkle inclusion (SHA256) | 72 | 482 bytes (depth 20) | All pass on regtest |
| Merkle rejection | 38 | — | All pass interpreter |
| FRI colinearity check | 92 | 1,742 bytes | 72/72 accept on regtest |

Total: 1,326 test vectors. All base field, Merkle inclusion, and FRI
colinearity vectors confirmed on BSV regtest. Extension field and
rejection vectors confirmed via Rúnar interpreter.

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
plus the Poseidon2 hash function:
- Baby Bear field arithmetic (confirmed)
- SHA-256 Merkle proof verification (confirmed — used for BSVM-specific
  bindings, NOT for FRI)
- Poseidon2 permutation over Baby Bear — **REQUIRED**. SP1 hardcodes
  BabyBearPoseidon2 as its STARK configuration. All FRI Merkle
  commitments and Fiat-Shamir challenge derivation use Poseidon2.
  There is no SHA256 alternative in SP1. The Rúnar FRI verifier MUST
  implement the full Poseidon2 permutation in Bitcoin Script using
  Baby Bear field arithmetic (multiplications, additions, constant
  additions — no bitwise operations). Parameters: width=16, rate=8,
  capacity=8, sbox_degree=7, external_rounds=8, internal_rounds=13.
  Round constants from Plonky3's p3-poseidon2 crate. Estimated script
  size: 30-50KB for the permutation subroutine. Generate test vectors
  from Plonky3 with SP1's exact parameters before implementing.

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
| Baby Bear field arithmetic | **COMPLETE** — codegen module, 1,326 test vectors |
| SHA256 Merkle proof verification | **COMPLETE** — for bridge/BSVM bindings (NOT FRI) |
| Poseidon2 over Baby Bear | **NEW — REQUIRED** — for FRI Merkle commitments + Fiat-Shamir |
| Poseidon2 Merkle proof verification | **NEW — REQUIRED** — for FRI query verification |
| Cross-covenant output read | **NEW** — calling convention + pattern |
| SP1 FRI verifier (with Poseidon2) | **NEW** — the main deliverable |
| Keccak-256 / Ethereum MPT in Script | **NOT NEEDED** — STARK proof covers it |
