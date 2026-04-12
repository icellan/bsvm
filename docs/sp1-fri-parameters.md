# SP1 FRI Parameters (Gate 0b Step 3)

Generated: 2026-04-06
SP1 version: 6.0.2
Source: SP1 v6 uses KoalaBear + StackedBasefold (not BabyBear + FRI).
The parameters below are from v4; see prover/host/artifacts/ for v6 data.
Plonky3 version: p3 v0.3.2-succinct

## Field Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Base field | Baby Bear | p = 2^31 - 2^27 + 1 = 2,013,265,921 |
| Extension field | BinomialExtensionField<BabyBear, 4> | Degree-4 extension, 124-bit elements |
| Extension modulus | x^4 - 11 | Irreducible over Baby Bear |
| Two-adic generators | Up to 2^27 roots of unity | log_n max = 27 in TwoAdicFriPcs |

## FRI Configuration

SP1 defines four FRI configurations. The core and compressed proofs use different ones.

### Core Proof: `sp1_fri_config()` / `default_fri_config()`

| Parameter | Value |
|-----------|-------|
| log_blowup | 1 |
| Blowup factor | 2 |
| num_queries | 100 (env: FRI_QUERIES) |
| proof_of_work_bits | 16 |
| Folding factor | 2 (binary folding, hardcoded in Plonky3) |
| Hash function | Poseidon2 (Baby Bear, width 16, sbox degree 7) |
| Digest size | 8 Baby Bear elements = 32 bytes |

### Compressed Proof: `compressed_fri_config()`

| Parameter | Value |
|-----------|-------|
| log_blowup | 2 |
| Blowup factor | 4 |
| num_queries | 50 (env: FRI_QUERIES) |
| proof_of_work_bits | 16 |
| Folding factor | 2 (binary folding) |
| Hash function | Poseidon2 (Baby Bear, width 16, sbox degree 7) |
| Digest size | 8 Baby Bear elements = 32 bytes |

### Ultra-Compressed: `ultra_compressed_fri_config()`

| Parameter | Value |
|-----------|-------|
| log_blowup | 3 |
| Blowup factor | 8 |
| num_queries | 33 (env: FRI_QUERIES) |
| proof_of_work_bits | 16 |
| Folding factor | 2 (binary folding) |
| Hash function | Poseidon2 (Baby Bear, width 16, sbox degree 7) |
| Digest size | 8 Baby Bear elements = 32 bytes |

### Inner Recursion: `inner_fri_config()`

| Parameter | Value |
|-----------|-------|
| log_blowup | 1 |
| Blowup factor | 2 |
| num_queries | 100 (env: FRI_QUERIES) |
| proof_of_work_bits | 16 |
| Folding factor | 2 (binary folding) |
| Hash function | Poseidon2 (Baby Bear, width 16, sbox degree 7) |
| Digest size | 8 Baby Bear elements = 32 bytes |

## Security Analysis

### Soundness Level

FRI soundness = `num_queries * log_blowup` bits from the proximity test,
plus `proof_of_work_bits` from grinding.

| Config | Proximity bits | PoW bits | Total |
|--------|---------------|----------|-------|
| Core (default) | 100 × 1 = 100 | 16 | 116 |
| Compressed | 50 × 2 = 100 | 16 | 116 |
| Ultra-compressed | 33 × 3 = 99 | 16 | 115 |
| Inner recursion | 100 × 1 = 100 | 16 | 116 |

All configurations target approximately 100-bit FRI proximity soundness
plus 16-bit proof-of-work, for ~116 bits total security.

### Conjectured vs Proven Security

The above is the *conjectured* FRI soundness. The proven soundness bound
for FRI over extension fields is tighter:

- Conjectured: `num_queries * log_blowup`
- Proven (Johnson bound): `num_queries * log_blowup / extension_degree`

For degree-4 extension: proven = 100/4 = 25 bits from proximity alone.
However, SP1 operates in the *list-decoding* regime where the conjectured
bound is widely accepted. The 100-bit conjectured level is standard for
production STARK systems.

## FRI Round Details (from actual proof)

### Number of Rounds

Both core and compressed proofs show **19 commit phase commits**, meaning
19 FRI folding rounds.

The number of rounds is determined by:
```
rounds = max_log_degree + log_blowup - 1
```

For the core proof: max chip log_degree = 19 (Program chip), log_blowup = 1:
```
LDE degree = 2^(19+1) = 2^20
After 19 binary folds: 2^(20-19) = 2^1 → final polynomial is degree 1
(4 Baby Bear elements as a degree-4 extension field element)
```

For the compressed proof: max chip log_degree = 19 (BatchFRI, MemoryVar, Select),
log_blowup = 1 (inner FRI config, NOT the compressed config — the compressed
config's log_blowup=2 applies to the *compression step*, not the inner recursion):
```
Same calculation: 19 rounds, final polynomial of degree 1
```

### Merkle Path Depths per Round

At FRI round k (0-indexed), the codeword has length 2^(20-k). The Merkle
tree depth is (20-k). Each opening proof is a path from leaf to root,
requiring (depth - 1) sibling hashes:

| Round | Codeword length | Tree depth | Path length (siblings) |
|-------|----------------|------------|----------------------|
| 0 | 2^20 = 1,048,576 | 20 | 19 |
| 1 | 2^19 = 524,288 | 19 | 18 |
| 2 | 2^18 = 262,144 | 18 | 17 |
| ... | ... | ... | ... |
| 17 | 2^3 = 8 | 3 | 2 |
| 18 | 2^2 = 4 | 2 | 1 |

Total path nodes per query: 19 + 18 + ... + 1 = 190
Total path nodes for 100 queries: 19,000
At 32 bytes per node: **608,000 bytes** for FRI Merkle paths.

### PCS Query Openings

Each FRI query also requires batch openings against the original polynomial
commitments (4 batches: preprocessed, main, permutation, quotient).

Each batch opening includes:
- `opened_values`: The polynomial evaluations at the query point
- `opening_proof`: Merkle path to prove inclusion in the commitment

The Merkle paths here are against the original LDE commitment tree (depth 20),
so each path is **20 nodes x 32 bytes = 640 bytes**.

4 batches × 100 queries × 640 bytes = 256,000 bytes for batch Merkle paths.

## Hash Function: Poseidon2

### Critical Finding

**SP1 uses Poseidon2 (not SHA256) for ALL FRI Merkle commitments.**

This applies to:
- Core proofs (`CoreSC = BabyBearPoseidon2`)
- Compressed proofs (`InnerSC = BabyBearPoseidon2`)
- The recursion circuit itself

SP1 does NOT have a SHA256-based STARK configuration for proof generation.
The `BabyBearPoseidon2` type is the only STARK config used.

### Type Chain Confirming This

From `sp1-prover/src/lib.rs`:
```rust
pub type CoreSC = BabyBearPoseidon2;
pub type InnerSC = BabyBearPoseidon2;
```

From `sp1-stark/src/bb31_poseidon2.rs`:
```rust
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, DIGEST_SIZE>;
pub type InnerCompress = TruncatedPermutation<InnerPerm, 2, 8, 16>;
pub type InnerPerm = Poseidon2<InnerVal, Poseidon2ExternalMatrixGeneral,
                               DiffusionMatrixBabyBear, 16, 7>;
```

The Poseidon2 configuration:
- **State width**: 16 Baby Bear elements
- **Sbox degree**: 7 (x^7)
- **External rounds**: 8 (4 before, 4 after internal rounds)
- **Internal rounds**: 13
- **Total rounds**: 21
- **Round constants**: From `sp1-primitives::RC_16_30`
- **External matrix**: `Poseidon2ExternalMatrixGeneral` (circulant MDS)
- **Internal matrix**: `DiffusionMatrixBabyBear`

### Hashing Process

**Leaf hashing** (`PaddingFreeSponge<Poseidon2, 16, 8, 8>`):
1. Initialize state to 16 zeros
2. Absorb input in chunks of 8 Baby Bear elements (rate = 8)
3. Apply Poseidon2 permutation after each absorption
4. Squeeze 8 elements as the digest (capacity = 8)

**Internal node compression** (`TruncatedPermutation<Poseidon2, 2, 8, 16>`):
1. Take two 8-element digests (left child, right child)
2. Concatenate to form 16-element state (fills the full Poseidon2 width)
3. Apply one Poseidon2 permutation
4. Truncate output to first 8 elements as the parent digest

### Poseidon2 Internals (per permutation call)

```
Input: [x_0, x_1, ..., x_15]  (16 Baby Bear elements)

1. External round (×4):
   a. Add round constants (16 constants per round)
   b. Apply S-box x^7 to all 16 elements
   c. Apply external MDS matrix (4×4 circulant matrix applied blockwise)

2. Internal round (×13):
   a. Add round constant to x_0 only (1 constant per round)
   b. Apply S-box x^7 to x_0 only
   c. Apply internal diffusion matrix (DiffusionMatrixBabyBear)

3. External round (×4):
   Same as step 1 with different round constants

Output: [y_0, y_1, ..., y_15]
```

Total operations per permutation call:
- S-box (x^7): 8 × 16 + 13 × 1 = 141 exponentiations
- Matrix multiplications: 21 (4+13+4)
- Round constant additions: 8 × 16 + 13 × 1 = 141

## Implications for the Runar FRI Verifier

### Problem

The Runar verifier (Bitcoin Script) needs to verify FRI proofs on-chain.
This requires:
1. Recomputing Poseidon2 Merkle paths
2. Checking FRI folding consistency
3. Verifying the proof-of-work

BSV's `OP_SHA256` is native and fast. Poseidon2 over Baby Bear is NOT
a native opcode — it must be implemented in Script.

### Poseidon2 in Bitcoin Script: Complexity Estimate

Each Poseidon2 permutation requires:
- 141 S-box computations (x^7 = x * x * x * x * x * x * x in Baby Bear)
  - Each x^7 = 3 multiplications (x^2, x^4, x^4 * x^2 * x)
  - Each multiplication = modular multiply in 31-bit field
- 21 matrix-vector multiplications over Baby Bear
- 141 field additions for round constants

For one FRI verification (compressed proof, 100 queries):
- Merkle path verification: 19,000 compression calls + batch paths
- Each compression = 1 Poseidon2 permutation
- Total Poseidon2 calls: ~23,000+
- Total Script ops: Very large (millions of opcodes)

### Mitigation Options

1. **Accept Poseidon2 in Script**: Implement Poseidon2 Baby Bear arithmetic
   in Bitcoin Script. This is feasible but will be the largest Script program
   ever deployed. Runar's compiler may need optimization for arithmetic-heavy
   circuits.

2. **Reduce query count**: Set `FRI_QUERIES=20` to reduce from 100 to 20
   queries. This reduces Merkle path verifications by 5x but also reduces
   soundness from 100 bits to 20 bits (unacceptable alone — would need
   compensating measures).

3. **Use SP1 Groth16/Plonk wrapping**: SP1 can wrap the STARK proof into a
   Groth16 or Plonk proof (~300 bytes). This requires a BN254 pairing verifier
   instead of FRI, which is a different (possibly harder) challenge for Script.

4. **Hybrid approach**: Verify only a subset of FRI queries on-chain (e.g., 10),
   with the remaining queries checked by nodes. This trades on-chain security
   for feasibility.

5. **Custom SP1 fork with SHA256**: Fork SP1/Plonky3 to use SHA256 instead of
   Poseidon2 for Merkle commitments. The `p3-merkle-tree` crate is generic over
   the hash function. This would make the proofs larger (SHA256 is not
   algebraic, so cannot be efficiently proven inside STARK) but would make
   on-chain verification use native `OP_SHA256`.

   **Tradeoff**: SHA256-based FRI proofs verified inside the SP1 recursion
   circuit would be much slower to prove (SHA256 in STARK is expensive).
   Poseidon2 is specifically chosen because it's cheap inside the STARK
   recursion circuit. Any change here affects proving performance significantly.

6. **Two-layer approach**: Use SP1's Poseidon2-based STARK for proving, then
   wrap it in a second proof system that uses SHA256 for its commitments.
   The outer proof is what goes on-chain. SP1's Plonk/Groth16 wrapping
   already does something similar (wrapping STARK into SNARK), but uses
   BN254 rather than SHA256.

### Recommendation

The most practical path is likely **Option 1** (Poseidon2 in Script) combined
with query count reduction, or **Option 3** (Groth16 wrapping) if a BN254
verifier can be built in Runar.

Key considerations:
- Poseidon2 in Script is novel but technically sound — all operations are
  basic modular arithmetic on 31-bit values
- Baby Bear field arithmetic (mod 2013265921) can use the stack efficiently
  since values fit in 32 bits
- The round constants are fixed and can be embedded in the Script
- Runar's macro system should help manage the repetitive structure

## Appendix: SP1 Type Aliases

```rust
// sp1-prover/src/lib.rs
pub type CoreSC = BabyBearPoseidon2;
pub type InnerSC = BabyBearPoseidon2;
pub type OuterSC = BabyBearPoseidon2Outer;

// sp1-stark/src/bb31_poseidon2.rs  
pub type InnerVal = BabyBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
pub type InnerPerm = Poseidon2<InnerVal, Poseidon2ExternalMatrixGeneral,
                               DiffusionMatrixBabyBear, 16, 7>;
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, DIGEST_SIZE>;  // DIGEST_SIZE=8
pub type InnerCompress = TruncatedPermutation<InnerPerm, 2, 8, 16>;
pub type InnerValMmcs = FieldMerkleTreeMmcs<BabyBear::Packing, BabyBear::Packing,
                                             InnerHash, InnerCompress, 8>;
pub type InnerChallengeMmcs = ExtensionMmcs<InnerVal, InnerChallenge, InnerValMmcs>;
pub type InnerPcs = TwoAdicFriPcs<InnerVal, InnerDft, InnerValMmcs, InnerChallengeMmcs>;

// Plonky3 p3-merkle-tree
// Commitment = Hash<BabyBear, BabyBear, 8>  (8 field elements)
// Proof = Vec<[BabyBear; 8]>  (list of sibling digests)

// FRI config values
pub const DIGEST_SIZE: usize = 8;
```

## Appendix: Actual Proof Numbers

From inspection of the generated proof (4,908 cycle guest program):

### Core Proof
- Shard count: 1
- Chip count: 20
- Max log_degree: 19 (Program chip)
- FRI commit phase commits: 19
- FRI query count: 100
- FRI round 0 Merkle path depth: 19
- Final polynomial: 4 Baby Bear elements (degree-1 in extension)
- Proof-of-work witness: 1,006,646,045 (BabyBear)
- Total size: 1,799,788 bytes

### Compressed Proof
- Shard count: 1 (always, after compression)
- Chip count: 9 (recursion chips)
- Max log_degree: 19 (BatchFRI, MemoryVar, Select)
- FRI commit phase commits: 19
- FRI query count: 100
- Final polynomial: 4 Baby Bear elements
- Proof-of-work witness: 1,761,611,405 (BabyBear)
- Recursion VK: 762 bytes (9 preprocessed chips)
- Public values per shard: 231 (PROOF_MAX_NUM_PVS constant)
- Total size: 1,315,538 bytes

### Verifying Key (Core)
- VK size: 234 bytes
- Preprocessed chips: 2 (Program, Byte)
- VK hash: 0x00d1b500acba23ce11744b8c8656a7a9a7ae7476105da1341804adfde913e4e6
