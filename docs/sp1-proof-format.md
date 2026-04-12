# SP1 Proof Format Documentation (Gate 0b Steps 1-3)

Generated: 2026-04-06
SP1 SDK version: 6.0.2 (reports as v6.0.0 in proof metadata)

## Guest Program

Minimal arithmetic: `a + b = sum` where a=10, b=20, sum=30.

```rust
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let a: u32 = sp1_zkvm::io::read();
    let b: u32 = sp1_zkvm::io::read();
    let sum = a + b;
    sp1_zkvm::io::commit(&sum);
}
```

## Execution Metrics

| Metric | Value |
|--------|-------|
| Total RISC-V cycles | 4,908 |
| Execution time (no proof) | ~3.4 ms |
| Guest ELF size | 131,296 bytes (128 KB) |

## Proof Generation Results

### CORE Proof (raw STARK, scales linearly with cycles)

| Metric | Value |
|--------|-------|
| Proving time | ~11.0 s |
| Verification time | ~159 ms |
| Proof size | 1,799,788 bytes (1,757.6 KB) |

### COMPRESSED Proof (recursive STARK compression, constant size)

| Metric | Value |
|--------|-------|
| Proving time | ~21.7 s |
| Verification time | ~68 ms |
| Proof size | 1,315,538 bytes (1,284.7 KB) |

### Common Artifacts

| Artifact | Size |
|----------|------|
| Verifying key (VK) | 234 bytes |
| Public values | 4 bytes |
| VK hash | 0x00d1b500acba23ce11744b8c8656a7a9a7ae7476105da1341804adfde913e4e6 |

## Public Values

- Size: 4 bytes
- Hex: `1e000000` (little-endian u32 = 30)
- Content: The committed output of the guest program (the sum)

## Gate 0b Threshold Evaluation

The relevant proof for BSV on-chain verification is the **compressed** proof,
since core proofs scale linearly and would be impractical for larger programs.

| Metric | Threshold | Measured | Status |
|--------|-----------|----------|--------|
| Proof size | < 200 KB acceptable, < 500 KB marginal | 1,284.7 KB | UNACCEPTABLE |

### Analysis

The compressed proof size of 1.28 MB for a trivial 4,908-cycle program exceeds
the 500 KB threshold. However, several factors are relevant:

1. **Constant overhead**: The compressed proof size is dominated by the recursive
   compression circuit, not the guest program complexity. A much larger program
   (e.g., full EVM execution with thousands of transactions) would produce a
   compressed proof of similar size.

2. **Core proof scaling**: The core proof scales linearly with cycles. For real
   EVM batches (~10M+ cycles), core proofs would be hundreds of MB. The
   compressed proof remains ~1.3 MB regardless.

3. **Proof decomposition for BSV**: The SP1 STARK proof internally uses FRI
   (Fast Reed-Solomon Interactive Oracle Proof). The BSV covenant verifier only
   needs to check the FRI proof structure, not the full compressed proof
   serialization. The actual data needed for on-chain verification may be
   smaller than the full serialized proof.

4. **Options to reduce on-chain footprint**:
   - Extract only the FRI query proofs and commitments needed for verification
   - Use Plonk/Groth16 wrapping (SP1 supports this) for ~300 byte proofs,
     but this requires a different verifier (BN254 pairing, not FRI)
   - Batch multiple blocks per proof to amortize the fixed cost

---

## SP1 Proof Binary Layout (Step 2 — Byte-Level Structure)

All proofs are serialized with **bincode** (little-endian, varint length
prefixes for variable-length containers). The top-level type is
`SP1ProofWithPublicValues`:

```
SP1ProofWithPublicValues {
    proof: SP1Proof,             // enum discriminant (u32) + payload
    public_values: SP1PublicValues,  // length-prefixed byte vec
    sp1_version: String,         // length-prefixed UTF-8 string
}
```

### SP1Proof Enum Variants

```
SP1Proof::Core(Vec<ShardProof<CoreSC>>)         // discriminant = 0
SP1Proof::Compressed(Box<SP1ReduceProof<InnerSC>>)  // discriminant = 1
SP1Proof::Plonk(PlonkBn254Proof)                // discriminant = 2
SP1Proof::Groth16(Groth16Bn254Proof)            // discriminant = 3
```

**Both CoreSC and InnerSC are `BabyBearPoseidon2`** — they use
identical field and hash parameters. The difference is only in the FRI
configuration (blowup, query count).

### ShardProof<SC> Structure

Each shard proof contains:

```
ShardProof<SC: StarkGenericConfig> {
    commitment: ShardCommitment<Com<SC>>,
    opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    opening_proof: TwoAdicFriPcsProof<Val, Challenge, InputMmcs, FriMmcs>,
    chip_ordering: HashMap<String, usize>,
    public_values: Vec<Val<SC>>,
}
```

#### ShardCommitment — 96 bytes

Three Poseidon2 commitments, each `Hash<BabyBear, BabyBear, 8>` = 8 x u32 = 32 bytes:

```
ShardCommitment {
    main_commit:        [BabyBear; 8],   // 32 bytes — Merkle root of main trace
    permutation_commit: [BabyBear; 8],   // 32 bytes — Merkle root of permutation trace
    quotient_commit:    [BabyBear; 8],   // 32 bytes — Merkle root of quotient polynomial
}
```

#### ShardOpenedValues — Variable Size

```
ShardOpenedValues {
    chips: Vec<ChipOpenedValues<BabyBear, BinomialExtensionField<BabyBear, 4>>>,
}

ChipOpenedValues {
    preprocessed: AirOpenedValues { local: Vec<EF>, next: Vec<EF> },
    main:         AirOpenedValues { local: Vec<EF>, next: Vec<EF> },
    permutation:  AirOpenedValues { local: Vec<EF>, next: Vec<EF> },
    quotient:     Vec<Vec<EF>>,       // quotient chunks, each width-4
    global_cumulative_sum: SepticDigest<BabyBear>,  // 14 x BabyBear (curve point)
    local_cumulative_sum: EF,         // 4 x BabyBear
    log_degree: usize,               // u64 in bincode
}
```

Where `EF = BinomialExtensionField<BabyBear, 4>` = 4 x u32 = 16 bytes per element.

**Measured sizes:**
- Core proof opened_values: 60,776 bytes (59.4 KB) — 20 chips
- Compressed proof opened_values: 26,816 bytes (26.2 KB) — 9 chips

#### TwoAdicFriPcsProof (Opening Proof) — Dominates Proof Size

```
TwoAdicFriPcsProof {
    fri_proof: FriProof<Challenge, FriMmcs, Val>,
    query_openings: Vec<Vec<BatchOpening<Val, InputMmcs>>>,
}
```

##### FriProof Structure

```
FriProof<F: Field, M: Mmcs<F>, Witness> {
    commit_phase_commits: Vec<M::Commitment>,  // Merkle roots per folding round
    query_proofs: Vec<QueryProof<F, M>>,       // One per FRI query
    final_poly: F,                              // Final constant (degree-4 extension)
    pow_witness: Witness,                       // Proof-of-work nonce (BabyBear)
}

QueryProof<F, M> {
    commit_phase_openings: Vec<CommitPhaseProofStep<F, M>>,
}

CommitPhaseProofStep<F, M> {
    sibling_value: F,                // Extension field element (4 x BabyBear = 16 bytes)
    opening_proof: Vec<[BabyBear; 8]>,  // Merkle path (list of Poseidon2 digests)
}
```

Each Merkle path node is `[BabyBear; 8]` = 32 bytes (Poseidon2 digest).

##### BatchOpening Structure

```
BatchOpening<Val, InputMmcs> {
    opened_values: Vec<Vec<Val>>,         // Per-matrix evaluations at query point
    opening_proof: Vec<[BabyBear; 8]>,    // Merkle path for the batch commitment
}
```

### Measured Core Proof Layout (Shard 0)

```
Total shard proof:  1,799,745 bytes (1,757.6 KB)
├── commitment:         96 bytes (0.005%)
├── opened_values:  60,776 bytes (3.4%)
├── opening_proof: 1,737,452 bytes (96.5%)
│   ├── fri_proof:      655,044 bytes (37.7%)
│   │   ├── commit_phase_commits: 19 × 32 bytes = 608 bytes
│   │   ├── query_proofs: 100 queries × 19 rounds each
│   │   │   Each round: 16 bytes (sibling) + Merkle path
│   │   │   Path lengths: 19, 18, 17, ..., 1 nodes × 32 bytes each
│   │   ├── final_poly: 16 bytes
│   │   └── pow_witness: 4 bytes
│   └── query_openings: 1,082,408 bytes (62.3%)
│       100 queries × 4 batches each:
│         Batch 0 (preprocessed): 2 matrices, 25 values, 20-node path
│         Batch 1 (main trace):   20 matrices, 1,260 values, 20-node path
│         Batch 2 (permutation):  20 matrices, 444 values, 20-node path
│         Batch 3 (quotient):     40 matrices, 160 values, 20-node path
├── chip_ordering:     489 bytes
└── public_values:     932 bytes
```

**Key insight**: 96.5% of the proof is the opening_proof (FRI + PCS queries).
The FRI query proofs and PCS query openings are split roughly 38/62.

### Measured Compressed Proof Layout

```
Total serialized:  1,315,538 bytes (1,284.7 KB)
├── SP1Proof enum discriminant: 4 bytes
├── SP1ReduceProof:
│   ├── recursion_vk:     762 bytes
│   └── shard_proof:  1,314,741 bytes (1,283.9 KB)
│       ├── commitment:        96 bytes
│       ├── opened_values: 26,816 bytes (26.2 KB)
│       ├── opening_proof: 1,286,652 bytes (1,256.5 KB)
│       │   ├── fri_proof:      655,044 bytes (639.7 KB)
│       │   │   ├── commit_phase_commits: 19 × 32 bytes = 608 bytes
│       │   │   ├── query_proofs: 100 queries × 19 rounds
│       │   │   ├── final_poly: 16 bytes
│       │   │   └── pow_witness: 4 bytes
│       │   └── query_openings: 631,608 bytes (616.8 KB)
│       │       100 queries × 4 batches:
│       │         Batch 0 (preprocessed): 9 matrices, 163 values, 20-node path
│       │         Batch 1 (main):         9 matrices, 408 values, 20-node path
│       │         Batch 2 (permutation):  9 matrices, 188 values, 20-node path
│       │         Batch 3 (quotient):    18 matrices, 72 values, 20-node path
│       ├── chip_ordering:    245 bytes
│       └── public_values:    932 bytes
├── public_values: ~12 bytes
└── sp1_version: ~18 bytes
```

### Chip Configuration

#### Core Proof: 20 RISC-V Execution Chips

| Chip | log_degree | Purpose |
|------|-----------|---------|
| Program | 19 | Program ROM |
| Global | 18 | Global bus |
| MemoryGlobalFinalize | 17 | Memory finalization |
| MemoryGlobalInit | 17 | Memory initialization |
| Byte | 16 | Byte lookup table |
| Cpu | 16 | CPU execution trace |
| AddSub | 15 | Addition/subtraction ALU |
| Lt | 14 | Less-than comparison |
| Auipc | 13 | Add upper immediate to PC |
| Bitwise | 13 | Bitwise operations |
| Branch | 13 | Branch instructions |
| DivRem | 13 | Division/remainder |
| Jump | 13 | Jump instructions |
| MemoryInstrs | 13 | Memory load/store |
| MemoryLocal | 13 | Local memory |
| Mul | 13 | Multiplication |
| ShiftLeft | 13 | Left shift |
| ShiftRight | 13 | Right shift |
| SyscallCore | 13 | System call core |
| SyscallInstrs | 13 | System call instructions |

#### Compressed Proof: 9 Recursion Chips

| Chip | log_degree | Purpose |
|------|-----------|---------|
| BatchFRI | 19 | FRI batch verification |
| MemoryVar | 19 | Variable memory access |
| Select | 19 | Multiplexer/selector |
| ExpReverseBitsLen | 18 | Exponentiation for FRI |
| MemoryConst | 17 | Constant memory access |
| Poseidon2WideDeg3 | 17 | Poseidon2 hash computation |
| BaseAlu | 16 | Base field ALU |
| ExtAlu | 16 | Extension field ALU |
| PublicValues | 4 | Public value constraints |

### FRI Round Structure (Both Core and Compressed)

Both proofs have **19 commit phase commits** (FRI folding rounds). This means:
- Starting polynomial degree: 2^20 = 1,048,576 (after blowup from max log_degree 19 + log_blowup 1)
- After 19 folds (factor-2 folding): degree = 2^(20-19) = 2 -> final polynomial is degree-1 (constant in extension field)
- Each fold halves the polynomial degree

Each of the **100 query proofs** contains 19 commit phase openings. At round k,
the Merkle path has (20 - 1 - k) = 19, 18, 17, ..., 1 siblings:
- Round 0: 19-node Merkle path (tree depth 20)
- Round 1: 18-node Merkle path (tree depth 19)
- ...
- Round 18: 1-node Merkle path (tree depth 2)

Total FRI Merkle path nodes per query = 19+18+...+1 = 190 nodes x 32 bytes = 6,080 bytes.
Over 100 queries: 608,000 bytes for FRI Merkle paths alone (~59% of the FRI proof).

### Digest Format

All Merkle tree commitments and path nodes are **Poseidon2 digests**:
- Format: `[BabyBear; 8]` = 8 Baby Bear field elements
- Size: 8 x 4 bytes = 32 bytes per digest
- Each element is a canonical Baby Bear value: 0 <= x < 2^31 - 2^27 + 1

### Field Element Encoding (bincode)

| Type | Size | Encoding |
|------|------|----------|
| BabyBear (Val) | 4 bytes | Little-endian u32, canonical form |
| BinomialExtensionField<BabyBear, 4> (Challenge) | 16 bytes | 4 x BabyBear, coefficients in order |
| SepticExtension<BabyBear> | 28 bytes | 7 x BabyBear |
| SepticDigest<BabyBear> | 56 bytes | 2 x SepticExtension (x, y curve point) |
| Poseidon2 digest | 32 bytes | [BabyBear; 8] |
| usize | 8 bytes | Little-endian u64 (bincode default) |
| Vec length prefix | 8 bytes | Little-endian u64 |
| HashMap length prefix | 8 bytes | Little-endian u64 |

---

## FRI Parameters (Step 3)

See `docs/sp1-fri-parameters.md` for the complete FRI parameter analysis.

### Critical Finding: Hash Function

**ALL SP1 FRI Merkle commitments use Poseidon2 over Baby Bear.**

This is confirmed from three independent sources:

1. **Source code**: `CoreSC = BabyBearPoseidon2` and `InnerSC = BabyBearPoseidon2`
   (sp1-prover/src/lib.rs). Both use `PaddingFreeSponge<Poseidon2, 16, 8, 8>`
   for hashing and `TruncatedPermutation<Poseidon2, 2, 8, 16>` for compression.

2. **Proof inspection**: All commitments are `Hash<BabyBear, BabyBear, 8>` — arrays
   of 8 BabyBear field elements. This is the Poseidon2 digest format, not SHA256
   (which would be raw 32-byte hashes).

3. **Recursion circuit**: The compressed proof contains a `Poseidon2WideDeg3` chip
   at log_degree=17, confirming Poseidon2 is computed within the recursion STARK
   itself.

### Implication for Runar Verifier

The Runar FRI verifier **cannot use BSV's native OP_SHA256**. It must implement
Poseidon2 over Baby Bear in Bitcoin Script. This is a significant complexity
increase. See `docs/sp1-fri-parameters.md` for detailed analysis and mitigation
options.

## Artifacts Location

All artifacts are saved in `prover/host/artifacts/`:
- `core_proof.bin` — Serialized core STARK proof
- `compressed_proof.bin` — Serialized compressed STARK proof
- `vk.bin` — Serialized verifying key
- `vk_hash.hex` — VK hash as hex string
- `public_values.bin` — Raw public values bytes
- `guest.elf` — Guest program RISC-V ELF binary

Inspection binary: `cargo run --bin inspect_proof -- <artifacts_dir>`

## Next Steps (Gate 0b Steps 4-7)

1. **Step 4**: Write the EVM guest program (single transfer) and generate a
   proof with full FRI verification trace.
2. **Step 5**: Implement the full FRI verifier in Runar using the proven
   primitives from Gate 0a.
3. **Step 6**: Deploy and test on BSV regtest.
4. **Step 7**: Measure and evaluate against thresholds.
