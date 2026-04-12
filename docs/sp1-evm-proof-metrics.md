# SP1 EVM Transfer Proof Metrics — Gate 0b Step 4

Generated: (run timestamp in program output)

## Test Scenario

- **Guest program**: Simplified balance transfer (not full revm)
- **SP1 version**: v6.0.0
- **Chain ID**: 46573
- **Sender**: `0xaabbccddee11223344556677889900aabbccddee`
- **Recipient**: `0x112233445566778899aabbccddeeff1122334455`
- **Transfer value**: 500000000 (simplified units)
- **Gas**: 21000 * 1 = 21000

## Execution Metrics

| Metric | Value |
|--------|-------|
| RISC-V cycle count | 45088 |
| Execution time (no proof) | 4.320667ms |
| Guest ELF size | 184584 bytes (180.3 KB) |

## Proof Metrics

### Core Proof

| Metric | Value |
|--------|-------|
| Proving time | 20.088759375s |
| Verification time | 60.200709ms |
| Proof size | 2777376 bytes (2712.3 KB) |
| Shards | 2 |

### Compressed Proof

| Metric | Value |
|--------|-------|
| Proving time | 80.385403041s |
| Verification time | 26.8235ms |
| Proof size | 1272677 bytes (1242.8 KB) |

## Public Values (112 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 32 | preStateRoot | `8b4339a7232c8f672b1c4321d786ef7b53a677a30cdd512cde4f729532bdf911` |
| 32 | 32 | postStateRoot | `f5d48588c32c988760e0e39b49e6d47ab309a72cb8ce913edad89094fb98f72b` |
| 64 | 8 | gasUsed | `0000000000005208` (= 21000) |
| 72 | 32 | batchDataHash | `d57b551b3a181971e11cda402aa1b626a4ed8464741cc7bc615e157c902fc43e` |
| 104 | 8 | chainId | `000000000000b5ed` (= 46573) |

## Artifacts

| File | Size |
|------|------|
| `core_proof.bin` | 2777376 bytes (2712.3 KB) |
| `compressed_proof.bin` | 1272677 bytes (1242.8 KB) |
| `vk.bin` | 104 bytes |
| `guest_evm.elf` | 184584 bytes (180.3 KB) |
| `public_values.bin` | 112 bytes |

## Gate 0b Evaluation

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Compressed proof size | 1242.8 KB | < 200 KB acceptable, < 500 KB marginal | UNACCEPTABLE |

## VK Hash

```
0x00258e9bac494c2301d94d561c8bdf037acc42d7f9fb3b350206d816347f7d8a
```
