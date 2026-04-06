# Phase 1: EVM Extraction

## Goal
Extract geth's `core/vm` package into a standalone Go module (`pkg/vm`) with zero dependencies on go-ethereum's consensus, p2p, ethdb, or trie packages. The extracted EVM must pass the Ethereum VM test suite.

## Source
Base extraction on the **last stable geth release tag before EOF (EVM Object Format, EIP-7692)**. EOF introduces new opcodes (RJUMP, CALLF, RETF), a container format, and deploy-time validation — a significant scope increase that is deferred to a future version of bsvm.

Concretely: use a geth tag from the **Prague/Electra (Pectra) hardfork** era, before EOF activation. As of early 2026, this is likely in the v1.14.x or v1.15.x range. Document the exact tag used in the repository README.

The `core/vm` directory is the primary target.

## Files to Extract from geth `core/vm/`

These files form the EVM core and should be copied into `pkg/vm/`:

### Direct copy (minimal modifications needed)
- `opcodes.go` — Opcode constants (STOP, ADD, MUL, ... SELFDESTRUCT)
- `stack.go` — EVM stack implementation
- `memory.go` — EVM memory model
- `memory_table.go` — Memory size calculation functions
- `gas.go` — Gas cost constants
- `gas_table.go` — Gas cost functions per opcode per hardfork
- `jump_table.go` — Instruction sets per hardfork (Frontier through Fusaka)
- `instructions.go` — Opcode implementation functions
- `common.go` — Shared utilities (calcMemSize64, getData, etc.)
- `errors.go` — EVM error definitions
- `analysis.go` — Bytecode analysis (JUMPDEST validation via bitvec)

### Copy with interface replacement needed
- `evm.go` — Core EVM struct and Call/Create methods. Must replace geth-specific `state.AccessEvents` and `stateless` references with our own interfaces (remove Verkle/witness code paths entirely).
- `interpreter.go` — The main bytecode interpreter loop
- `contract.go` — Contract representation (code, gas, caller)
- `contracts.go` — Precompiled contracts (ecRecover, SHA256, RIPEMD160, identity, modexp, ecAdd, ecMul, ecPairing, blake2f, point evaluation). These have crypto dependencies — use the same underlying Go crypto libraries directly.
- `logger.go` / tracing hooks — Simplified; we define our own `Tracer` interface.

### Files to NOT copy (replace with our own)
- `interface.go` — We redefine the `StateDB` interface (see Phase 1b)
- Any file importing `github.com/ethereum/go-ethereum/core/state`
- Any file importing `github.com/ethereum/go-ethereum/ethdb`
- Any file importing `github.com/ethereum/go-ethereum/consensus`

## Dependency Replacement Strategy

### Dependencies we KEEP (import directly or vendor)
These are small, well-contained libraries:
- `github.com/holiman/uint256` — 256-bit integer math (used everywhere in EVM)
- `golang.org/x/crypto` — For blake2b, bn256, etc. used in precompiles
- Standard library `crypto/sha256`, `crypto/ecdsa`, `math/big`

### Dependencies we REPLACE with our own types

| geth package | Our replacement | Notes |
|---|---|---|
| `common.Address` | `pkg/types.Address` | `[20]byte` alias, same semantics |
| `common.Hash` | `pkg/types.Hash` | `[32]byte` alias, same semantics |
| `common.Big*` constants | `pkg/types` constants | `Big0`, `Big1`, `Big32`, etc. |
| `core/tracing` | `pkg/vm/tracing` | Simplified tracer hooks |
| `core/types.AccessList` | `pkg/types.AccessList` | Same struct, our package |
| `core/types.Log` | `pkg/types.Log` | Same struct, our package |
| `params.ChainConfig` | `pkg/vm.ChainConfig` | Simplified, L2-relevant fields only |
| `params.Rules` | `pkg/vm.Rules` | Which opcodes/features are active |
| `crypto.CreateAddress` | `pkg/crypto.CreateAddress` | Contract address derivation |
| `crypto.CreateAddress2` | `pkg/crypto.CreateAddress2` | CREATE2 address derivation |
| `crypto.Keccak256*` | `pkg/crypto.Keccak256*` | Keccak hashing |

### Key: the `params.ChainConfig` simplification

geth's `ChainConfig` contains dozens of hardfork block numbers for mainnet Ethereum. We replace it with a simplified config that just declares which EIP set is active:

```go
// pkg/vm/config.go
type ChainConfig struct {
    ChainID  *big.Int // L2 chain ID (pick a unique one, register on chainlist.org)
    
    // We target a fixed EIP set equivalent to latest Ethereum hardfork.
    // No need for per-block hardfork transitions on a new L2.
    // These booleans exist mainly for testing older EVM behaviors.
    HomesteadBlock      *big.Int // nil = always active
    EIP150Block         *big.Int
    EIP155Block         *big.Int
    EIP158Block         *big.Int
    ByzantiumBlock      *big.Int
    ConstantinopleBlock *big.Int
    PetersburgBlock     *big.Int
    IstanbulBlock       *big.Int
    BerlinBlock         *big.Int
    LondonBlock         *big.Int
    ShanghaiTime        *uint64
    CancunTime          *uint64
    PragueTime          *uint64
    // FusakaTime is nil (not active) in v1. Fusaka activates EOF
    // (EIP-7692), which is explicitly excluded from the initial release.
    // This field exists for forward compatibility — set it to nil.
    FusakaTime          *uint64
}

// DefaultL2Config returns a config with all hardforks active from genesis.
func DefaultL2Config(chainID int64) *ChainConfig {
    zero := big.NewInt(0)
    zeroTime := uint64(0)
    return &ChainConfig{
        ChainID:             big.NewInt(chainID),
        HomesteadBlock:      zero,
        EIP150Block:         zero,
        EIP155Block:         zero,
        EIP158Block:         zero,
        ByzantiumBlock:      zero,
        ConstantinopleBlock: zero,
        PetersburgBlock:     zero,
        IstanbulBlock:       zero,
        BerlinBlock:         zero,
        LondonBlock:         zero,
        ShanghaiTime:        &zeroTime,
        CancunTime:          &zeroTime,
        PragueTime:          &zeroTime,
        FusakaTime:          nil, // Fusaka/EOF not active in v1
    }
}

// Rules returns the active ruleset for a given block number and timestamp.
func (c *ChainConfig) Rules(num *big.Int, isMerge bool, timestamp uint64) Rules {
    // Implementation mirrors geth's params.ChainConfig.Rules()
    // but using our simplified config
}
```

## StateDB Interface (the critical seam)

This is the most important interface in the entire project. The EVM calls into `StateDB` for all state access. Our implementation (Phase 1b) backs this with our own MPT + LevelDB.

```go
// pkg/vm/statedb.go

type StateDB interface {
    // Account management
    CreateAccount(Address)
    CreateContract(Address)
    Exist(Address) bool
    Empty(Address) bool
    
    // Balance
    GetBalance(Address) *uint256.Int
    AddBalance(Address, *uint256.Int, BalanceChangeReason) uint256.Int
    SubBalance(Address, *uint256.Int, BalanceChangeReason) uint256.Int
    
    // Nonce
    GetNonce(Address) uint64
    SetNonce(Address, uint64, NonceChangeReason)
    
    // Code
    GetCode(Address) []byte
    SetCode(Address, []byte, CodeChangeReason) []byte // returns prev code
    GetCodeHash(Address) Hash
    GetCodeSize(Address) int
    
    // Storage
    GetState(Address, Hash) Hash
    GetCommittedState(Address, Hash) Hash
    SetState(Address, Hash, Hash) Hash // returns prev value
    GetStorageRoot(Address) Hash
    
    // Transient storage (EIP-1153)
    GetTransientState(Address, Hash) Hash
    SetTransientState(Address, Hash, Hash)
    
    // Self-destruct
    SelfDestruct(Address)
    HasSelfDestructed(Address) bool
    Selfdestruct6780(Address) // EIP-6780: only in same tx
    
    // Logs & refunds
    AddLog(*Log)
    AddRefund(uint64)
    SubRefund(uint64)
    GetRefund() uint64
    
    // Preimage recording
    AddPreimage(Hash, []byte)
    
    // Access list (EIP-2929)
    AddressInAccessList(Address) bool
    SlotInAccessList(Address, Hash) (addressPresent bool, slotPresent bool)
    AddAddressToAccessList(Address)
    AddSlotToAccessList(Address, Hash)
    
    // Snapshot & revert (for call frames)
    Snapshot() int
    RevertToSnapshot(int)
    
    // Prepare sets up access list for a new transaction
    Prepare(rules Rules, sender, coinbase Address, dest *Address, precompiles []Address, txAccess AccessList)
    
}

// NOTE: We do NOT include PointCache() in the StateDB interface. This was
// a geth-internal implementation detail for the EIP-4844 KZG precompile.
// The point cache is passed via the EVM Config instead — it is a
// precompile concern, not a state concern.
```

### Tracing Reason Enums

The StateDB interface uses typed reason parameters for balance, nonce,
and code changes. These mirror geth's `core/tracing` reason types:

```go
// pkg/vm/tracing/reasons.go

type BalanceChangeReason byte

const (
    BalanceChangeUnspecified     BalanceChangeReason = 0
    BalanceIncreaseRewardMineUncle BalanceChangeReason = 1
    BalanceIncreaseRewardMineBlock BalanceChangeReason = 2
    BalanceDecreaseSelfdestructBurn BalanceChangeReason = 3
    BalanceIncreaseDeposit       BalanceChangeReason = 4
    BalanceDecreaseWithdrawal    BalanceChangeReason = 5
    BalanceDecreaseGasBuy        BalanceChangeReason = 6
    BalanceIncreaseGasReturn     BalanceChangeReason = 7
    BalanceChangeTransfer        BalanceChangeReason = 8
    BalanceDecreaseSelfdestruct  BalanceChangeReason = 9
    BalanceIncreaseSelfdestruct  BalanceChangeReason = 10
    BalanceDecreaseTxFee         BalanceChangeReason = 11
    BalanceIncreaseTxFee         BalanceChangeReason = 12
)

type NonceChangeReason byte

const (
    NonceChangeUnspecified NonceChangeReason = 0
    NonceChangeTransaction NonceChangeReason = 1
)

type CodeChangeReason byte

const (
    CodeChangeUnspecified CodeChangeReason = 0
    CodeChangeCreation    CodeChangeReason = 1
    CodeChangeSelfdestruct CodeChangeReason = 2
)
```

These enums are for tracing/debugging. The StateDB implementation
should propagate them to any active tracer. The EVM itself does not
branch on these values.

**Notes on divergences from geth's StateDB interface:**
- We omit `GetStateAndCommittedState` (only used internally in geth for gas calculation — we can handle this in our implementation).
- We omit `Finalise` / `IntermediateRoot` — these are called by the block processor, not the EVM itself. Our block engine calls them on our concrete StateDB type.
- We omit Verkle/witness-related methods — these are Ethereum-specific state proof mechanisms not needed for our L2.
- We keep the `tracing.*Reason` parameters but define our own simplified reason enums (see above).

**Interface vs concrete type**: The `vm.StateDB` interface contains
only methods called by the EVM during execution. Methods called by
the block executor (`SetTxContext`, `GetLogs`, `IntermediateRoot`,
`Finalise`, `Commit`) are on the concrete `state.StateDB` type, not
on the interface. This matches geth's design.

**Nonce timing**: The sender's nonce is incremented as the FIRST step of `StateTransition.execute()`, before any EVM code runs. This means `GetNonce(sender)` during execution returns the post-increment value. Contract address derivation uses `GetNonce(sender) - 1`.

## Cryptographic Primitives

**Curve**: secp256k1 (same as Ethereum and BSV)

**Sender recovery**: Standard Ethereum ECDSA recovery.
`ecrecover(hash, v, r, s) -> public_key -> last_20_bytes(keccak256(pubkey)) -> address`

**Supported signature schemes**:
- EIP-155 (replay protection via chain ID in v)
- EIP-2930 (typed transaction with access list, y-parity in v)
- EIP-1559 (dynamic fee, y-parity in v)

**Invalid signatures**: rejected with error before execution. Gas is
not consumed. The transaction is not included in the batch.

**EIP-191/712**: Not required for v1. Standard `eth_sign` and
`eth_signTypedData` are client-side operations; the L2 only needs
to verify transaction signatures, not arbitrary message signatures.
EIP-712 structured data is verified within smart contracts using
`ecrecover` — this works unchanged since the EVM precompile handles it.

## BlockContext and TxContext

The EVM needs environmental context. We define these to match geth but without the `state.AccessEvents` field:

```go
// pkg/vm/context.go

type BlockContext struct {
    CanTransfer CanTransferFunc
    Transfer    TransferFunc
    GetHash     GetHashFunc

    Coinbase    Address
    GasLimit    uint64
    BlockNumber *big.Int
    Time        uint64
    Difficulty  *big.Int // always 0 for our L2 (post-merge equivalent)
    BaseFee     *big.Int
    BlobBaseFee *big.Int // always 1 for our L2 (see note below)
    Random      *Hash
}

type TxContext struct {
    Origin     Address    // msg.sender of the original tx
    GasPrice   *big.Int   // effective gas price
    BlobHashes []Hash     // EIP-4844 (always empty for L2, but interface-compatible)
    BlobFeeCap *big.Int
}

type CanTransferFunc func(StateDB, Address, *uint256.Int) bool
type TransferFunc func(StateDB, Address, Address, *uint256.Int)
type GetHashFunc func(uint64) Hash
```

**BlobBaseFee**: Set to `big.NewInt(1)` (arbitrary minimum). This is not
computed via EIP-4844 blob gas math — blobs are not used on this L2. The
value 1 is chosen because 0 is invalid per the EIP-4844 specification.
Our L2 does not use blob transactions, but the `BLOBBASEFEE` opcode
(EIP-7516) must return a valid value. A nil value would cause a
nil-pointer dereference in the EVM. Contracts ported from L1 that
check `block.blobbasefee` will see 1.

**BlobHashes**: Always empty (`[]Hash{}`). Our L2 does not support
Type 3 blob transactions. The `BLOBHASH` opcode (EIP-4844) will return
`Hash{}` for any index, which matches Ethereum behavior when the index
is out of range.

## PREVRANDAO Derivation

The `BlockContext.Random` field (`*Hash`) provides the value returned by
the EVM's `PREVRANDAO` opcode (formerly `DIFFICULTY` post-merge). On
Ethereum mainnet, this comes from the beacon chain RANDAO. On our L2,
we derive it deterministically from BSV data:

```go
// Random = keccak256(BSVBlockHash || L2BlockNumber)
// where BSVBlockHash is the hash of the BSV block that contains the
// covenant UTXO being spent (i.e., the BSV block in which the previous
// covenant-advance transaction was mined). During live execution by the
// proposer, this is the BSV block height of the current covenant tip.
// During replay from BSV data, the BSV block hash is extracted from
// the batch data.
func deriveRandom(bsvBlockHash Hash, l2BlockNum uint64) *Hash {
    data := append(bsvBlockHash[:], big.NewInt(int64(l2BlockNum)).Bytes()...)
    h := crypto.Keccak256Hash(data)
    return &h
}
```

**Important**: This value is deterministic and predictable by any BSV
observer. It is NOT a secure source of randomness. This matches
Ethereum's PREVRANDAO, which is also biasable by validators. Contracts
requiring strong randomness should use a commit-reveal scheme or an
oracle, not `block.prevrandao`.

The `Random` value is included in the batch data encoding (see spec 11,
"Batch Data Encoding Format" — the `Random` field is part of the block
context fields in the OP_RETURN payload) so that nodes replaying from
BSV data compute the identical value. The proposer derives it at
execution time and embeds it in the batch; all other nodes use the
value from the batch data verbatim.

## EVM Construction

```go
// pkg/vm/evm.go — modified from geth

func NewEVM(blockCtx BlockContext, statedb StateDB, chainConfig *ChainConfig, config Config) *EVM {
    // Same as geth but using our types
}
```

## Precompiled Contracts

All standard Ethereum precompiles at addresses 0x01-0x0a should be included. Crypto dependencies:

| Precompile | Address | Crypto Dependency |
|---|---|---|
| ecRecover | 0x01 | `crypto/ecdsa` + `secp256k1` |
| SHA-256 | 0x02 | `crypto/sha256` |
| RIPEMD-160 | 0x03 | `golang.org/x/crypto/ripemd160` |
| Identity | 0x04 | none |
| Modexp | 0x05 | `math/big` |
| ecAdd | 0x06 | `bn256` (from geth's `crypto/bn256`) |
| ecMul | 0x07 | `bn256` |
| ecPairing | 0x08 | `bn256` |
| Blake2f | 0x09 | `golang.org/x/crypto/blake2b` |
| Point eval | 0x0a | `c-kzg-4844` or Go equivalent |

**Decision**: Implement the KZG point evaluation precompile (0x0a, EIP-4844)
using a pure-Go KZG library to avoid CGO dependencies. Use
`crate-crypto/go-kzg-4844` (pure Go, no CGO) or `protolambda/go-kzg`
(also pure Go). Do NOT use `ethereum/c-kzg-4844`'s Go bindings — those
wrap a C library via CGO, violating the zero-CGO requirement.
The trusted setup parameters (the SRS) are the same as Ethereum's —
the ceremony data is public and deterministic.

**Trusted setup loading**: The KZG trusted setup (~48MB JSON) is loaded
at node startup from `<datadir>/kzg-trusted-setup.json`. If the file
does not exist, the node downloads it from Ethereum's public ceremony
data repository on first run and caches it locally. The file's SHA256
hash is verified against a hardcoded expected value before use:

```go
// pkg/crypto/kzg.go

const (
    KZGTrustedSetupSHA256 = "..." // SHA256 of the canonical trusted setup JSON
    KZGTrustedSetupURL    = "https://ceremony.ethereum.org/trusted-setup.json"
)

func LoadKZGTrustedSetup(dataDir string) (*kzg.Context, error) {
    path := filepath.Join(dataDir, "kzg-trusted-setup.json")
    if _, err := os.Stat(path); os.IsNotExist(err) {
        if err := downloadAndVerify(KZGTrustedSetupURL, path, KZGTrustedSetupSHA256); err != nil {
            return nil, fmt.Errorf("KZG trusted setup download failed: %w", err)
        }
    }
    return kzg.NewContextFromFile(path)
}
```

**Verification process**: The SHA256 hash is copied from the official Ethereum KZG ceremony repository (`ethereum/kzg-ceremony`). The download MUST use HTTPS. Nodes verify the hash on first startup; if verification fails, the node refuses to start. The hash value in source code is reviewed during code audit.

The KZG context is passed to the point evaluation precompile via the
EVM `Config` struct, not via `StateDB` (see "StateDB Interface" note
about `PointCache`).

Our L2 doesn't use blob transactions natively (data goes to BSV), but
contracts deployed on the L2 must be able to call this precompile and
get correct results. Full EVM compatibility means no missing precompiles.

**EVM version note**: We target the last pre-EOF stable geth release.
EOF (EVM Object Format, EIP-7692) is explicitly excluded from v1 — it
introduces RJUMP, CALLF, RETF opcodes and a container format that
significantly increases extraction scope. All other EIPs active in the
target geth release must be fully implemented — no partial support.
Document which geth tag was used in the repository README.

EOF support may be added in a future version via the protocol upgrade
mechanism (see spec 09, Milestone 10).

## Custom BSV Precompiles

We reserve precompile address range 0x80-0xFF for BSV-specific precompiles:

| Address | Name | Purpose |
|---|---|---|
| 0x80 | `BSV_VERIFY_TX` | Verify a BSV transaction proof (SPV) |
| 0x81 | `BSV_VERIFY_SCRIPT` | Verify a BSV script execution |
| 0x82 | `BSV_BLOCK_HASH` | Get a BSV block hash by height |

Interfaces are defined in Phase 1 (Milestone 1) alongside the standard
precompiles. Implementations are completed in Milestone 5 (Overlay Node)
when BSV connectivity is available. The interfaces must be complete from
the start so the EVM can route calls to these addresses.

**Before implementation (Milestones 1-4)**: Calls to BSV precompile
addresses (0x80-0xFF) revert with an error indicating the precompile
is not yet active. The precompile returns `(nil, ErrBSVPrecompileNotActive)`
and consumes all provided gas (matching Ethereum's behavior for failed
precompile calls). This ensures contracts that attempt BSV-specific
operations fail explicitly rather than returning incorrect data.

```go
var ErrBSVPrecompileNotActive = errors.New("BSV precompile not active")

// StubBSVPrecompile is used for BSV precompiles before their
// implementations are available.
type StubBSVPrecompile struct{}

func (s *StubBSVPrecompile) RequiredGas(input []byte) uint64 {
    return uint64(len(input)) // Consume proportional gas
}

func (s *StubBSVPrecompile) Run(input []byte) ([]byte, error) {
    return nil, ErrBSVPrecompileNotActive
}
```

**BSV Precompile Input/Output Formats** (reserved, not active in v1):

- **0x80 `BSV_VERIFY_TX`**: Input: `RLP(txBytes, blockHash, merkleProof)`. Output: `0x01` (valid) or revert.
- **0x81 `BSV_VERIFY_SCRIPT`**: Input: `RLP(scriptPubKey, scriptSig, flags)`. Output: `0x01` (valid) or revert.
- **0x82 `BSV_BLOCK_HASH`**: Input: `uint256(bsvBlockHeight)`. Output: `bytes32(blockHash)` or revert if unknown.

These are stubbed with `ErrBSVPrecompileNotActive` until the precompile milestone. The interfaces are defined here to allow contract developers to target them speculatively.

## Testing Strategy

### Primary: Ethereum VM Test Suite
Clone `github.com/ethereum/tests` and run the `VMTests` and `GeneralStateTests`:
- `VMTests/` — Low-level opcode tests
- `GeneralStateTests/` — Full transaction execution tests

We must pass 100% of tests for the hardfork level we target.

### Secondary: Differential testing against geth
For any given transaction input + state, our EVM must produce identical:
- Return data
- Gas used
- State changes (storage writes, balance changes, nonce changes)
- Logs emitted
- Error conditions

### Implementation
```go
// test/evmtest/runner.go

type TestRunner struct {
    evm *vm.EVM
    stateDB *state.MemoryStateDB // in-memory StateDB for testing
}

func (r *TestRunner) RunVMTest(test VMTest) error {
    // 1. Set up pre-state from test fixture
    // 2. Execute transaction
    // 3. Compare post-state against expected
    // 4. Compare gas used, logs, return data
}
```

## Deliverables

1. `pkg/vm/` — Complete extracted EVM package, compiles independently
2. `pkg/types/` — Shared types (Address, Hash, Log, AccessList, etc.)
3. `pkg/crypto/` — Keccak256, CreateAddress, CreateAddress2, secp256k1 wrappers
4. `test/evmtest/` — Test runner that passes ethereum/tests VMTests
5. `go.mod` with minimal dependencies (uint256, x/crypto, and standard library)

## Acceptance Criteria

- [ ] `go build ./pkg/vm/...` succeeds with zero geth imports
- [ ] All ethereum/tests `VMTests` pass
- [ ] All ethereum/tests `GeneralStateTests` for target hardfork pass (excluding tests that require full block/consensus context)
- [ ] `go vet` and `golangci-lint` pass
- [ ] No CGO dependencies in core EVM (use pure-Go KZG for point evaluation precompile)
