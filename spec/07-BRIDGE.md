# Phase 6: BSV ↔ L2 Bridge

## Goal
Enable users to move value between BSV (L1) and the EVM L2. Deposits lock BSV in a bridge UTXO and mint equivalent balance on L2. Withdrawals burn L2 balance and release BSV from the bridge.

Deposits go to a specific shard. The bridge covenant UTXO is per-shard.
The user locks BSV in shard A's bridge covenant, and shard A credits the
user's L2 address.

## Bridge Model

We use a **lock-and-mint / burn-and-release** model:

```
DEPOSIT (BSV → L2):
  1. User sends BSV to the shard's bridge covenant with a deposit memo
  2. Any shard node detects the deposit on BSV
  3. Deposit is included as a system transaction in the next L2 block
  4. User's L2 address is credited with equivalent wBSV balance

WITHDRAWAL (L2 → BSV):
  1. User calls the bridge contract on L2 (or sends a special L2 tx)
  2. L2 balance is burned
  3. After confirmation period, bridge releases BSV to user's BSV address
  4. Release tx is posted to BSV
```

## Native Token: wBSV

The L2's native gas token is **wBSV** (wrapped BSV). It represents BSV locked in the bridge 1:1.

**Key decision**: wBSV is the native token used for gas, not an ERC-20. It behaves exactly like ETH does on Ethereum — it's what `msg.value` transfers, what `address.balance` returns, and what gas fees are paid in. This means existing Solidity contracts that use `payable` and `msg.value` work without modification.

The ERC-20 representation (for DeFi composability) is deployed as a separate wrapper contract, similar to WETH on Ethereum.

```
1 wBSV (L2 native) = 1 BSV (locked on L1)
1 wBSV = 100,000,000 satoshis (same as BSV)
```

The EVM uses 18 decimal places internally. We define: **1 wBSV = 10^18 wei equivalent** to match Ethereum tooling expectations. The bridge handles the conversion: 1 BSV (10^8 satoshis) = 10^18 L2 wei.

**Conversion factor**: 1 satoshi = 10^10 L2 wei.

wBSV is the native gas token within each shard. 1 wBSV = 1 BSV = 10^18 L2
wei. 1 satoshi = 10^10 L2 wei. This is per-shard — wBSV on Shard A is
independent of wBSV on Shard B (though both are backed 1:1 by BSV locked
in their respective bridge covenants).

## Deposit Flow (detailed)

### Step 1: User creates BSV deposit transaction

The user sends BSV to a specific bridge address. The output script includes the user's L2 (Ethereum-format) address in an OP_RETURN:

```
BSV Deposit Transaction:
  Input:  User's BSV UTXOs
  Output 0: <shard_bridge_covenant> <deposit_amount>
  Output 1: OP_RETURN "BSVM" 0x03 <shard_id> <l2_address>
  Output 2: Change back to user's BSV address (optional)
```

The bridge covenant is compiled by Rúnar (spec 10, `contracts/bridge.go`).

Message type `0x03` = deposit.

### Step 2: Bridge monitor detects deposit

```go
// pkg/bridge/monitor.go

type BridgeMonitor struct {
    bsvClient    BSVClient
    bridgeCovenant *CompiledCovenant  // Rúnar-compiled bridge covenant
    chainDB      block.ChainDB
    overlay      *overlay.OverlayNode
    db           db.Database          // Persists deposit tracking state
    
    // Confirmation requirement
    confirmations int // Default: 6 BSV blocks
    
    // Track processed deposits to prevent double-credit.
    // Persisted to db on every deposit credit (same WriteBatch as the
    // L2 block write). On startup, loaded from db via LoadProcessedDeposits().
    // Key format: "d" + depositBSVTxID (33 bytes). Value: empty.
    processedDeposits map[Hash]bool
}

// LoadProcessedDeposits reads the persisted deposit set from the database.
// Called during node startup before the BridgeMonitor begins processing.
func (m *BridgeMonitor) LoadProcessedDeposits() error {
    // Iterate all keys with prefix "d" in the database
    // Populate m.processedDeposits from persisted state
}

// PersistDeposit writes a deposit txid to the database. Called in the
// same WriteBatch as the L2 block that credits the deposit, ensuring
// atomicity: if the block write succeeds, the deposit is marked as
// processed; if it fails, neither is persisted.
func (m *BridgeMonitor) PersistDeposit(depositTxID Hash, batch db.Batch) {
    key := append([]byte("d"), depositTxID[:]...)
    batch.Put(key, nil)
}

func (m *BridgeMonitor) Run(ctx context.Context) error {
    blockCh, err := m.bsvClient.SubscribeNewBlocks(ctx)
    if err != nil {
        return err
    }
    
    for {
        select {
        case <-ctx.Done():
            return nil
        case bsvBlock := <-blockCh:
            m.processBlock(bsvBlock)
        }
    }
}

func (m *BridgeMonitor) processBlock(bsvBlock *BSVBlock) {
    for _, tx := range bsvBlock.Transactions {
        deposit := m.parseDeposit(tx)
        if deposit == nil {
            continue
        }
        
        // Check confirmations
        if bsvBlock.Height - deposit.BlockHeight < uint64(m.confirmations) {
            // Queue for later processing
            m.pendingDeposits = append(m.pendingDeposits, deposit)
            continue
        }
        
        // Credit the L2 account
        m.creditDeposit(deposit)
    }
    
    // Check pending deposits that may now have enough confirmations
    m.processPendingDeposits(bsvBlock.Height)
}

type Deposit struct {
    BSVTxID     Hash
    BSVBlockHeight uint64
    L2Address   Address
    Amount      *big.Int // In satoshis
    Confirmed   bool
}

func (m *BridgeMonitor) creditDeposit(dep *Deposit) {
    // Convert satoshis to L2 wei
    // 1 satoshi = 10^10 L2 wei
    l2Amount := new(uint256.Int).Mul(
        new(uint256.Int).SetUint64(dep.Amount.Uint64()),
        new(uint256.Int).SetUint64(1e10),
    )
    
    // Create a system deposit transaction on L2.
    // This is a special tx type included by any node processing deposits.
    depositTx := &DepositTransaction{
        SourceHash:  dep.BSVTxID,
        From:        BridgeSystemAddress, // 0x0000...dead or similar
        To:          dep.L2Address,
        Value:       l2Amount,
        IsSystemTx:  true,
    }
    
    // Submit to overlay node for inclusion in next block
    m.overlay.SubmitSystemTx(depositTx)
}
```

### Step 3: Deposit included in L2 block

The overlay node includes the deposit as the first transaction(s) in the
next block. System transactions are included before user transactions.

#### Deposit Determinism Protocol

For deposits to be deterministic across all nodes in a multi-node shard,
all nodes must agree on WHICH deposits to include in each L2 block. This
requires strict rules:

1. **Deposit horizon**: Each L2 block has a "BSV deposit horizon" — a BSV
   block height. All deposits from BSV blocks at or below the horizon that
   have not yet been credited on L2 MUST be included in this block. The
   horizon is chosen by the proposing node and embedded in the batch data
   (see spec 11, "Batch Data Encoding Format", the `BSV deposit horizon`
   field).

2. **Eligibility rule**: A deposit from BSV block at height H is eligible
   for inclusion in an L2 block whose deposit horizon >= H + `confirmations`
   (default: 6). This ensures the BSV deposit tx has sufficient
   confirmations before being credited on L2.

3. **Deterministic ordering**: Eligible deposits are included in a
   canonical order: sorted by (BSV block height ASC, BSV tx index ASC,
   output index ASC). This ensures all nodes produce the same deposit
   list for the same horizon.

4. **Monotonic horizon**: The deposit horizon must be >= the previous
   block's deposit horizon. It cannot go backwards.

5. **Replay determinism**: When a node replays a winner's batch (after
   losing a race), it extracts the deposit horizon from the batch data
   and includes exactly those deposits. The replaying node does NOT use
   its own view of BSV — it uses the proposer's horizon verbatim.

6. **Horizon staleness limit**: The deposit horizon must be within 3 BSV
   blocks of the proposer's observed BSV tip. A proposer cannot set an
   artificially low horizon to delay deposits indefinitely.

**Deposit horizon enforcement**: The overlay node validates the deposit horizon in `ValidateBatchProposal()`: `abs(depositHorizon - observedBSVTip) <= 3`. Batches with a stale deposit horizon are rejected before execution. The covenant does NOT enforce this check — it trusts the STARK proof, which commits to the deposit horizon as a public value. Honest verifying nodes reject batches with stale horizons during re-execution.

```go
type DepositInclusion struct {
    Horizon      uint64     // BSV block height: include all confirmed deposits up to here
    Confirmations int       // Required BSV confirmations (default: 6)
}

// EligibleDeposits returns all deposits that must be included in the
// next L2 block given the specified BSV deposit horizon.
func (m *BridgeMonitor) EligibleDeposits(horizon uint64, lastIncludedHorizon uint64) []*Deposit {
    var deposits []*Deposit
    for h := lastIncludedHorizon + 1; h <= horizon - uint64(m.confirmations); h++ {
        blockDeposits := m.depositsAtHeight(h) // sorted by tx index, output index
        deposits = append(deposits, blockDeposits...)
    }
    return deposits // deterministic: same horizon → same deposits
}
```

### System Transaction Execution Model

Deposit system transactions are NOT executed through the EVM. They
bypass the normal `StateTransition.execute()` path entirely. Instead,
the block executor applies them as direct state mutations:

```go
// pkg/block/system_tx.go

// ApplyDepositTx applies a deposit system transaction by directly
// mutating the StateDB. This bypasses the EVM entirely — no gas is
// bought, no gas is consumed, no gas is refunded, no Solidity code
// is executed.
//
// This follows the same pattern as Optimism's deposit transactions
// (OP Stack's `core/state_processor.go:applyTransaction` with
// `tx.IsDepositTx()` handling).
func ApplyDepositTx(statedb *state.StateDB, header *L2Header, tx *DepositTransaction) *Receipt {
    // 1. Ensure the recipient account exists
    if !statedb.Exist(tx.To) {
        statedb.CreateAccount(tx.To)
    }

    // Account initialization: If the deposit recipient address does not
    // exist, CreateAccount(addr) initializes it with nonce = 0,
    // balance = 0, codeHash = emptyCodeHash, storageRoot = emptyRoot.
    // The deposit amount is then added via AddBalance. Deposits to
    // existing accounts (including contracts) simply add to the existing
    // balance.

    // 2. Credit the deposit amount directly
    statedb.AddBalance(tx.To, tx.Value, tracing.BalanceIncreaseDeposit)

    // 3. Update the bridge contract's totalDeposited counter via direct
    //    storage mutation — NO EVM execution, NO Solidity call.
    //
    //    The totalDeposited field is at a well-known storage slot in the
    //    L2Bridge predeploy contract. The block executor writes to this
    //    slot directly, the same way it writes the recipient's balance.
    //    This ensures the deposit path is fully deterministic, cannot
    //    fail, cannot consume gas, and cannot interact with any contract.
    //
    //    Storage slot derivation:
    //    totalDeposited is a uint256 state variable at Solidity storage
    //    slot 4 in the L2Bridge contract. Storage layout:
    //      slot 0: withdrawals mapping
    //      slot 1: withdrawalHashes mapping
    //      slot 2: withdrawalNonce
    //      slot 3: (reserved — BLOCKS_PER_PERIOD and MAX_WITHDRAWAL_BPS are constants, not storage)
    //      slot 4: totalDeposited
    //      slot 5: totalWithdrawn
    //      slot 6: periodWithdrawals mapping
    //    The slot key is simply bytes32(uint256(4)).
    //
    //    This is a FIXED SLOT — it is part of the bridge predeploy's
    //    storage layout and must never change. Both the Go block executor
    //    and the SP1 guest program must use this exact slot.
    totalDepositedSlot := TotalDepositedStorageSlot // bytes32(uint256(4))
    currentTotal := statedb.GetState(BridgeContractAddress, totalDepositedSlot)
    newTotal := new(uint256.Int).Add(
        new(uint256.Int).SetBytes(currentTotal[:]),
        tx.Value,
    )
    var newTotalHash Hash
    newTotal.WriteToSlice(newTotalHash[:])
    statedb.SetState(BridgeContractAddress, totalDepositedSlot, newTotalHash)

    // 4. Create receipt (always successful — deposits cannot fail)
    receipt := &Receipt{
        Type:              DepositTxType,  // Type 126 (0x7E), matching Optimism convention
        Status:            ReceiptStatusSuccessful,
        CumulativeGasUsed: 0, // No gas consumed
        TxHash:            tx.Hash(),
        GasUsed:           0,
        Logs:              nil, // No EVM execution, no logs
        BlockNumber:       header.Number,
    }

    return receipt
}

// DepositTxType is the EIP-2718 transaction type for deposit system txs.
// Uses 0x7E (126), matching the Optimism deposit tx type convention.
const DepositTxType = 0x7E

// TotalDepositedStorageSlot is the fixed storage slot for the
// totalDeposited variable in the L2Bridge predeploy contract.
// Solidity storage slot 4 (uint256). This is a compile-time constant
// derived from the bridge contract's storage layout.
//
// DO NOT CHANGE THIS without updating the L2Bridge contract layout,
// the SP1 guest program, and the bridge rate-limiting logic.
var TotalDepositedStorageSlot = Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4} // bytes32(uint256(4))
```

**Why not use the EVM?** Setting Gas=0 on an EVM transaction would
cause an immediate out-of-gas error. Granting unlimited gas to a
system transaction is dangerous — a bug in the deposit path could
consume unbounded gas. The safest approach is to bypass the EVM
entirely and apply the deposit as direct state mutations. This:
- Cannot fail (no revert path, no Solidity execution)
- Cannot consume gas from the block's gas pool
- Cannot interact with other contracts (no reentrancy risk)
- Is trivially deterministic across all EVM implementations
- Matches the approach used by Optimism (the most battle-tested L2)

**Why direct storage mutation instead of a Solidity call?** An earlier
version of this spec called `L2Bridge.recordDeposit(amount)` as an EVM
call from `BridgeSystemAddress`. This was inconsistent: the receipt
claimed `GasUsed=0` and `Logs=nil`, but the EVM call consumed ~25K gas
and could potentially emit logs or trigger reentrancy. The direct
storage mutation is exactly what it claims to be — a pure state write
with no code execution. The rate-limit denominator (`totalDeposited`) is
kept in sync with actual deposits by a mechanism that is bit-for-bit
identical between the Go block executor and the SP1 guest program.

**SP1 guest handling**: The SP1 guest program (revm) must also handle
deposit system transactions identically — as direct state mutations,
NOT as EVM calls. The guest identifies deposit txs by the `0x7E` type
byte and:
1. Credits the recipient's balance directly via `db.insert_account_info()`
2. Writes to the bridge contract's `totalDeposited` storage slot
   (`bytes32(uint256(4))`) directly via `db.insert_account_storage()`,
   incrementing the current value by the deposit amount.

No Solidity code is executed. No `recordDeposit()` function is called.
Both the Go EVM and the Rust revm guest must produce identical state
roots for deposit-only blocks. The direct storage write ensures this
by eliminating all code execution from the deposit path.

### Deposit Transaction Encoding (Type 0x7E)

Deposit system transactions use EIP-2718 typed transaction envelope
with type byte `0x7E` (126), matching the Optimism deposit tx convention.
The RLP encoding is:

```
0x7E || RLP([sourceHash, from, to, value, gas, isSystemTx, data])
```

| Field | Type | Description |
|-------|------|-------------|
| `sourceHash` | `bytes32` | BSV deposit txid (the BSV transaction that locked BSV in the bridge covenant) |
| `from` | `address` | `BridgeSystemAddress` (`0x000...dEaD`) — the system sender |
| `to` | `address` | Recipient L2 address (from the deposit OP_RETURN) |
| `value` | `uint256` | Deposit amount in L2 wei (satoshis × 10^10) |
| `gas` | `uint64` | Always 0 — deposits bypass the EVM and consume no gas |
| `isSystemTx` | `bool` | Always `true` |
| `data` | `bytes` | Empty (`0x`) |

**Deposit transactions have no signature.** They are not signed by any
private key — they are synthesized by the overlay node based on observed
BSV deposits. The `sourceHash` (BSV txid) serves as a unique identifier
for deduplication.

**Batch data encoding**: Deposit transactions appear in the batch data
RLP transaction list like any other transaction, with the `0x7E` type
prefix. The SP1 guest program identifies them by the type byte and
handles them as direct balance credits (see "Deposit System Transaction
Handling in SP1 Guest" in Spec 12).

```go
// pkg/types/deposit_tx.go

type DepositTransaction struct {
    SourceHash  Hash      // BSV deposit txid
    From        Address   // BridgeSystemAddress
    To          Address   // Recipient L2 address
    Value       *uint256.Int // Amount in L2 wei
    Gas         uint64    // Always 0
    IsSystemTx  bool      // Always true
    Data        []byte    // Empty
}

const DepositTxType = 0x7E

// Hash returns keccak256(0x7E || RLP([sourceHash, from, to, value, gas, isSystemTx, data]))
func (tx *DepositTransaction) Hash() Hash {
    return rlpHash(tx)
}
```

## Withdrawal Flow (detailed)

### Step 1: User initiates withdrawal on L2

The user sends a transaction to the bridge contract (or a special withdrawal address):

```solidity
// Bridge contract on L2 (deployed at a fixed address, e.g., 0x4200...0010)
contract L2Bridge {
    event WithdrawalInitiated(
        address indexed sender,
        bytes20 bsvAddress,
        uint256 amount,     // In L2 wei (satoshi-aligned, divisible by 1e10)
        uint256 nonce
    );

    // Dead address where burned wBSV is sent. This address has no
    // private key, so the wBSV is permanently irrecoverable on L2.
    address constant BURN_ADDRESS = address(0x000000000000000000000000000000000000dEaD);
    
    mapping(uint256 => Withdrawal) public withdrawals;
    // Withdrawal hash: hash256(bsvAddress || satoshiAmount_uint64_be || nonce_uint64_be).
    // This hash is committed by the SP1 guest program into a SHA256 Merkle
    // tree of all withdrawals in the batch. The bridge covenant on BSV
    // verifies withdrawal existence via a SHA256 Merkle inclusion proof
    // against the withdrawalRoot in the STARK proof's public values.
    // No Keccak-256 or MPT verification is needed in Bitcoin Script —
    // the STARK proof covers the full EVM execution that produced the hash.
    //
    // IMPORTANT: The hash uses uint64 for the satoshi amount and nonce,
    // NOT uint256. This matches the Rúnar bridge covenant which operates
    // on uint64 values (sufficient for satoshi amounts up to 2^64-1).
    // The Solidity contract converts from uint256 L2 wei to uint64 satoshis
    // before hashing.
    mapping(uint256 => bytes32) public withdrawalHashes;
    uint256 public withdrawalNonce;
    
    // --- Rate limiting ---
    // Prevents draining >10% of locked BSV per period (~24 hours of L2 blocks).
    // Period length is denominated in L2 block numbers, not BSV blocks,
    // because the Solidity contract only has access to block.number.
    uint256 public constant BLOCKS_PER_PERIOD = 8640;          // ~24h at ~10s/block
    uint256 public constant MAX_WITHDRAWAL_BPS = 1000;         // 10% in basis points
    uint256 public totalDeposited;                             // cumulative deposits (L2 wei) — slot 4, written by block executor
    uint256 public totalWithdrawn;                             // cumulative withdrawals (L2 wei) — slot 5, updated by withdraw()
    mapping(uint256 => uint256) public periodWithdrawals;      // period => cumulative withdrawn (L2 wei)

    // totalDeposited is updated by the block executor via DIRECT STORAGE
    // MUTATION during deposit processing — NOT via a Solidity function call.
    // The executor writes to storage slot 4 (this variable's slot) directly,
    // bypassing the EVM entirely. This ensures deposit processing is
    // deterministic, gas-free, and cannot fail.
    //
    // DO NOT add a recordDeposit() function. The totalDeposited slot is
    // written by the block executor and SP1 guest program, not by Solidity.
    // See spec 07, "System Transaction Execution Model" for details.

    address constant BRIDGE_SYSTEM_ADDRESS = address(0x000000000000000000000000000000000000dEaD);

    function currentPeriod() internal view returns (uint256) {
        return block.number / BLOCKS_PER_PERIOD;
    }

    function withdraw(bytes20 bsvAddress) external payable {
        require(msg.value > 0, "Must send wBSV");
        // Enforce satoshi alignment: 1 satoshi = 10^10 L2 wei.
        // Amounts not divisible by 10^10 cannot be converted to whole
        // satoshis on BSV. Reject to prevent dust loss.
        require(msg.value % 1e10 == 0, "Amount must be satoshi-aligned");

        // Rate limit: no more than 10% of total deposited per period
        uint256 period = currentPeriod();
        uint256 maxPerPeriod = (totalDeposited * MAX_WITHDRAWAL_BPS) / 10000;
        require(
            periodWithdrawals[period] + msg.value <= maxPerPeriod,
            "Withdrawal rate limit exceeded"
        );
        periodWithdrawals[period] += msg.value;

        // Convert L2 wei to satoshis for the withdrawal hash.
        // This must match the Rúnar bridge covenant's hash computation.
        uint64 satoshiAmount = uint64(msg.value / 1e10);
        require(uint256(satoshiAmount) * 1e10 == msg.value, "Amount overflow");
        
        uint256 nonce = withdrawalNonce++;
        uint64 nonce64 = uint64(nonce);
        require(uint256(nonce64) == nonce, "Nonce overflow");

        withdrawals[nonce] = Withdrawal({
            sender: msg.sender,
            bsvAddress: bsvAddress,
            amount: msg.value,
            timestamp: block.timestamp,
            finalized: false
        });
        
        // Store withdrawal hash in contract storage.
        // Uses abi.encodePacked with bytes20 + uint64 + uint64 to match
        // the Rúnar bridge covenant's hash computation exactly:
        //   hash256(bsvAddr || uint64_be(satoshiAmount) || uint64_be(nonce))
        // hash256 = SHA256(SHA256(data)), matching BSV's OP_HASH256.
        //
        // The SP1 guest program reads this hash from contract storage after
        // execution and includes it in the batch's withdrawal Merkle tree.
        // The tree root is committed as a STARK public value. The bridge
        // covenant verifies withdrawal inclusion via a SHA256 Merkle proof
        // against that root — no Keccak-256 or MPT verification in Script.
        withdrawalHashes[nonce] = sha256(abi.encodePacked(
            sha256(abi.encodePacked(bsvAddress, satoshiAmount, nonce64))
        ));
        
        totalWithdrawn += msg.value;

        emit WithdrawalInitiated(msg.sender, bsvAddress, msg.value, nonce);
        
        // Burn the wBSV by sending to an unrecoverable dead address.
        // This is a true burn — the balance moves to BURN_ADDRESS which
        // has no private key. It does NOT accumulate in this contract.
        payable(BURN_ADDRESS).transfer(msg.value);
    }
}
```

**Withdrawal hash encoding consistency**: The Solidity contract and the
Rúnar bridge covenant MUST compute identical hashes for the same
withdrawal. Both use hash256 (double-SHA256):
`hash256(bsvAddress_bytes20 || satoshiAmount_uint64_be || nonce_uint64_be)`.
In Solidity: `sha256(abi.encodePacked(sha256(abi.encodePacked(bsvAddress, satoshiAmount, nonce64))))`.
In Rúnar: `m.Hash256(m.Cat(bsvAddr, m.Uint64ToBytes(amount), m.Uint64ToBytes(nonce)))`.
The Solidity contract converts from L2 wei (uint256) to satoshis (uint64)
before hashing. The Rúnar covenant receives satoshi amounts directly.
This alignment is critical — a mismatch means withdrawals cannot be verified.

**Gas cost note**: The `withdraw()` function calls `sha256` twice (hash256).
The SHA-256 precompile (0x02) costs 60 base + 12 per 32-byte word. For the
36-byte input: inner hash costs 60 + 24 = 84 gas; outer hash costs 60 + 12 =
72 gas. Total hash cost: ~156 gas — negligible. The `withdraw()` function's
total gas cost is dominated by storage writes (`withdrawals` and
`withdrawalHashes` mappings: ~40,000 gas for two SSTORE operations).
The `transfer` to BURN_ADDRESS adds ~2,300 gas. Total estimated gas for
`withdraw()`: ~65,000 gas. This is well within the block gas limit.

### Step 2: Proof-verified withdrawal (no challenge period)

Since every covenant advance requires a STARK proof that the state
transition is correct, there is **no challenge period**. The STARK
proof's public values include a `withdrawalRoot` — the SHA256 Merkle
root of all withdrawal hashes produced in the batch. The SP1 guest
program detects `WithdrawalInitiated` events, reads the corresponding
`withdrawalHashes[nonce]` values from contract storage, and builds
a SHA256 Merkle tree committed as a public value. The bridge covenant
verifies withdrawal inclusion against this root using only SHA256
(native BSV opcode). No Keccak-256 or Ethereum MPT verification is
needed in Bitcoin Script — the STARK proof covers the full EVM
execution that produced the withdrawal hashes.

```go
type WithdrawalConfig struct {
    MinWithdrawal uint64           // Minimum withdrawal in satoshis
    Tiers         []WithdrawalTier // Confirmation tiers by amount
}

type WithdrawalTier struct {
    MaxAmount     uint64 // In satoshis. math.MaxUint64 for the final tier.
    Confirmations int    // BSV confirmations required
    // No GuardianFreeze field — the bridge is strictly trustless with
    // no guardian keys, no multisig, and no freeze capability.
}

var DefaultTiers = []WithdrawalTier{
    {MaxAmount: 1_000_000_000, Confirmations: 6},     // <=10 BSV
    {MaxAmount: 10_000_000_000, Confirmations: 20},    // <=100 BSV
    {MaxAmount: math.MaxUint64, Confirmations: 100},   // >100 BSV
}
```

The confirmation tiers ensure the covenant-advance tx containing
the withdrawal is confirmed in BSV before releasing funds. This
protects against BSV reorgs, not against invalid state transitions (which
the proof already prevents). Larger withdrawals require more confirmations.

### Bridge Confirmation Enforcement via CSV

The bridge covenant does NOT check BSV confirmation depth internally —
it delegates confirmation enforcement to Bitcoin's native
`OP_CHECKSEQUENCEVERIFY` (CSV) mechanism. When the bridge covenant
creates a withdrawal output (paying the user), it sets a relative
timelock on that output matching the withdrawal tier. The user can
only spend their withdrawal UTXO after the timelock expires.

This is cleaner than trying to check BSV block height within the
covenant script, because CSV is enforced by BSV miners at the
consensus level — it cannot be bypassed.

```go
// In pkg/covenant/contracts/bridge.go — withdraw method output construction

// Determine the CSV delay from the withdrawal tier
func csvDelayForAmount(amount uint64, tiers []WithdrawalTier) uint32 {
    for _, tier := range tiers {
        if amount <= tier.MaxAmount {
            return uint32(tier.Confirmations)
        }
    }
    return uint32(tiers[len(tiers)-1].Confirmations)
}

// The bridge covenant enforces a CSV-locked withdrawal output:
c.Method("withdraw", func(m *runar.MethodBuilder) {
    // ... (proof verification, nonce check, Merkle inclusion — as above)

    amount := m.Param("amount", runar.Uint64)

    // Determine CSV delay based on withdrawal tier.
    // The delay is provided as a parameter and verified against
    // the tier thresholds in Script:
    csvDelay := m.Param("csvDelay", runar.Uint32)
    m.Require(
        m.Or(
            m.And(m.LessOrEqual(amount, runar.Uint64Literal(1_000_000_000)),
                  m.Equal(csvDelay, runar.Uint32Literal(6))),
            m.And(m.LessOrEqual(amount, runar.Uint64Literal(10_000_000_000)),
                  m.Equal(csvDelay, runar.Uint32Literal(20))),
            m.Equal(csvDelay, runar.Uint32Literal(100)),
        ),
        "CSV delay must match withdrawal tier",
    )

    // Output 0: payment to user's BSV address with CSV timelock.
    // The output script is: <csvDelay> OP_CHECKSEQUENCEVERIFY OP_DROP
    // followed by a standard P2PKH script for the user's BSV address.
    // The user cannot spend this output until <csvDelay> BSV blocks
    // have been mined after the withdrawal tx is confirmed.
    csvScript := m.Cat(
        m.CSVPrefix(csvDelay), // <delay> OP_CSV OP_DROP
        m.P2PKH(bsvAddr),     // standard P2PKH
    )
    m.RequireOutput(0, csvScript, amount)

    // ... (state update, RequireStateOutput — as above)
})
```

**Why CSV instead of in-script height checking?** `OP_CHECKSEQUENCEVERIFY`
is enforced by BSV miners at the consensus level. A transaction spending
the CSV-locked output before the timelock expires is invalid — miners
reject it. This is strictly stronger than any in-script check, which
could be circumvented by a miner willing to include the transaction.
CSV is the canonical Bitcoin mechanism for relative timelocks.

### Step 3: Bridge covenant releases BSV

The bridge covenant is a separate Rúnar contract that releases BSV when
presented with proof that a withdrawal event exists in the state covenant.
**There is no bridge operator key.** The bridge covenant is proof-authorized,
just like the state covenant.

### Withdrawal Claim Lifecycle

A withdrawal moves through four phases: initiation (L2), proving (SP1),
claiming (BSV), and spending (BSV after CSV timelock).

#### Phase 1: L2 Initiation

The user calls `L2Bridge.withdraw()` on L2. This burns wBSV, stores a
`withdrawalHash` in contract storage, emits `WithdrawalInitiated`, and
increments the bridge's `withdrawalNonce`. The nonce is assigned
sequentially starting from 0.

#### Phase 2: Proving

The SP1 guest program detects the `WithdrawalInitiated` event, reads
the `withdrawalHashes[nonce]` value from bridge contract storage, and
includes it in a SHA256 Merkle tree committed as `withdrawalRoot` in
the STARK proof's public values. The `withdrawalRoot` is also embedded
in the OP_RETURN batch data of the covenant-advance BSV transaction.

#### Phase 3: Claiming (BSV transaction)

**Who broadcasts**: The user (or any relayer acting on the user's
behalf) constructs and broadcasts the BSV withdrawal-claim transaction.
The overlay node provides a convenience API (`bsv_buildWithdrawalClaim`)
that returns the unsigned BSV transaction and the required Merkle proof,
but any party with the withdrawal details can construct it independently
from BSV data. There is no privileged claimer — the withdrawal proof is
public and the bridge covenant is permissionless.

**Claim transaction structure**:

```
BSV Withdrawal Claim Transaction:
  Input 0:  bridge covenant UTXO (authorized by withdrawal proof in unlocking script)
  Input 1:  fee-funding UTXO (pays BSV miner fee — from claimer's wallet)
  Output 0: new bridge covenant UTXO (balance reduced by withdrawal amount)
  Output 1: user's BSV address with CSV timelock (withdrawal amount)
  Output 2: claimer's fee change (if any)
  Output 3: OP_RETURN withdrawal receipt (nonce, amount, bsvAddress)
```

The unlocking script for Input 0 contains:
- `amount` (uint64): withdrawal amount in satoshis
- `bsvAddress` (bytes20): recipient's BSV P2PKH address
- `nonce` (uint64): withdrawal nonce from L2 bridge contract
- `withdrawalProof` ([]bytes32): SHA256 Merkle authentication path
- `withdrawalRoot` (bytes32): the root from the batch's STARK public values
- `refOutputScript` (bytes): the state covenant's output script from the
  referenced covenant-advance tx (for cross-covenant verification)
- `refOpReturn` (bytes): the OP_RETURN data from the referenced tx
- `csvDelay` (uint32): CSV delay in blocks (must match withdrawal tier)
- `sighashPreimage` (bytes): for OP_PUSH_TX output enforcement

**Nonce deduplication — sequential claiming**: The bridge covenant state
includes `lastClaimedNonce` (uint64). Withdrawals MUST be claimed in
strict sequential order — the next claim must present nonce
`lastClaimedNonce + 1`. This prevents double-claiming without requiring
a bitmap or set in covenant state (which would grow unboundedly).

Sequential claiming means:
- Withdrawal nonce 0 must be claimed first, then 1, then 2, etc.
- If nonce 5 is ready but nonces 3 and 4 haven't been claimed yet,
  nonce 5 must wait
- The overlay node's `Withdrawer` processes claims in nonce order
- Any user can claim any nonce (it's permissionless), but the bridge
  covenant rejects out-of-order nonces

This is a deliberate trade-off: sequential ordering simplifies the
covenant state (a single uint64 counter) at the cost of potential
head-of-line blocking. In practice, the overlay node processes claims
automatically in order, so blocking is rare.

**Stuck withdrawal recovery**: If a withdrawal at nonce N cannot be
claimed (e.g., insufficient bridge balance, BSV fee wallet empty),
subsequent withdrawals are blocked. Recovery options:

1. **Top up the bridge**: Deposit additional BSV to cover the stuck
   withdrawal amount. The bridge balance increases and the claim can
   proceed.
2. **Wait for fee wallet replenishment**: If the prover's BSV fee
   wallet is empty, wait for the bridge withdrawal replenishment
   cycle (prover withdraws wBSV → BSV via bridge).
3. **External claim**: Any party can construct and broadcast the
   claim transaction from public BSV data — the stuck node does not
   need to be the claimer (see "Withdrawal claim construction by
   relayer" above).

If a withdrawal remains stuck for > 1000 BSV blocks (~7 days), the
overlay node logs a critical alert. The bridge covenant has no
automatic skip mechanism — sequential ordering is a hard constraint
that prevents double-claiming without unbounded state. A future v2
with sub-covenant sharding could partition nonces to reduce the
blast radius of stuck withdrawals.

**Withdrawal claim construction by relayer**: Any party can construct
the claim transaction from public BSV data:
1. Read the bridge covenant UTXO (by scanning for the bridge script hash)
2. Read the covenant-advance tx that contains the withdrawal batch
   (walk the state covenant UTXO chain on BSV)
3. Extract the `withdrawalRoot` from the OP_RETURN batch data
4. Compute the SHA256 Merkle inclusion proof for the withdrawal hash
5. Build and broadcast the claim transaction

No L2 node interaction is required. This ensures withdrawals can be
claimed even if all shard nodes are offline — BSV data alone is
sufficient.

```go
// pkg/bridge/withdrawer.go

type Withdrawer struct {
    bsvClient       BSVClient
    bridgeUTXO      *BridgeUTXO        // Tracks the single bridge covenant UTXO
    stateCovenant   *covenant.CovenantManager
    feeWallet       *covenant.FeeWallet
    chainDB         block.ChainDB
    config          WithdrawalConfig
}

func (w *Withdrawer) ProcessFinalizedWithdrawals() error {
    // 1. Scan L2 blocks for WithdrawalInitiated events in nonce order
    pendingWithdrawals := w.scanPendingWithdrawals()

    for _, wd := range pendingWithdrawals {
        // 2. Check BSV confirmations (reorg protection, NOT challenge period)
        if !w.hasRequiredConfirmations(wd) {
            break // Stop processing — later nonces also blocked
        }

        // 3. Verify sufficient balance in the bridge covenant
        if wd.AmountSatoshis > w.bridgeUTXO.Balance {
            slog.Error("insufficient balance in bridge covenant",
                "amount", wd.AmountSatoshis, "balance", w.bridgeUTXO.Balance)
            break
        }

        // 4. Verify this is the next nonce
        if wd.Nonce != w.bridgeUTXO.LastClaimedNonce + 1 {
            slog.Warn("withdrawal nonce not sequential — skipping",
                "expected", w.bridgeUTXO.LastClaimedNonce+1, "got", wd.Nonce)
            continue
        }

        // 5. Locate the covenant-advance BSV tx containing this withdrawal.
        //    Extract the withdrawalRoot from its OP_RETURN batch data.
        advanceTx, err := w.findCovenantAdvanceForBlock(wd.L2BlockNum)
        if err != nil {
            return fmt.Errorf("cannot find covenant advance for block %d: %w", wd.L2BlockNum, err)
        }
        withdrawalRoot := extractWithdrawalRoot(advanceTx.Outputs[1].Script)

        // 6. Build SHA256 Merkle inclusion proof for this withdrawal
        merkleProof := w.buildWithdrawalMerkleProof(wd, withdrawalRoot)

        // 7. Build the BSV claim transaction
        claimTx, err := w.buildClaimTx(w.bridgeUTXO, wd, merkleProof, withdrawalRoot, advanceTx)
        if err != nil {
            return fmt.Errorf("claim tx build failed for nonce %d: %w", wd.Nonce, err)
        }

        // 8. Broadcast to BSV
        txid, err := w.bsvClient.Broadcast(claimTx)
        if err != nil {
            return fmt.Errorf("claim broadcast failed for nonce %d: %w", wd.Nonce, err)
        }

        slog.Info("withdrawal claimed",
            "nonce", wd.Nonce,
            "amount", wd.AmountSatoshis,
            "bsvTx", txid,
        )

        // 9. Update bridge UTXO tracking
        w.bridgeUTXO.UpdateAfterWithdrawal(txid, wd.AmountSatoshis, wd.Nonce)
    }

    return nil
}
```

#### Phase 4: Spending (after CSV timelock)

The claim transaction's Output 1 pays the user's BSV address with a
CSV timelock. The user cannot spend these satoshis until the timelock
expires (6/20/100 BSV blocks depending on the tier). After the timelock,
the user spends the output with a standard P2PKH signature — no covenant
interaction required.

**Stranded withdrawal recovery**: If a withdrawal is finalized on L2
(wBSV burned, event emitted) but the bridge covenant fails to release
BSV (e.g., proof verification failure in the bridge script), the
withdrawal remains claimable indefinitely. The user can re-submit the
withdrawal proof to the bridge covenant at any time — there is no
expiration. The withdrawal hash persists in the batch's withdrawalRoot
permanently on BSV.

#### Withdrawal Claiming Concurrency

Withdrawal claims are sequential — each claim spends the current bridge
covenant UTXO and creates a new one with reduced balance. Two claims
cannot be broadcast simultaneously (the second would double-spend the
bridge UTXO). The overlay node's `Withdrawer` processes claims one at
a time, in strict nonce order.

At the target throughput (128 EVM txs per batch, ~2s batch interval),
withdrawal claiming latency is bounded by BSV transaction propagation
time (~1-2 seconds per claim). This supports ~30-60 withdrawal claims
per minute, which is sufficient for v1.

### Bridge Covenant Contract (Rúnar)

The bridge covenant is compiled by Rúnar alongside the state covenant.

```go
// pkg/covenant/contracts/bridge.go

func BridgeContract(stateCovenantScript []byte, gov GovernanceConfig) *runar.Contract {
    c := runar.NewStatefulContract("Bridge")

    c.State("balance", runar.Uint64)           // Total BSV held in the bridge covenant
    c.State("lastClaimedNonce", runar.Uint64)   // Last withdrawal nonce claimed (global sequential)
    c.State("frozen", runar.Uint8)              // 0 = active, 1 = frozen (governance)

    // Known state covenant script hash (set at genesis, immutable)
    c.Prop("stateCovenantScriptHash", runar.Bytes32, hash256(stateCovenantScript))

    // Deposit: anyone can add BSV to the bridge
    c.Method("deposit", func(m *runar.MethodBuilder) {
        depositAmount := m.Param("depositAmount", runar.Uint64)

        // Verify the output recreates the bridge covenant with increased balance
        c.SetState("balance", m.Add(c.GetState("balance"), depositAmount))

        // Verify output value matches the new balance
        m.RequireOutputValue(0, m.Add(c.GetState("balance"), depositAmount))
        m.RequireStateOutput()
    })

    // Withdraw: STARK-derived, proof-authorized release.
    //
    // The bridge does NOT verify the Ethereum MPT or use Keccak-256.
    // Instead, it leverages the STARK proof that already covers the
    // full EVM execution. The SP1 guest program detects withdrawals
    // during batch execution, reads the withdrawal hashes from
    // contract storage, and commits a SHA256 Merkle root of all
    // withdrawal hashes as a STARK public value. The OP_RETURN batch
    // data of the covenant-advance tx includes the individual withdrawal
    // details and the withdrawalRoot for data availability.
    //
    // The bridge covenant verifies withdrawal inclusion using only
    // SHA256 (native BSV opcode) — no Keccak-256 in Script.
    c.Method("withdraw", func(m *runar.MethodBuilder) {
        amount          := m.Param("amount", runar.Uint64)
        bsvAddr         := m.Param("bsvAddress", runar.Bytes20)
        nonce           := m.Param("nonce", runar.Uint64)
        withdrawalProof := m.Param("withdrawalProof", runar.ByteArray) // SHA256 Merkle proof
        withdrawalRoot  := m.Param("withdrawalRoot", runar.Bytes32)    // from batch's STARK public values
        refOutputScript := m.Param("refOutputScript", runar.VarBytes)  // state covenant output script
        refOpReturn     := m.Param("refOpReturn", runar.VarBytes)      // OP_RETURN from covenant-advance tx

        // 0. Reject if bridge is frozen by governance
        m.Require(
            m.Equal(c.GetState("frozen"), runar.Uint8Literal(0)),
            "bridge is frozen — withdrawals paused by governance",
        )

        // 1. Verify nonce is sequential — claims must be in strict order.
        //    lastClaimedNonce + 1 == nonce. This prevents double-claiming
        //    with a single uint64 counter (no bitmap or set needed).
        m.Require(
            m.Equal(nonce, m.Add(c.GetState("lastClaimedNonce"), runar.Uint64Literal(1))),
            "withdrawal nonce not sequential — must claim nonce lastClaimedNonce+1",
        )

        // 2. Compute the expected withdrawal hash.
        //    hash256(bsvAddress_bytes20 || satoshiAmount_uint64_be || nonce_uint64_be)
        //    This matches the L2Bridge Solidity contract's hash computation.
        expectedHash := m.Hash256(m.Cat(bsvAddr, m.Uint64ToBytes(amount), m.Uint64ToBytes(nonce)))

        // 3. Verify the withdrawal hash is in the withdrawalRoot via
        //    SHA256 Merkle inclusion proof. The tree is a binary SHA256
        //    Merkle tree of all withdrawal hashes in the batch, built by
        //    the SP1 guest program. Max depth: 16 (up to 65,536 withdrawals
        //    per batch — far beyond practical limits).
        //
        //    Each level: SHA256(left || right). ~3 opcodes per level,
        //    16 levels = ~50 opcodes. Trivial script cost.
        m.RequireSHA256MerkleProof(expectedHash, withdrawalRoot, withdrawalProof)

        // 4. Verify the withdrawalRoot comes from a confirmed state
        //    covenant advance. The unlocking script provides:
        //    - The referenced tx's output 0 script (state covenant)
        //    - The referenced tx's OP_RETURN data (batch data)
        //
        //    The bridge covenant verifies:
        //    a) Hash of the referenced output script matches the known
        //       state covenant script hash (proves it's a valid advance)
        //    b) The withdrawalRoot extracted from the OP_RETURN matches
        //       the one provided (proves the root is from that batch)
        //
        //    This is a READ of the state covenant, not a SPEND. The state
        //    covenant UTXO chain continues independently.
        m.Require(
            m.Equal(m.Hash256(refOutputScript), c.Prop("stateCovenantScriptHash")),
            "referenced output is not from state covenant",
        )
        // Extract withdrawalRoot from the batch data OP_RETURN.
        // Batch data layout: "BSVM\x02" prefix (5 bytes), then encoded
        // fields. The withdrawalRoot is at a fixed offset in the batch
        // data (see spec 12, Batch Data Encoding Format).
        extractedRoot := m.Substr(refOpReturn, batchWithdrawalRootOffset, 32)
        m.Require(
            m.Equal(extractedRoot, withdrawalRoot),
            "withdrawal root does not match batch data",
        )

        // 5. Verify sufficient balance in the bridge covenant
        m.Require(
            m.LessOrEqual(amount, c.GetState("balance")),
            "insufficient balance in bridge covenant",
        )

        // 6. Update state
        c.SetState("balance", m.Sub(c.GetState("balance"), amount))
        c.SetState("lastClaimedNonce", nonce)

        // 7. Enforce outputs:
        //    Output 0: new bridge covenant UTXO (reduced balance, updated nonce)
        m.RequireStateOutput()

        //    Output 1: payment to user's BSV address with CSV timelock.
        //    CSV delay is enforced per withdrawal tier (see Bridge
        //    Confirmation Enforcement via CSV section above).
        csvScript := m.Cat(
            m.CSVPrefix(csvDelay),
            m.P2PKH(bsvAddr),
        )
        m.RequireOutput(1, csvScript, amount)

        //    Output 2: OP_RETURN withdrawal receipt (for indexing / audit trail)
        receiptData := m.Cat([]byte("BSVM\x04"), m.Uint64ToBytes(nonce),
            m.Uint64ToBytes(amount), bsvAddr)
        m.RequireOutputScript(2, m.OpReturnPrefix(receiptData))
    })


    // --- Bridge governance methods ---
    // Inherited from the shard's governance mode. These are compiled
    // conditionally, same as the state covenant's governance methods
    // (see Spec 12). Bridge freeze blocks withdraw claims only ---
    // deposits are always accepted (the deposit method has no frozen check).

    switch gov.Mode {
    case GovernanceNone:
        // No bridge governance. Fully trustless.

    case GovernanceSingleKey:
        c.Prop("governanceKey", runar.PubKey, gov.Keys[0])

        c.Method("freeze", func(m *runar.MethodBuilder) {
            sig := m.Param("sig", runar.Sig)
            m.RequireCheckSig(sig, c.Prop("governanceKey"))
            m.Require(m.Equal(c.GetState("frozen"), runar.Uint8Literal(0)), "already frozen")
            c.SetState("frozen", runar.Uint8Literal(1))
            m.RequireStateOutput()
        })

        c.Method("unfreeze", func(m *runar.MethodBuilder) {
            sig := m.Param("sig", runar.Sig)
            m.RequireCheckSig(sig, c.Prop("governanceKey"))
            m.Require(m.Equal(c.GetState("frozen"), runar.Uint8Literal(1)), "not frozen")
            c.SetState("frozen", runar.Uint8Literal(0))
            m.RequireStateOutput()
        })

    case GovernanceMultiSig:
        c.Prop("governanceKeys", runar.PubKeyArray, gov.Keys)
        c.Prop("governanceThreshold", runar.Uint32, uint32(gov.Threshold))

        c.Method("freeze", func(m *runar.MethodBuilder) {
            sigs := m.Param("sigs", runar.SigArray)
            m.RequireMultiSig(sigs, c.Prop("governanceKeys"), c.Prop("governanceThreshold"))
            m.Require(m.Equal(c.GetState("frozen"), runar.Uint8Literal(0)), "already frozen")
            c.SetState("frozen", runar.Uint8Literal(1))
            m.RequireStateOutput()
        })

        c.Method("unfreeze", func(m *runar.MethodBuilder) {
            sigs := m.Param("sigs", runar.SigArray)
            m.RequireMultiSig(sigs, c.Prop("governanceKeys"), c.Prop("governanceThreshold"))
            m.Require(m.Equal(c.GetState("frozen"), runar.Uint8Literal(1)), "not frozen")
            c.SetState("frozen", runar.Uint8Literal(0))
            m.RequireStateOutput()
        })
    }

    return c.Build()
}
```

## Cross-Shard Bridging (Post-v1)

> **DEFERRED**: Cross-shard bridging is not included in the initial release.
> The design below is directional — it will be fully specified when
> cross-shard support is prioritised.

Moving assets between shards:
1. User calls bridge contract on Shard A: lock 100 tokens
2. Shard A emits a lock event, proven by its covenant chain
3. User (or relayer) submits the lock proof to Shard B's bridge contract
4. Shard B's bridge contract verifies the proof and mints 100 tokens

This is async, not atomic. The proof is an SPV proof that the lock event
exists in a BSV-confirmed L2 block on Shard A.

A full specification must address: lock proof format, Shard B verification
of Shard A's covenant state, double-spend prevention across shards, relay
mechanism design, and failure/timeout handling.

## Bridge Security

The bridge covenant inherits the shard's governance mode from genesis:

- **GovernanceNone**: The bridge is fully trustless. No guardian freeze,
  no privileged operator. The STARK proof is the sole authorization for
  withdrawals. CSV delays, rate limiting, and the single-covenant model
  are the only protections.

- **GovernanceSingleKey / GovernanceMultiSig**: The governance keys can
  freeze the bridge covenant independently of the state covenant. This
  allows freezing withdrawals while the state covenant continues
  operating (or vice versa). A bridge freeze blocks `withdraw` claims
  but does NOT affect deposits --- users can always lock BSV in the
  bridge. This asymmetry ensures deposits are never blocked by
  governance action.

The governance keys CANNOT directly withdraw BSV from the bridge. Only
a valid STARK-derived withdrawal proof can release funds. Governance
can only pause and resume the claim process.

### Bridge UTXO Model (v1: Single Covenant)

In v1, the bridge uses a **single covenant UTXO** that holds all locked
BSV for the shard. The overlay node tracks this UTXO:

```go
type BridgeUTXO struct {
    TxID             Hash
    Vout             uint32
    Balance          uint64   // Total BSV held in the bridge (satoshis)
    LastClaimedNonce uint64   // Last withdrawal nonce claimed (sequential)
    Script           []byte   // Compiled bridge covenant locking script
}
```

The single-covenant model is simpler and avoids the nonce partitioning
problem that sub-covenants would introduce (the L2 Solidity contract
has a single global `withdrawalNonce` counter that doesn't partition
cleanly across independent covenant UTXOs).

**Blast radius mitigation (without sub-covenants)**:
- The 10% per-period withdrawal rate limit caps exploit damage at 10% of TVL per day
- The tiered CSV confirmation delays (6/20/100 blocks) provide additional time for detection
- The STARK proof covers full EVM execution — exploits must circumvent the proof system itself

**Bridge UTXO capacity**: The single bridge UTXO can hold up to
2^64 - 1 satoshis (~184 billion BSV). This exceeds the total BSV supply.
No capacity limit is needed.

**v2 enhancement: Sharded bridge UTXOs**. A future version may split
deposits across multiple independent bridge covenant UTXOs for isolation.
This requires a nonce partitioning scheme where the L2 bridge contract
assigns each withdrawal to a specific sub-covenant at initiation time
(not at claim time). The sub-covenant index would be embedded in the
withdrawal hash. This is deferred because it adds significant complexity
to both the L2 contract and the BSV covenant logic.

### Tiered Withdrawal Confirmations

Larger withdrawals require more BSV confirmations before release. This
protects against BSV reorgs — not against invalid state (which the STARK
proof already prevents).

```
Withdrawal ≤ 10 BSV:   6 BSV confirmations (~1 hour)
Withdrawal > 10 BSV:  20 BSV confirmations (~3 hours)
Withdrawal > 100 BSV: 100 BSV confirmations (~17 hours)
```

See the `WithdrawalConfig` and `WithdrawalTier` types defined in the
"Proof-verified withdrawal" section above for the tiered confirmation
configuration.

### Global Withdrawal Rate Limit

The bridge covenant enforces a maximum withdrawal rate: no more than 10%
of total locked balance can be withdrawn per 144 BSV blocks (~24 hours).
This limits damage from any exploit to 10% of TVL per day.

The covenant tracks cumulative withdrawals using BSV block height as a
time proxy. The rate limit resets every 144 blocks.

```go
type RateLimitConfig struct {
    MaxPercentPerPeriod uint64 // Default: 10 (percent)
    PeriodBlocks        uint64 // Default: 144 (~24 hours of BSV blocks)
}
```

If the rate limit is hit, withdrawals are queued until the next period.
No funds are lost — just delayed. This is a purely algorithmic safety
mechanism with no trusted parties.

### Bridge Behavior During Rollbacks

When the overlay node performs a cascade rollback (Spec 11), bridge-related transactions require special handling:

**Deposits during rollback**:
- Deposits are BSV-side events (covenant UTXOs). A BSV reorg can invalidate a deposit.
- If block N credited a deposit and block N is rolled back, the deposit credit is reverted along with all other state changes.
- The deposit BSV UTXO returns to its pre-spend state. The user can re-deposit or reclaim their BSV.
- If the deposit BSV transaction is NOT affected by the BSV reorg (it was in a block before the reorg point), the deposit is re-included in the re-executed batch.

**Withdrawals during rollback**:
- If a withdrawal was initiated (wBSV burned on L2) in block N and block N is rolled back, the burn is reverted — the user's wBSV balance is restored.
- If the withdrawal was already finalized on BSV (bridge covenant released BSV), the rollback creates an inconsistency: the user has both BSV and wBSV.
- **Mitigation**: Withdrawal finalization on BSV requires the state covenant to be at a height >= the withdrawal block with >= 6 BSV confirmations. This ensures the L2 state is finalized before BSV is released. A 6-block BSV reorg that invalidates both the state covenant and bridge covenant is required to cause inconsistency — this is the same security assumption as Bitcoin itself.

**Invariant**: `bridge.TotalDeposited - bridge.TotalWithdrawn == sum(all L2 wBSV balances)`. This invariant is NOT a STARK public value — it is verified off-chain by each node during batch replay. The STARK proof covers the full EVM execution that maintains this invariant (every `AddBalance` for deposits and every `transfer` to `BURN_ADDRESS` for withdrawals), so the invariant holds as a consequence of correct execution. Nodes that detect a violation during re-execution flag an EVM disagreement. A future version may add an explicit invariant check to the public values layout, but for v1, the execution proof provides sufficient coverage.

**Rate limit enforcement location**: Withdrawal rate limiting is enforced
in the **L2 bridge contract**, not in the BSV covenant. The bridge
contract tracks cumulative withdrawals per time period and rejects
`withdraw()` calls that exceed the rate limit. Since the STARK proof
covers the state trie (which includes the bridge contract's storage),
the rate limit is indirectly enforced on-chain — a covenant advance with
a state root reflecting a rate-limit-violating withdrawal would require a
STARK proof of a state that includes the violation, which would fail if
the bridge contract correctly rejects it. The covenant does NOT enforce
rate limits directly — it only verifies: valid STARK proof + block number
increment.

**Rate limit and cascade rollback**: The `periodWithdrawals` mapping is
part of the L2 state trie. When a cascade rollback (Spec 11) re-executes
blocks, the state is rolled back to the last confirmed root, and all
`periodWithdrawals` entries from rolled-back blocks are reverted along
with all other state. Re-executed blocks may fall in the same or different
periods depending on their new block numbers. This is correct: the rate
limit applies to the canonical chain state, not to speculative state.
Users querying withdrawal availability should use the `safe` or `finalized`
block tags to avoid seeing rate limit state that may be reverted.

## Bridge Covenant Migration

When the state covenant migrates to a new script (spec 09, Milestone 10),
the bridge covenant's embedded state covenant script hash becomes stale.
The bridge covenant MUST be migrated simultaneously.

### Migration Protocol

1. **Coordinated migration**: The state covenant and bridge covenant
   migrate in the same BSV block (or consecutive transactions). The
   shard operator compiles the new state covenant, then recompiles the
   bridge covenant with the new state covenant script hash embedded.

2. **Bridge `migrate` method**: The bridge covenant includes a `migrate`
   method analogous to the state covenant's migrate method. It requires
   a valid STARK proof of the current state (proving the operator knows
   the current state) and transitions the bridge UTXO to the new script.

```go
// Added to pkg/covenant/contracts/bridge.go
c.Method("migrate", func(m *runar.MethodBuilder) {
    newScriptHash   := m.Param("newScriptHash", runar.Bytes32)
    stateRoot       := m.Param("stateRoot", runar.Bytes32)
    proof           := m.Param("proof", runar.VarBytes)
    publicValues    := m.Param("publicValues", runar.VarBytes)

    // Verify the caller knows the current state (prevents stale migrations).
    // The proof must be a valid SP1 proof whose public values contain
    // the current state root. This reuses the same verification as
    // the state covenant — the bridge covenant embeds the same SP1 VK.
    m.Require(
        runar.SP1Verify(proof, publicValues, c.Prop("sp1VK")),
        "invalid migration proof",
    )
    preRoot := m.ExtractBytes32(publicValues, 0)
    m.Require(
        m.Equal(preRoot, stateRoot),
        "state root mismatch in migration proof",
    )

    // Output 0 must use the NEW bridge covenant script
    m.RequireOutputScriptHash(0, newScriptHash)

    // Balance and nonce are carried forward unchanged
    m.RequireOutputState(0, "balance", c.GetState("balance"))
    m.RequireOutputState(0, "withdrawalNonce", c.GetState("withdrawalNonce"))

    // Satoshis preserved
    m.RequireOutputValue(0, m.InputValue(0))
})
```

3. **Migration ordering**: The state covenant migrates FIRST. The bridge
   covenant migrates SECOND (in the same block or immediately after).
   The new bridge covenant embeds the new state covenant's script hash.

4. **Withdrawal pause**: During migration, withdrawals are paused.
   Deposits continue normally (they are permissionless). The pause
   window is the time between the state covenant migration and the
   bridge covenant migration — typically one BSV block (~10 minutes)
   at most. In v1 there is only a single bridge covenant UTXO to
   migrate.

## Bridge Contract (L2 Predeploy)

The bridge contract is deployed at a fixed address in the L2 genesis state. It's a "predeploy" — it exists at block 0.

```go
// pkg/bridge/predeploy.go

const (
    BridgeContractAddress = Address{0x42, 0x00, ..., 0x00, 0x10} // 0x4200...0010
    BridgeSystemAddress   = Address{0xde, 0xad, ..., 0xde, 0xad} // System sender
)

// GenesisAlloc returns the genesis state for the bridge contract.
func BridgeGenesisAlloc() map[Address]GenesisAccount {
    return map[Address]GenesisAccount{
        BridgeContractAddress: {
            Code:    bridgeContractBytecode, // Compiled Solidity
            Storage: initialStorage(),
            Balance: uint256.NewInt(0),
        },
    }
}
```

## Deposit Merkle Tree

To enable efficient deposit deduplication and `eth_getProof`-style
queries for deposit verification, the overlay node maintains a Merkle
tree of all processed deposits. This tree is used for:
- **Deduplication on restart**: `processedDeposits` is the hot cache;
  the tree is the persistent index.
- **RPC queries**: `bsv_getDepositStatus(bsvTxID)` can prove inclusion.
- **State export**: The deposit set is included in state snapshots for
  fast sync.

Note: This is NOT used for fraud proofs (the system uses validity proofs).

```go
// pkg/bridge/deposit_tree.go

type DepositTree struct {
    tree *mpt.Trie
}

func (dt *DepositTree) AddDeposit(deposit *Deposit) Hash {
    key := deposit.BSVTxID[:]
    value := encodeDeposit(deposit)
    dt.tree.Update(key, value)
    return dt.tree.Hash()
}
```

## Cross-Shard Deposit Routing Details

**Shard ID encoding**: 4 bytes, big-endian uint32. Maximum 2^32 shards.
Shard ID 0 is reserved (invalid).

**Invalid shard ID**: If a deposit references an unknown shard ID, the
deposit is ignored by all shards. The BSV transaction is valid (the user
spent their UTXO) but no L2 credit is issued.

**Invalid deposits are non-refundable.** If a deposit references an
invalid shard ID, is below the minimum amount, or contains malformed
data, the BSV is locked permanently in the bridge covenant. There is
no refund mechanism in v1.

**Rationale**: A permissionless refund method cannot safely verify that
a deposit was "never credited on L2" — this would require proving a
negative (non-inclusion) inside Bitcoin Script, which is not feasible
without unbounded state in the covenant. A previous version of this
spec included a timeout-based refund, but it was vulnerable to double-
spending: a deposit could be credited on L2 AND refunded on BSV after
the timeout, letting the user keep both wBSV and the refunded BSV.

**User protection**: The deposit UX (wallet, SDK, documentation) MUST
validate deposit parameters before broadcasting:
- Verify the shard ID matches a known shard
- Verify the amount is >= `min_deposit_satoshis` (10,000 sats)
- Verify the L2 address is a valid 20-byte Ethereum address
- Display a clear warning that invalid deposits are irrecoverable

**Dust deposit enforcement**: The bridge covenant's `deposit` method
enforces a minimum deposit amount. Deposits below `min_deposit_satoshis`
are rejected by the covenant script (the transaction is invalid and
BSV miners will not mine it). This prevents accidental dust deposits.

**Dust deposits**: Deposits below `min_deposit_satoshis` (config, default
10,000 sats) are ignored. The bridge covenant should enforce a minimum
output value.

## Bridge Withdrawal Verification

**Withdrawal verification path**: The bridge covenant on BSV verifies
withdrawals via a **STARK-derived SHA256 Merkle tree**, not via direct
Ethereum MPT verification. No Keccak-256 is used in Script.

The L2 bridge contract stores a `withdrawalHashes` mapping in contract
storage. Each withdrawal writes `hash256(bsvAddress_bytes20 || satoshiAmount_uint64_be || nonce_uint64_be)`
to `withdrawalHashes[nonce]` (where hash256 = SHA256(SHA256(data))).

The SP1 guest program, after executing all transactions in a batch,
scans for `WithdrawalInitiated` events from the bridge contract. For
each withdrawal, it reads the corresponding `withdrawalHashes[nonce]`
value from the bridge contract's storage. It builds a binary SHA256
Merkle tree of all withdrawal hashes and commits the root as a STARK
public value (`withdrawalRoot`). This root is also included in the
OP_RETURN batch data for data availability.

The bridge covenant on BSV verifies a withdrawal by checking:
1. The withdrawal hash is in the `withdrawalRoot` via SHA256 Merkle
   inclusion proof (native OP_SHA256, ~50 opcodes)
2. The `withdrawalRoot` comes from a confirmed state covenant advance
   (cross-covenant output reference — verify script hash of the
   referenced tx's output matches the state covenant)

This works because:
- The STARK proof covers the full EVM execution that produced the
  withdrawal hashes (every opcode, every storage write)
- The SP1 guest reads the hashes from contract storage post-execution
  and commits them as a SHA256 Merkle root
- The covenant verifies the batch data hash (which includes the
  withdrawal root) against the STARK public values
- The bridge verifies individual withdrawal inclusion against the root

The bridge covenant does NOT use event logs, receipt tries, or
Ethereum MPT verification in Script. Events are still emitted (for
RPC `eth_getLogs` queries by frontends) but are not part of the
on-chain BSV verification path. All Script-level hashing uses SHA256.

### Withdrawal Proof Structure (STARK-Derived, SHA256 Only)

The bridge covenant verifies withdrawal inclusion using a SHA256 Merkle
proof against the `withdrawalRoot` committed by the SP1 guest program.
**No Keccak-256 or Ethereum MPT verification is performed in Script.**
The STARK proof covers the full EVM execution (including Keccak-256 MPT
operations inside the zkVM). The bridge only uses SHA256 (native BSV
opcode).

```
WithdrawalClaim {
    // Withdrawal details
    BSVAddress      [20]byte   // Recipient BSV P2PKH address
    SatoshiAmount   uint64     // Amount in satoshis (big-endian)
    Nonce           uint64     // Sequential withdrawal nonce (big-endian)

    // SHA256 Merkle inclusion proof
    WithdrawalRoot  [32]byte   // From the batch's STARK public values
    MerkleProof     [][]byte   // SHA256 Merkle authentication path (max depth 16)
    LeafIndex       uint32     // Position in the withdrawal Merkle tree

    // Cross-covenant reference to the state covenant advance tx
    RefOutputScript []byte     // State covenant's output 0 locking script
    RefOpReturn     []byte     // OP_RETURN batch data from the advance tx
}
```

**Verification algorithm** (executed in Bitcoin Script via Rúnar):

1. Compute the expected withdrawal hash:
   `hash256(bsvAddress_20 || satoshiAmount_u64_be || nonce_u64_be)`
   This matches the L2Bridge Solidity contract's hash computation.
2. Verify the withdrawal hash is in the `withdrawalRoot` via SHA256
   Merkle inclusion proof. Each level: `SHA256(left || right)`.
   Max depth 16, ~50 opcodes total.
3. Verify the `withdrawalRoot` comes from a confirmed state covenant
   advance by checking the referenced OP_RETURN batch data and
   verifying the referenced output script hash matches the known
   state covenant script hash.
4. Check nonce matches `withdrawalNonce` (sequential replay protection).
5. Enforce correct BSV output to the recipient.

**Hash function**: All Merkle proof hashes use SHA256 (native OP_SHA256).
No Keccak-256 is used in the bridge covenant script.

**Script cost**: The SHA256 Merkle verification is ~50 opcodes (16 levels
× ~3 opcodes). The hash256 computation for the withdrawal hash is 2
opcodes (OP_HASH256). The cross-covenant reference check is ~10 opcodes.
Total bridge covenant withdrawal path: ~200 opcodes — trivial.

**Withdrawal hash encoding**: `hash256(bsvAddress || satoshiAmount || nonce)`
where hash256 = SHA256(SHA256(data)), bsvAddress is bytes20,
satoshiAmount is uint64 (big-endian, in satoshis NOT L2 wei), nonce is
uint64 (big-endian). In Solidity: `sha256(abi.encodePacked(sha256(abi.encodePacked(...))))`.
In Rúnar: `m.Hash256(m.Cat(...))` which maps to BSV's OP_HASH256.
The Solidity contract converts from L2 wei to satoshis before hashing.
The SP1 guest reads these hashes from the bridge contract's storage
after execution and includes them in the batch's SHA256 Merkle tree.
Both sides use identical encoding: `hash256(20 bytes || 8 bytes || 8 bytes)`
= 36 bytes input.

## Deliverables

1. `pkg/bridge/monitor.go` — BSV deposit monitoring
2. `pkg/bridge/withdrawer.go` — BSV withdrawal processing
3. `pkg/bridge/predeploy.go` — Genesis bridge contract deployment
4. `pkg/bridge/deposit_tree.go` — Deposit Merkle tree
5. `pkg/bridge/types.go` — Deposit, Withdrawal types
6. `contracts/L2Bridge.sol` — Solidity bridge contract
7. `pkg/bridge/config.go` — Bridge configuration

## Acceptance Criteria

- [ ] Deposits: BSV sent to bridge address credits L2 account after confirmations
- [ ] Withdrawals: L2 withdrawal request releases BSV after BSV confirmation period (reorg protection, not a challenge period)
- [ ] Double-deposit prevention: same BSV tx can't be credited twice
- [ ] Amount conversion: satoshi↔L2 wei conversion is exact and reversible
- [ ] Bridge contract: deployed in genesis state at fixed address
- [ ] System transactions: deposit txs are included before user txs in blocks
- [ ] Deposit events: queryable via eth_getLogs on the bridge contract
- [ ] Withdrawal events: queryable and trackable through to BSV release
