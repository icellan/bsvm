# Phase 1b: Custom StateDB Implementation

## Goal
Implement the `StateDB` interface defined in Phase 1 with a standalone Merkle Patricia Trie (MPT) backed by LevelDB or Pebble, independent of geth's `core/state` package.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  vm.StateDB interface             │
└──────────────────────┬───────────────────────────┘
                       │ implements
                       ▼
┌──────────────────────────────────────────────────┐
│              state.StateDB (our impl)             │
│  - In-memory cache of dirty accounts/storage      │
│  - Journal for snapshot/revert                    │
│  - Transient storage (per-tx, EIP-1153)           │
│  - Access list tracking (EIP-2929)                │
│  - Log accumulation                               │
└──────────────────────┬───────────────────────────┘
                       │ reads/writes
                       ▼
┌──────────────────────────────────────────────────┐
│              mpt.Trie (Merkle Patricia Trie)      │
│  - Account trie: address → RLP(Account)           │
│  - Storage tries: per-account storage slots        │
│  - Produces state root hashes                      │
└──────────────────────┬───────────────────────────┘
                       │ persists to
                       ▼
┌──────────────────────────────────────────────────┐
│              db.Database interface                 │
│  - LevelDB (default, production)                  │
│  - MemoryDB (testing)                             │
│  - Pebble (alternative, CockroachDB's engine)     │
└──────────────────────────────────────────────────┘
```

## Account Model

Each account in the EVM world state is represented as:

```go
// pkg/state/account.go

type Account struct {
    Nonce    uint64
    Balance  *uint256.Int
    Root     Hash        // Storage trie root (empty trie hash if no storage)
    CodeHash Hash        // Keccak256 of the contract code (empty hash if EOA)
}
```

Accounts are stored in the account trie keyed by `Keccak256(address)`.

## StateDB Implementation

```go
// pkg/state/statedb.go

type StateDB struct {
    db       Database           // Underlying key-value store
    trie     *mpt.SecureTrie    // Account trie
    
    // Per-account state objects (cached in memory during execution)
    stateObjects     map[Address]*stateObject
    stateObjectsDirty map[Address]struct{}
    
    // Journal for snapshot/revert
    journal *journal
    validRevisions []revision
    nextRevisionID int
    
    // Transaction-scoped state
    transientStorage transientStorage   // EIP-1153
    accessList       *accessList        // EIP-2929
    logs             []*Log
    logSize          uint
    refund           uint64
    preimages        map[Hash][]byte
    
    // The state root before any modifications in this execution context
    originalRoot Hash
}

// New creates a new StateDB from a given state root.
func New(root Hash, db Database) (*StateDB, error) {
    tr, err := mpt.NewSecureTrie(root, db)
    if err != nil {
        return nil, err
    }
    return &StateDB{
        db:               db,
        trie:             tr,
        stateObjects:     make(map[Address]*stateObject),
        stateObjectsDirty: make(map[Address]struct{}),
        journal:          newJournal(),
        accessList:       newAccessList(),
        transientStorage: newTransientStorage(),
        preimages:        make(map[Hash][]byte),
        originalRoot:     root,
    }, nil
}
```

## stateObject (per-account cache)

```go
// pkg/state/state_object.go

type stateObject struct {
    address  Address
    addrHash Hash    // Keccak256(address), used as trie key
    
    // Account data
    data Account
    
    // Contract code (lazy loaded)
    code     []byte
    codeHash Hash
    codeDirty bool
    
    // Storage cache
    originStorage  Storage  // Cache of storage read from trie
    pendingStorage Storage  // Storage entries modified in current block
    dirtyStorage   Storage  // Storage entries modified in current tx
    
    // Flags
    created     bool  // true if account was created in this tx
    selfDestructed bool
    
    db *StateDB // back-pointer
}

type Storage map[Hash]Hash
```

## Journal (Snapshot/Revert)

The EVM uses snapshot/revert for call frames: when an inner CALL reverts, state changes from that call frame are rolled back. This is critical for correctness.

**Depth limit**: Maximum snapshot depth is 1024 (matching the EVM call depth limit). `Snapshot()` returns `ErrSnapshotDepthExceeded` if this limit is reached. In practice, the EVM's own call depth limit (1024) prevents deeper nesting.

```go
// pkg/state/journal.go

type journal struct {
    entries []journalEntry
}

type journalEntry interface {
    revert(*StateDB)
}

// Example journal entries:
type createObjectChange struct {
    account Address
}

type balanceChange struct {
    account Address
    prev    *uint256.Int
}

type nonceChange struct {
    account Address
    prev    uint64
}

type storageChange struct {
    account  Address
    key      Hash
    prevalue Hash
}

type codeChange struct {
    account  Address
    prevCode []byte
    prevHash Hash
}

type addLogChange struct {
    txHash Hash
}

type refundChange struct {
    prev uint64
}

type accessListAddAccountChange struct {
    address Address
}

type accessListAddSlotChange struct {
    address Address
    slot    Hash
}

type transientStorageChange struct {
    account Address
    key     Hash
    prevalue Hash
}

type selfDestructChange struct {
    account     Address
    prev        bool
    prevBalance *uint256.Int
}
```

## Commit Flow

After a block's transactions are executed:

```go
// Finalise moves pending storage writes to the trie (but doesn't hash)
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
    for addr := range s.stateObjectsDirty {
        obj := s.stateObjects[addr]
        if obj.selfDestructed || (deleteEmptyObjects && obj.empty()) {
            s.deleteStateObject(obj)
        } else {
            obj.updateStorageTrie(s.db) // flush dirty storage → storage trie
            obj.updateAccountTrie(s.trie) // flush account data → account trie
        }
    }
    s.clearJournal()
}

// Commit computes the new state root and persists everything to the DB.
func (s *StateDB) Commit(deleteEmptyObjects bool) (Hash, error) {
    s.Finalise(deleteEmptyObjects)
    
    // Commit all storage tries
    for addr := range s.stateObjectsDirty {
        obj := s.stateObjects[addr]
        if err := obj.commitStorageTrie(s.db); err != nil {
            return Hash{}, err
        }
    }
    
    // Commit the account trie → produces state root
    root, err := s.trie.Commit()
    if err != nil {
        return Hash{}, err
    }
    
    // Flush trie nodes to the underlying database
    if err := s.db.Commit(root); err != nil {
        return Hash{}, err
    }
    
    return root, nil
}

// IntermediateRoot computes the current state root without persisting.
// Used after each transaction to get the post-tx state root for receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) Hash {
    s.Finalise(deleteEmptyObjects)
    return s.trie.Hash()
}
```

### Concrete StateDB Methods (not on the vm.StateDB interface)

These methods are called by the block executor or prover, not by the EVM:

```go
// Block executor methods
func (s *StateDB) SetTxContext(txHash Hash, txIndex int)
func (s *StateDB) GetLogs(txHash Hash) []*Log
func (s *StateDB) SetBalance(addr Address, amount *uint256.Int) // Used by genesis init (spec 08)
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) Hash
func (s *StateDB) Finalise(deleteEmptyObjects bool)
func (s *StateDB) Commit(deleteEmptyObjects bool) (Hash, error)

// Merkle proof methods (used by prover state export and eth_getProof RPC)
//
// GetProof returns the Merkle proof for an account in the account trie.
// The proof is a list of RLP-encoded trie nodes from the root to the
// account's leaf (or the proof of non-existence).
func (s *StateDB) GetProof(addr Address) ([][]byte, error)

// GetStorageProof returns the Merkle proof for a storage slot in an
// account's storage trie. The proof is a list of RLP-encoded trie nodes
// from the account's storage root to the slot's leaf.
func (s *StateDB) GetStorageProof(addr Address, slot Hash) ([][]byte, error)

// Cumulative access tracking (used by prover state export)
//
// StartAccessRecording begins recording all account and storage slot
// accesses across multiple transactions. This is separate from the
// per-transaction EIP-2929 access list (which resets each tx).
// Call this before executing a batch of transactions.
func (s *StateDB) StartAccessRecording()

// StopAccessRecording stops recording and returns the cumulative set
// of all accounts and storage slots accessed since StartAccessRecording.
// This is used to determine which state to export for the SP1 guest.
func (s *StateDB) StopAccessRecording() *AccessRecording

// AccessRecording holds the cumulative set of all accounts and storage
// slots accessed during a batch execution.
type AccessRecording struct {
    Accounts []Address             // All accounts accessed (read or written)
    Slots    map[Address][]Hash    // All storage slots accessed per account
}
```

The access recording is implemented by hooking into the stateObject
lookup path. Every call to `getStateObject(addr)` records the address.
Every call to `GetState(addr, slot)` or `SetState(addr, slot, ...)` records
the slot. This is lightweight — just appending to maps — and captures
every account/slot the EVM touches, including implicit accesses like
balance checks and nonce reads.

The cumulative access recording is distinct from EIP-2929's access list:
- EIP-2929 access list: per-transaction, used for warm/cold gas pricing
- Access recording: per-batch, used for prover state export
Both can run simultaneously without interference.

**Thread safety**: Access recording state is protected by a dedicated `sync.Mutex` (`accessMu`). The recording map is Copy-on-Write: `StartAccessRecording()` creates a new map under the lock; `StopAccessRecording()` atomically swaps the map pointer to nil. EVM execution and access recording run in the same goroutine — the mutex is only needed to synchronize with the state export goroutine that reads the accumulated map.

## MemoryStateDB (for testing)

For unit tests and the ethereum/tests runner, we need a fast in-memory implementation:

```go
// pkg/state/memory_statedb.go

type MemoryStateDB struct {
    accounts         map[Address]*Account
    code             map[Address][]byte
    storage          map[Address]map[Hash]Hash
    // ... same interface, backed by maps instead of trie
}
```

This is simpler but cannot produce valid state roots. It's used for quick
EVM opcode testing where we don't care about the trie.

**Testing limitation**: `MemoryStateDB` uses dummy storage roots and map-copy snapshots. It validates EVM execution logic but NOT Merkle Patricia Trie correctness. Integration tests MUST use the real StateDB backed by LevelDB + MPT (`pkg/state/`) to catch trie-related bugs.

**Stub behavior for trie-related methods**:
- `GetStorageRoot(addr)`: returns `EmptyRootHash` (the root of an empty
  MPT: `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`).
  This applies to both non-existent accounts and accounts with no storage
  slots. The `MemoryStateDB` implementation also returns `EmptyRootHash`
  for consistency — it does NOT use a dummy hash.
- `Snapshot()` / `RevertToSnapshot()`: implemented via copying the
  maps (acceptable for testing; not performant for production).
- `IntermediateRoot()`: returns `Hash{}` (not meaningful without a trie).

## Database Interface

```go
// internal/db/database.go

type Database interface {
    Get(key []byte) ([]byte, error)
    Has(key []byte) (bool, error)
    Put(key []byte, value []byte) error
    Delete(key []byte) error
    NewBatch() Batch
    Close() error
}

type Batch interface {
    Put(key []byte, value []byte) error
    Delete(key []byte) error
    Write() error
    Reset()
    ValueSize() int
}
```

Implementations:
- `internal/db/leveldb.go` — Wraps `syndtr/goleveldb`
- `internal/db/memorydb.go` — In-memory map for testing
- `internal/db/pebble.go` — Optional Pebble backend

## Merkle Patricia Trie

We need a standalone MPT implementation. Options:
1. **Extract from geth's `trie/` package** — Most complete but has many internal dependencies
2. **Use a standalone implementation** — e.g., `hashicorp/go-ethereum-hdwallet` has a simpler one
3. **Write a minimal one** — Only ~1000 lines for a basic MPT

**Recommendation**: Extract geth's `trie/` package. It's well-tested and the MPT must be bit-for-bit identical to Ethereum's for state root compatibility (important if we ever want to do state proofs).

Files to extract from geth `trie/`:
- `trie.go` — Core trie operations
- `secure_trie.go` — Trie with hashed keys (what StateDB uses)
- `hasher.go` — RLP encoding + Keccak hashing of nodes
- `node.go` — Trie node types (full, short, hash, value)
- `encoding.go` — Hex/compact encoding
- `database.go` — Trie node caching layer
- `iterator.go` — Trie traversal (needed for storage enumeration)

Place in `pkg/mpt/`.

## Transient Storage (EIP-1153)

```go
// pkg/state/transient_storage.go

type transientStorage map[Address]Storage

func (t transientStorage) Set(addr Address, key, value Hash) {
    if _, ok := t[addr]; !ok {
        t[addr] = make(Storage)
    }
    t[addr][key] = value
}

func (t transientStorage) Get(addr Address, key Hash) Hash {
    val, ok := t[addr]
    if !ok {
        return Hash{}
    }
    return val[key]
}
```

Transient storage is cleared after each transaction (not persisted to trie).

**Revert semantics**: Transient storage changes are journaled alongside persistent state. `RevertToSnapshot()` reverts transient storage modifications made after the snapshot, matching EIP-1153 semantics. Transient storage is cleared entirely after each top-level transaction (not persisted to trie).

## Access List (EIP-2929)

```go
// pkg/state/access_list.go

type accessList struct {
    addresses map[Address]int          // address → index in slots
    slots     []map[Hash]struct{}       // parallel to addresses
}
```

## State Snapshots

For fast sync and state growth management, the StateDB supports
serializing and restoring complete state snapshots.

```go
// pkg/state/snapshot.go

// CreateSnapshot serializes the entire state at the current root.
// The snapshot is a streaming format — accounts, storage, and code
// are written in chunks to avoid loading the entire state into memory.
func (s *StateDB) CreateSnapshot(w io.Writer) error {
    // 1. Iterate all accounts in the trie
    // 2. For each account, write: address, nonce, balance, codeHash
    // 3. For each account with storage, iterate storage trie
    // 4. Write code blobs referenced by codeHash
}

// RestoreSnapshot loads state from a snapshot stream.
// Returns the MPT state root computed from the restored state.
func RestoreSnapshot(r io.Reader, db Database) (Hash, error) {
    // 1. Read accounts and storage from the stream
    // 2. Insert into fresh MPT
    // 3. Commit and return the state root
    // Caller verification (two checks):
    //   a) keccak256(snapshot stream) == snapshot hash from BSV announcement
    //      (verifies download integrity)
    //   b) returned state root == state root in the covenant at the snapshot
    //      block number (verifies state correctness against the covenant chain)
}
```

Snapshots are created periodically (configurable, default every 10,000
L2 blocks). The snapshot hash is published in the covenant OP_RETURN
so new nodes can download a snapshot from any peer and verify it against
the covenant chain, reducing sync time from "replay entire history" to
"download snapshot + replay recent blocks."

Add to `pkg/state/` deliverables: `snapshot.go` — State snapshot
serialization and restore.

## State Tree Type

**State tree type**: Ethereum's Merkle Patricia Trie (MPT) with
Keccak256 hashing. All nodes must use the identical MPT implementation
to produce matching state roots.

SP1's built-in keccak256 precompile (accelerated circuit, ~100K RISC-V
cycles per hash) makes Keccak256 efficient to prove. There is no need
for a ZK-friendly hash (Poseidon) — keccak256 is used throughout,
maintaining full Ethereum compatibility for `eth_getProof` and all
state proof tooling.

The genesis configuration includes a `hashFunction` field for future
extensibility:
```json
{
  "config": { ... },
  "hashFunction": "keccak256"
}
```
Valid values: `"keccak256"` (default). Future versions may add
alternatives if proving economics change.

## Deliverables

1. `pkg/state/statedb.go` — Full `StateDB` implementation
2. `pkg/state/state_object.go` — Per-account state cache
3. `pkg/state/journal.go` — Snapshot/revert journal
4. `pkg/state/access_list.go` — EIP-2929 access list
5. `pkg/state/transient_storage.go` — EIP-1153 transient storage
6. `pkg/state/memory_statedb.go` — In-memory testing implementation
7. `pkg/state/proof.go` — Merkle proof generation (`GetProof`, `GetStorageProof`)
8. `pkg/state/access_recording.go` — Cumulative access recording for prover
9. `pkg/state/snapshot.go` — State snapshot serialization and restore
10. `pkg/mpt/` — Extracted Merkle Patricia Trie
11. `internal/db/` — LevelDB + MemoryDB backends

## Acceptance Criteria

- [ ] `StateDB` satisfies the `vm.StateDB` interface
- [ ] Snapshot/revert: nested snapshots (depth 3+) correctly restore all state modifications (balances, nonces, storage, code, access lists, transient storage) at each level. Tested via a contract that does A.call(B.call(C)) where C reverts.
- [ ] State root computation produces correct Keccak256 MPT roots
- [ ] EVM + StateDB together pass ethereum/tests `GeneralStateTests`
- [ ] Storage trie isolation: each account has independent storage
- [ ] Transient storage cleared between transactions
- [ ] Access list properly tracks warm/cold state access
- [ ] Journal entries correctly undo all state modifications on revert
- [ ] State roots match geth output for identical pre-state and transactions, verified against ethereum/tests GeneralStateTests
