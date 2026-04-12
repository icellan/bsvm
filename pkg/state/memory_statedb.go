package state

import (
	"fmt"
	"sort"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// Ensure MemoryStateDB implements vm.StateDB at compile time.
var _ vm.StateDB = (*MemoryStateDB)(nil)

// memoryAccount holds account state for the in-memory StateDB.
type memoryAccount struct {
	nonce            uint64
	balance          uint256.Int
	code             []byte
	codeHash         types.Hash
	storage          map[types.Hash]types.Hash
	committedStorage map[types.Hash]types.Hash
	selfDestructed   bool
	created          bool
}

// memorySnapshot stores a complete snapshot of all accounts for revert.
type memorySnapshot struct {
	accounts map[types.Address]*memoryAccount
	refund   uint64
	logSize  int
}

// MemoryStateDB is a simple in-memory StateDB for testing. It implements
// the vm.StateDB interface without needing a real trie or database.
type MemoryStateDB struct {
	accounts         map[types.Address]*memoryAccount
	transientStorage transientStorage
	accessList       *accessList
	logs             []*types.Log
	refund           uint64
	preimages        map[types.Hash][]byte
	snapshots        []memorySnapshot
	txHash           types.Hash
	txIndex          int
}

// NewMemoryStateDB creates a new in-memory StateDB for testing purposes.
func NewMemoryStateDB() *MemoryStateDB {
	return &MemoryStateDB{
		accounts:         make(map[types.Address]*memoryAccount),
		transientStorage: newTransientStorage(),
		accessList:       newAccessList(),
		preimages:        make(map[types.Hash][]byte),
	}
}

// getAccount returns the account for the given address, or nil if it does
// not exist.
func (m *MemoryStateDB) getAccount(addr types.Address) *memoryAccount {
	return m.accounts[addr]
}

// getOrCreateAccount returns the account for the given address, creating
// a new empty account if it does not exist.
func (m *MemoryStateDB) getOrCreateAccount(addr types.Address) *memoryAccount {
	acct := m.accounts[addr]
	if acct == nil {
		acct = &memoryAccount{
			codeHash:         types.EmptyCodeHash,
			storage:          make(map[types.Hash]types.Hash),
			committedStorage: make(map[types.Hash]types.Hash),
		}
		m.accounts[addr] = acct
	}
	return acct
}

// CreateAccount creates a new account. If the account already exists,
// the balance is preserved.
func (m *MemoryStateDB) CreateAccount(addr types.Address) {
	existing := m.getAccount(addr)
	newAcct := &memoryAccount{
		codeHash:         types.EmptyCodeHash,
		storage:          make(map[types.Hash]types.Hash),
		committedStorage: make(map[types.Hash]types.Hash),
	}
	if existing != nil {
		newAcct.balance = existing.balance
	}
	m.accounts[addr] = newAcct
}

// CreateContract marks the given address as a newly created contract.
func (m *MemoryStateDB) CreateContract(addr types.Address) {
	acct := m.getOrCreateAccount(addr)
	acct.created = true
}

// Exist reports whether the given account exists.
func (m *MemoryStateDB) Exist(addr types.Address) bool {
	return m.accounts[addr] != nil
}

// Empty returns whether the given account is considered empty.
func (m *MemoryStateDB) Empty(addr types.Address) bool {
	acct := m.getAccount(addr)
	if acct == nil {
		return true
	}
	return acct.nonce == 0 && acct.balance.IsZero() && acct.codeHash == types.EmptyCodeHash
}

// GetBalance returns the balance of the given account.
func (m *MemoryStateDB) GetBalance(addr types.Address) *uint256.Int {
	acct := m.getAccount(addr)
	if acct == nil {
		return new(uint256.Int)
	}
	return new(uint256.Int).Set(&acct.balance)
}

// AddBalance adds amount to the account balance. Returns the previous balance.
func (m *MemoryStateDB) AddBalance(addr types.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	acct := m.getOrCreateAccount(addr)
	prev := acct.balance
	acct.balance.Add(&acct.balance, amount)
	return prev
}

// SubBalance subtracts amount from the account balance. Returns the previous balance.
func (m *MemoryStateDB) SubBalance(addr types.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	acct := m.getOrCreateAccount(addr)
	prev := acct.balance
	acct.balance.Sub(&acct.balance, amount)
	return prev
}

// GetNonce returns the nonce of the given account.
func (m *MemoryStateDB) GetNonce(addr types.Address) uint64 {
	acct := m.getAccount(addr)
	if acct == nil {
		return 0
	}
	return acct.nonce
}

// SetNonce sets the nonce of the given account.
func (m *MemoryStateDB) SetNonce(addr types.Address, nonce uint64, reason tracing.NonceChangeReason) {
	acct := m.getOrCreateAccount(addr)
	acct.nonce = nonce
}

// GetCode returns the code associated with the given account.
func (m *MemoryStateDB) GetCode(addr types.Address) []byte {
	acct := m.getAccount(addr)
	if acct == nil {
		return nil
	}
	return acct.code
}

// SetCode sets the code for the given account. Returns the previous code.
func (m *MemoryStateDB) SetCode(addr types.Address, code []byte, reason tracing.CodeChangeReason) []byte {
	acct := m.getOrCreateAccount(addr)
	prevCode := acct.code
	acct.code = make([]byte, len(code))
	copy(acct.code, code)
	acct.codeHash = types.BytesToHash(crypto.Keccak256(code))
	return prevCode
}

// GetCodeHash returns the code hash of the given account.
func (m *MemoryStateDB) GetCodeHash(addr types.Address) types.Hash {
	acct := m.getAccount(addr)
	if acct == nil {
		return types.EmptyCodeHash
	}
	return acct.codeHash
}

// GetCodeSize returns the size of the code associated with the given account.
func (m *MemoryStateDB) GetCodeSize(addr types.Address) int {
	return len(m.GetCode(addr))
}

// GetState returns the value of a storage slot.
func (m *MemoryStateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	acct := m.getAccount(addr)
	if acct == nil {
		return types.Hash{}
	}
	return acct.storage[key]
}

// GetCommittedState returns the value of a storage slot from the committed state.
func (m *MemoryStateDB) GetCommittedState(addr types.Address, key types.Hash) types.Hash {
	acct := m.getAccount(addr)
	if acct == nil {
		return types.Hash{}
	}
	return acct.committedStorage[key]
}

// SetState sets the value of a storage slot. Returns the previous value.
func (m *MemoryStateDB) SetState(addr types.Address, key, value types.Hash) types.Hash {
	acct := m.getOrCreateAccount(addr)
	prev := acct.storage[key]
	acct.storage[key] = value
	return prev
}

// GetStorageRoot returns the storage root of the given account. For the
// in-memory implementation, this returns the empty root hash.
func (m *MemoryStateDB) GetStorageRoot(addr types.Address) types.Hash {
	return types.EmptyRootHash
}

// GetTransientState returns a value from transient storage.
func (m *MemoryStateDB) GetTransientState(addr types.Address, key types.Hash) types.Hash {
	return m.transientStorage.Get(addr, key)
}

// SetTransientState sets a value in transient storage.
func (m *MemoryStateDB) SetTransientState(addr types.Address, key, value types.Hash) {
	m.transientStorage.Set(addr, key, value)
}

// SelfDestruct marks the given account for self-destruction.
func (m *MemoryStateDB) SelfDestruct(addr types.Address) {
	acct := m.getAccount(addr)
	if acct == nil {
		return
	}
	acct.selfDestructed = true
	acct.balance = uint256.Int{}
}

// HasSelfDestructed returns whether the given account has been self-destructed.
func (m *MemoryStateDB) HasSelfDestructed(addr types.Address) bool {
	acct := m.getAccount(addr)
	if acct == nil {
		return false
	}
	return acct.selfDestructed
}

// Selfdestruct6780 implements EIP-6780: only self-destructs if created in
// the same transaction.
func (m *MemoryStateDB) Selfdestruct6780(addr types.Address) {
	acct := m.getAccount(addr)
	if acct == nil {
		return
	}
	if acct.created {
		m.SelfDestruct(addr)
	}
}

// AddLog adds a log entry.
func (m *MemoryStateDB) AddLog(log *types.Log) {
	log.TxHash = m.txHash
	log.TxIndex = uint(m.txIndex)
	log.Index = uint(len(m.logs))
	m.logs = append(m.logs, log)
}

// AddRefund adds gas to the refund counter.
func (m *MemoryStateDB) AddRefund(gas uint64) {
	m.refund += gas
}

// SubRefund subtracts gas from the refund counter. It panics if the
// subtraction would underflow, matching geth behavior — an underflow
// indicates a gas accounting logic error that must not be silenced.
func (m *MemoryStateDB) SubRefund(gas uint64) {
	if gas > m.refund {
		panic(fmt.Sprintf("refund counter below zero (gas: %d > refund: %d)", gas, m.refund))
	}
	m.refund -= gas
}

// GetRefund returns the current refund counter.
func (m *MemoryStateDB) GetRefund() uint64 {
	return m.refund
}

// AddPreimage records a SHA3 preimage.
func (m *MemoryStateDB) AddPreimage(hash types.Hash, preimage []byte) {
	if _, ok := m.preimages[hash]; !ok {
		cp := make([]byte, len(preimage))
		copy(cp, preimage)
		m.preimages[hash] = cp
	}
}

// AddressInAccessList returns whether the address is in the access list.
func (m *MemoryStateDB) AddressInAccessList(addr types.Address) bool {
	return m.accessList.ContainsAddress(addr)
}

// SlotInAccessList returns whether the address and slot are in the access list.
func (m *MemoryStateDB) SlotInAccessList(addr types.Address, slot types.Hash) (bool, bool) {
	return m.accessList.Contains(addr, slot)
}

// AddAddressToAccessList adds an address to the access list.
func (m *MemoryStateDB) AddAddressToAccessList(addr types.Address) {
	m.accessList.AddAddress(addr)
}

// AddSlotToAccessList adds an address+slot pair to the access list.
func (m *MemoryStateDB) AddSlotToAccessList(addr types.Address, slot types.Hash) {
	m.accessList.AddSlot(addr, slot)
}

// Snapshot creates a snapshot and returns a revision id.
func (m *MemoryStateDB) Snapshot() int {
	snap := memorySnapshot{
		accounts: m.deepCopyAccounts(),
		refund:   m.refund,
		logSize:  len(m.logs),
	}
	id := len(m.snapshots)
	m.snapshots = append(m.snapshots, snap)
	return id
}

// RevertToSnapshot reverts state to the given snapshot. If the
// revision id is invalid the call is silently ignored to avoid
// crashing the node on a stale or out-of-range snapshot id.
func (m *MemoryStateDB) RevertToSnapshot(revid int) {
	if revid < 0 || revid >= len(m.snapshots) {
		return
	}
	snap := m.snapshots[revid]
	m.accounts = snap.accounts
	m.refund = snap.refund
	m.logs = m.logs[:snap.logSize]
	m.snapshots = m.snapshots[:revid]
}

// Prepare sets up the access list for an upcoming transaction.
func (m *MemoryStateDB) Prepare(rules vm.Rules, sender, coinbase types.Address, dest *types.Address, precompiles []types.Address, txAccess types.AccessList) {
	if rules.IsBerlin {
		m.accessList = newAccessList()
		m.accessList.AddAddress(sender)
		if dest != nil {
			m.accessList.AddAddress(*dest)
		}
		for _, addr := range precompiles {
			m.accessList.AddAddress(addr)
		}
		for _, tuple := range txAccess {
			m.accessList.AddAddress(tuple.Address)
			for _, key := range tuple.StorageKeys {
				m.accessList.AddSlot(tuple.Address, key)
			}
		}
		if rules.IsShanghai {
			m.accessList.AddAddress(coinbase)
		}
	}
	m.transientStorage = newTransientStorage()
}

// deepCopyAccounts creates a deep copy of all accounts.
func (m *MemoryStateDB) deepCopyAccounts() map[types.Address]*memoryAccount {
	cp := make(map[types.Address]*memoryAccount, len(m.accounts))
	for addr, acct := range m.accounts {
		newAcct := &memoryAccount{
			nonce:            acct.nonce,
			balance:          acct.balance,
			codeHash:         acct.codeHash,
			selfDestructed:   acct.selfDestructed,
			created:          acct.created,
			storage:          make(map[types.Hash]types.Hash, len(acct.storage)),
			committedStorage: make(map[types.Hash]types.Hash, len(acct.committedStorage)),
		}
		if acct.code != nil {
			newAcct.code = make([]byte, len(acct.code))
			copy(newAcct.code, acct.code)
		}
		for k, v := range acct.storage {
			newAcct.storage[k] = v
		}
		for k, v := range acct.committedStorage {
			newAcct.committedStorage[k] = v
		}
		cp[addr] = newAcct
	}
	return cp
}

// SetTxContext sets the current transaction hash and index for log attribution.
func (m *MemoryStateDB) SetTxContext(txHash types.Hash, txIndex int) {
	m.txHash = txHash
	m.txIndex = txIndex
}

// GetLogs returns the logs matching the specified transaction hash, and annotates
// them with the given blockNumber and blockHash.
func (m *MemoryStateDB) GetLogs(txHash types.Hash, blockNumber uint64, blockHash types.Hash) []*types.Log {
	var result []*types.Log
	for _, l := range m.logs {
		if l.TxHash == txHash {
			l.BlockNumber = blockNumber
			l.BlockHash = blockHash
			result = append(result, l)
		}
	}
	return result
}

// Logs returns all accumulated logs across all transactions.
func (m *MemoryStateDB) Logs() []*types.Log {
	cpy := make([]*types.Log, len(m.logs))
	copy(cpy, m.logs)
	return cpy
}

// Preimages returns all recorded SHA3 preimages.
func (m *MemoryStateDB) Preimages() map[types.Hash][]byte {
	return m.preimages
}

// TxIndex returns the current transaction index set by SetTxContext.
func (m *MemoryStateDB) TxIndex() int {
	return m.txIndex
}

// SetBalance sets the balance for the given address directly. This is used
// by genesis initialisation to set initial balances without going through
// the Add/Sub path.
func (m *MemoryStateDB) SetBalance(addr types.Address, amount *uint256.Int) {
	acct := m.getOrCreateAccount(addr)
	acct.balance.Set(amount)
}

// IntermediateRoot computes a deterministic hash of all account state. For
// MemoryStateDB, which has no backing trie, this sorts all account addresses,
// encodes their state, and keccak256-hashes the result.
func (m *MemoryStateDB) IntermediateRoot(deleteEmptyObjects bool) types.Hash {
	m.Finalise(deleteEmptyObjects)

	if len(m.accounts) == 0 {
		return types.EmptyRootHash
	}

	// Sort addresses for deterministic ordering.
	addrs := make([]types.Address, 0, len(m.accounts))
	for addr := range m.accounts {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return string(addrs[i][:]) < string(addrs[j][:])
	})

	// Build a deterministic blob: for each account, append address + nonce
	// + balance + codeHash + sorted storage keys and values.
	var buf []byte
	for _, addr := range addrs {
		acct := m.accounts[addr]
		buf = append(buf, addr[:]...)

		// Encode nonce as 8 bytes big-endian.
		nonceBuf := [8]byte{
			byte(acct.nonce >> 56), byte(acct.nonce >> 48),
			byte(acct.nonce >> 40), byte(acct.nonce >> 32),
			byte(acct.nonce >> 24), byte(acct.nonce >> 16),
			byte(acct.nonce >> 8), byte(acct.nonce),
		}
		buf = append(buf, nonceBuf[:]...)

		// Encode balance as 32 bytes big-endian.
		balBytes := acct.balance.Bytes32()
		buf = append(buf, balBytes[:]...)

		// Code hash.
		buf = append(buf, acct.codeHash[:]...)

		// Sorted storage.
		storageKeys := make([]types.Hash, 0, len(acct.committedStorage))
		for k := range acct.committedStorage {
			storageKeys = append(storageKeys, k)
		}
		sort.Slice(storageKeys, func(i, j int) bool {
			return string(storageKeys[i][:]) < string(storageKeys[j][:])
		})
		for _, k := range storageKeys {
			v := acct.committedStorage[k]
			buf = append(buf, k[:]...)
			buf = append(buf, v[:]...)
		}
	}

	return types.BytesToHash(crypto.Keccak256(buf))
}

// Finalise moves dirty storage into committed storage and removes
// self-destructed accounts (or empty accounts if deleteEmptyObjects is true).
func (m *MemoryStateDB) Finalise(deleteEmptyObjects bool) {
	toDelete := make([]types.Address, 0)
	for addr, acct := range m.accounts {
		if acct.selfDestructed || (deleteEmptyObjects && m.isAccountEmpty(acct)) {
			toDelete = append(toDelete, addr)
			continue
		}
		// Move dirty storage to committed.
		for k, v := range acct.storage {
			acct.committedStorage[k] = v
		}
	}
	for _, addr := range toDelete {
		delete(m.accounts, addr)
	}
}

// isAccountEmpty returns whether the given memory account is empty according
// to EIP-161 (zero balance, zero nonce, empty code hash).
func (m *MemoryStateDB) isAccountEmpty(acct *memoryAccount) bool {
	return acct.nonce == 0 && acct.balance.IsZero() && acct.codeHash == types.EmptyCodeHash
}

// Commit finalises the state and returns a deterministic root hash. For
// MemoryStateDB this calls Finalise and then IntermediateRoot.
func (m *MemoryStateDB) Commit(deleteEmptyObjects bool) (types.Hash, error) {
	root := m.IntermediateRoot(deleteEmptyObjects)
	return root, nil
}

// Copy creates a deep, independent copy of the MemoryStateDB.
func (m *MemoryStateDB) Copy() *MemoryStateDB {
	cp := &MemoryStateDB{
		accounts:         m.deepCopyAccounts(),
		transientStorage: m.transientStorage.Copy(),
		accessList:       m.accessList.Copy(),
		refund:           m.refund,
		txHash:           m.txHash,
		txIndex:          m.txIndex,
		preimages:        make(map[types.Hash][]byte, len(m.preimages)),
	}

	// Deep copy logs.
	if m.logs != nil {
		cp.logs = make([]*types.Log, len(m.logs))
		for i, l := range m.logs {
			logCopy := new(types.Log)
			*logCopy = *l
			if l.Topics != nil {
				logCopy.Topics = make([]types.Hash, len(l.Topics))
				copy(logCopy.Topics, l.Topics)
			}
			if l.Data != nil {
				logCopy.Data = make([]byte, len(l.Data))
				copy(logCopy.Data, l.Data)
			}
			cp.logs[i] = logCopy
		}
	}

	// Deep copy preimages.
	for k, v := range m.preimages {
		cv := make([]byte, len(v))
		copy(cv, v)
		cp.preimages[k] = cv
	}

	// Snapshots are NOT copied; they reference the original state and
	// cannot be meaningfully applied to the copy.

	return cp
}

// GetProof returns an empty Merkle proof. MemoryStateDB has no backing trie,
// so no real proof can be generated.
func (m *MemoryStateDB) GetProof(addr types.Address) ([][]byte, error) {
	return [][]byte{}, nil
}

// GetStorageProof returns an empty storage proof. MemoryStateDB has no
// backing trie, so no real proof can be generated.
func (m *MemoryStateDB) GetStorageProof(addr types.Address, slot types.Hash) ([][]byte, error) {
	return [][]byte{}, nil
}

// StartAccessRecording is a no-op for MemoryStateDB. The in-memory
// implementation does not track access for prover state export.
func (m *MemoryStateDB) StartAccessRecording() {}

// StopAccessRecording returns an empty AccessRecording. MemoryStateDB does
// not track access for prover state export.
func (m *MemoryStateDB) StopAccessRecording() *AccessRecording {
	return &AccessRecording{
		Slots: make(map[types.Address][]types.Hash),
	}
}

// Database returns nil. MemoryStateDB has no backing database.
func (m *MemoryStateDB) Database() interface{} {
	return nil
}

// Error returns nil. MemoryStateDB does not encounter database errors.
func (m *MemoryStateDB) Error() error {
	return nil
}
