package state

import "github.com/icellan/bsvm/pkg/types"

// accessList implements EIP-2929 warm/cold access tracking. It tracks which
// addresses and storage slots have been accessed during transaction execution.
type accessList struct {
	addresses map[types.Address]int     // address -> index into slots, or -1 if no slots
	slots     []map[types.Hash]struct{} // per-address slot sets
}

// newAccessList creates a new empty access list.
func newAccessList() *accessList {
	return &accessList{
		addresses: make(map[types.Address]int),
	}
}

// ContainsAddress returns whether the given address is in the access list.
func (al *accessList) ContainsAddress(address types.Address) bool {
	_, ok := al.addresses[address]
	return ok
}

// Contains checks if the address and slot are in the access list. The first
// return value indicates if the address is present, the second indicates if
// the slot is present.
func (al *accessList) Contains(address types.Address, slot types.Hash) (bool, bool) {
	idx, addrPresent := al.addresses[address]
	if !addrPresent || idx == -1 {
		return addrPresent, false
	}
	_, slotPresent := al.slots[idx][slot]
	return addrPresent, slotPresent
}

// AddAddress adds an address to the access list. Returns true if the address
// was not already present.
func (al *accessList) AddAddress(address types.Address) bool {
	if _, present := al.addresses[address]; present {
		return false
	}
	al.addresses[address] = -1
	return true
}

// AddSlot adds an address and slot pair to the access list. Returns two booleans:
// the first indicates if the address was added, the second if the slot was added.
func (al *accessList) AddSlot(address types.Address, slot types.Hash) (bool, bool) {
	idx, addrPresent := al.addresses[address]
	if !addrPresent || idx == -1 {
		// Address not present, or present but with no slot set yet.
		al.slots = append(al.slots, map[types.Hash]struct{}{slot: {}})
		newIdx := len(al.slots) - 1
		al.addresses[address] = newIdx
		return !addrPresent, true
	}
	// Address already present with a slot set.
	if _, slotPresent := al.slots[idx][slot]; slotPresent {
		return false, false
	}
	al.slots[idx][slot] = struct{}{}
	return false, true
}

// DeleteSlot removes a specific slot from the access list for the given address.
func (al *accessList) DeleteSlot(address types.Address, slot types.Hash) {
	idx, ok := al.addresses[address]
	if !ok || idx == -1 {
		return
	}
	delete(al.slots[idx], slot)
}

// DeleteAddress removes an address from the access list entirely.
func (al *accessList) DeleteAddress(address types.Address) {
	delete(al.addresses, address)
}

// DeleteExtraSlot removes the last slot set appended for the given address,
// reverting the address to having no slot tracking.
func (al *accessList) DeleteExtraSlot(address types.Address) {
	idx, ok := al.addresses[address]
	if !ok || idx == -1 {
		return
	}
	// Remove the slot set and revert the address to -1 (no slots).
	al.slots = al.slots[:len(al.slots)-1]
	al.addresses[address] = -1
}

// Entries returns the access list contents as a slice of AccessListEntry.
// Each entry contains an address and its associated storage keys. Addresses
// with no tracked slots are included with an empty storage keys slice.
func (al *accessList) Entries() []AccessListEntry {
	entries := make([]AccessListEntry, 0, len(al.addresses))
	for addr, idx := range al.addresses {
		entry := AccessListEntry{Address: addr}
		if idx >= 0 && idx < len(al.slots) {
			for slot := range al.slots[idx] {
				entry.StorageKeys = append(entry.StorageKeys, slot)
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// AccessListEntry holds an address and its associated storage keys from the
// access list. This is used by eth_createAccessList to return the collected
// accesses.
type AccessListEntry struct {
	Address     types.Address
	StorageKeys []types.Hash
}

// Copy creates a deep copy of the access list.
func (al *accessList) Copy() *accessList {
	cp := newAccessList()
	for k, v := range al.addresses {
		cp.addresses[k] = v
	}
	cp.slots = make([]map[types.Hash]struct{}, len(al.slots))
	for i, slotMap := range al.slots {
		cp.slots[i] = make(map[types.Hash]struct{}, len(slotMap))
		for k := range slotMap {
			cp.slots[i][k] = struct{}{}
		}
	}
	return cp
}
