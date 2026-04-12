package types

// AccessList is an EIP-2930 access list specifying addresses and storage keys
// that a transaction plans to access.
type AccessList []AccessTuple

// AccessTuple represents a single entry in an EIP-2930 access list.
type AccessTuple struct {
	Address     Address `json:"address"`
	StorageKeys []Hash  `json:"storageKeys"`
}

// StorageKeys returns the total number of storage keys across all tuples.
func (al AccessList) StorageKeys() int {
	n := 0
	for _, tuple := range al {
		n += len(tuple.StorageKeys)
	}
	return n
}
