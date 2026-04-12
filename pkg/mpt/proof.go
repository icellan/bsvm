// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package mpt

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *Trie) Prove(key []byte, proofDb db.Database) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	// Collect all nodes on the path to key.
	var (
		prefix []byte
		nodes  []node
		tn     = t.root
	)
	key = keybytesToHex(key)
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {
		case *shortNode:
			if !bytes.HasPrefix(key, n.Key) {
				tn = nil
			} else {
				tn = n.Val
				prefix = append(prefix, n.Key...)
				key = key[len(n.Key):]
			}
			nodes = append(nodes, n)
		case *fullNode:
			tn = n.Children[key[0]]
			prefix = append(prefix, key[0])
			key = key[1:]
			nodes = append(nodes, n)
		case hashNode:
			blob, err := t.reader.node(prefix, types.BytesToHash(n))
			if err != nil {
				slog.Error("Unhandled trie error in Trie.Prove", "err", err)
				return err
			}
			decoded, err := decodeNodeUnsafe(n, blob)
			if err != nil {
				return fmt.Errorf("corrupted trie node %x: %v", n, err)
			}
			tn = decoded
		default:
			return fmt.Errorf("corrupted trie node: %T", tn)
		}
	}
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)

	for i, n := range nodes {
		var hn node
		n, hn = hasher.proofHash(n)
		if hash, ok := hn.(hashNode); ok || i == 0 {
			enc := nodeToBytes(n)
			if !ok {
				hash = hasher.hashData(enc)
			}
			proofDb.Put(hash, enc)
		}
	}
	return nil
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key.
func (t *StateTrie) Prove(key []byte, proofDb db.Database) error {
	return t.trie.Prove(key, proofDb)
}

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProof(rootHash types.Hash, key []byte, proofDb db.Database) (value []byte, err error) {
	key = keybytesToHex(key)
	wantHash := rootHash
	for i := 0; ; i++ {
		buf, _ := proofDb.Get(wantHash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node %d (hash %064x) missing", i, wantHash)
		}
		n, err := decodeNode(wantHash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %d: %v", i, err)
		}
		keyrest, cld, err := get(n, key, true)
		if err != nil {
			return nil, err
		}
		switch cld := cld.(type) {
		case nil:
			return nil, nil
		case hashNode:
			key = keyrest
			copy(wantHash[:], cld)
		case valueNode:
			return cld, nil
		}
	}
}

// proofToPath converts a merkle proof to trie node path.
func proofToPath(rootHash types.Hash, root node, key []byte, proofDb db.Database, allowNonExistent bool) (node, []byte, error) {
	resolveNode := func(hash types.Hash) (node, error) {
		buf, _ := proofDb.Get(hash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node (hash %064x) missing", hash)
		}
		n, err := decodeNode(hash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %v", err)
		}
		return n, err
	}
	if root == nil {
		n, err := resolveNode(rootHash)
		if err != nil {
			return nil, nil, err
		}
		root = n
	}
	var (
		err           error
		child, parent node
		keyrest       []byte
		valnode       []byte
	)
	key, parent = keybytesToHex(key), root
	for {
		var getErr error
		keyrest, child, getErr = get(parent, key, false)
		if getErr != nil {
			return nil, nil, getErr
		}
		switch cld := child.(type) {
		case nil:
			if allowNonExistent {
				return root, nil, nil
			}
			return nil, nil, errors.New("the node is not contained in trie")
		case *shortNode:
			key, parent = keyrest, child
			continue
		case *fullNode:
			key, parent = keyrest, child
			continue
		case hashNode:
			child, err = resolveNode(types.BytesToHash(cld))
			if err != nil {
				return nil, nil, err
			}
		case valueNode:
			valnode = cld
		}
		switch pnode := parent.(type) {
		case *shortNode:
			pnode.Val = child
		case *fullNode:
			pnode.Children[key[0]] = child
		default:
			return nil, nil, fmt.Errorf("corrupted trie node: %T", pnode)
		}
		if len(valnode) > 0 {
			return root, valnode, nil
		}
		key, parent = keyrest, child
	}
}

// VerifyRangeProof checks whether the given leaf nodes and edge proof
// can prove the given trie leaves range is matched with the specific root.
func VerifyRangeProof(rootHash types.Hash, firstKey []byte, keys [][]byte, values [][]byte, proof db.Database) (bool, error) {
	if len(keys) != len(values) {
		return false, fmt.Errorf("inconsistent proof data, keys: %d, values: %d", len(keys), len(values))
	}
	for i := 0; i < len(keys); i++ {
		if i < len(keys)-1 {
			if bytes.Compare(keys[i], keys[i+1]) >= 0 {
				return false, errors.New("range is not monotonically increasing")
			}
			if bytes.HasPrefix(keys[i+1], keys[i]) {
				return false, errors.New("range contains path prefixes")
			}
		}
		if len(values[i]) == 0 {
			return false, errors.New("range contains deletion")
		}
	}
	if proof == nil {
		tr := NewStackTrie(nil)
		for index, key := range keys {
			tr.Update(key, values[index])
		}
		if have, want := tr.Hash(), rootHash; have != want {
			return false, fmt.Errorf("invalid proof, want hash %x, got %x", want, have)
		}
		return false, nil
	}
	if len(keys) == 0 {
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, true)
		if err != nil {
			return false, err
		}
		hasRight, err := hasRightElement(root, firstKey)
		if err != nil {
			return false, err
		}
		if val != nil || hasRight {
			return false, errors.New("more entries available")
		}
		return false, nil
	}
	var lastKey = keys[len(keys)-1]
	if len(keys) == 1 && bytes.Equal(firstKey, lastKey) {
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, false)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(firstKey, keys[0]) {
			return false, errors.New("correct proof but invalid key")
		}
		if !bytes.Equal(val, values[0]) {
			return false, errors.New("correct proof but invalid data")
		}
		hasRight, err := hasRightElement(root, firstKey)
		if err != nil {
			return false, err
		}
		return hasRight, nil
	}
	if bytes.Compare(firstKey, lastKey) >= 0 {
		return false, errors.New("invalid edge keys")
	}
	if len(firstKey) != len(lastKey) {
		return false, errors.New("inconsistent edge keys")
	}
	root, _, err := proofToPath(rootHash, nil, firstKey, proof, true)
	if err != nil {
		return false, err
	}
	root, _, err = proofToPath(rootHash, root, lastKey, proof, true)
	if err != nil {
		return false, err
	}
	empty, err := unsetInternal(root, firstKey, lastKey)
	if err != nil {
		return false, err
	}
	tr := &Trie{root: root, reader: newEmptyReader(), tracer: newTracer()}
	if empty {
		tr.root = nil
	}
	for index, key := range keys {
		tr.Update(key, values[index])
	}
	if tr.Hash() != rootHash {
		return false, fmt.Errorf("invalid proof, want hash %x, got %x", rootHash, tr.Hash())
	}
	hasRight, err := hasRightElement(tr.root, keys[len(keys)-1])
	if err != nil {
		return false, err
	}
	return hasRight, nil
}

func unsetInternal(n node, left []byte, right []byte) (bool, error) {
	left, right = keybytesToHex(left), keybytesToHex(right)
	var (
		pos                           = 0
		parent                        node
		shortForkLeft, shortForkRight int
	)
findFork:
	for {
		switch rn := (n).(type) {
		case *shortNode:
			rn.flags = nodeFlag{dirty: true}
			if len(left)-pos < len(rn.Key) {
				shortForkLeft = bytes.Compare(left[pos:], rn.Key)
			} else {
				shortForkLeft = bytes.Compare(left[pos:pos+len(rn.Key)], rn.Key)
			}
			if len(right)-pos < len(rn.Key) {
				shortForkRight = bytes.Compare(right[pos:], rn.Key)
			} else {
				shortForkRight = bytes.Compare(right[pos:pos+len(rn.Key)], rn.Key)
			}
			if shortForkLeft != 0 || shortForkRight != 0 {
				break findFork
			}
			parent = n
			n, pos = rn.Val, pos+len(rn.Key)
		case *fullNode:
			rn.flags = nodeFlag{dirty: true}
			leftnode, rightnode := rn.Children[left[pos]], rn.Children[right[pos]]
			if leftnode == nil || rightnode == nil || leftnode != rightnode {
				break findFork
			}
			parent = n
			n, pos = rn.Children[left[pos]], pos+1
		default:
			return false, fmt.Errorf("corrupted trie node: %T", n)
		}
	}
	switch rn := n.(type) {
	case *shortNode:
		if shortForkLeft == -1 && shortForkRight == -1 {
			return false, errors.New("empty range")
		}
		if shortForkLeft == 1 && shortForkRight == 1 {
			return false, errors.New("empty range")
		}
		if shortForkLeft != 0 && shortForkRight != 0 {
			if parent == nil {
				return true, nil
			}
			parent.(*fullNode).Children[left[pos-1]] = nil
			return false, nil
		}
		if shortForkRight != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[left[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, left[pos:], len(rn.Key), false)
		}
		if shortForkLeft != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[right[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, right[pos:], len(rn.Key), true)
		}
		return false, nil
	case *fullNode:
		for i := left[pos] + 1; i < right[pos]; i++ {
			rn.Children[i] = nil
		}
		if err := unset(rn, rn.Children[left[pos]], left[pos:], 1, false); err != nil {
			return false, err
		}
		if err := unset(rn, rn.Children[right[pos]], right[pos:], 1, true); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, fmt.Errorf("corrupted trie node: %T", n)
	}
}

func unset(parent node, child node, key []byte, pos int, removeLeft bool) error {
	switch cld := child.(type) {
	case *fullNode:
		if removeLeft {
			for i := 0; i < int(key[pos]); i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
		} else {
			for i := key[pos] + 1; i < 16; i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
		}
		return unset(cld, cld.Children[key[pos]], key, pos+1, removeLeft)
	case *shortNode:
		if !bytes.HasPrefix(key[pos:], cld.Key) {
			if removeLeft {
				if bytes.Compare(cld.Key, key[pos:]) < 0 {
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				}
			} else {
				if bytes.Compare(cld.Key, key[pos:]) > 0 {
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				}
			}
			return nil
		}
		if _, ok := cld.Val.(valueNode); ok {
			fn := parent.(*fullNode)
			fn.Children[key[pos-1]] = nil
			return nil
		}
		cld.flags = nodeFlag{dirty: true}
		return unset(cld, cld.Val, key, pos+len(cld.Key), removeLeft)
	case nil:
		return nil
	default:
		return fmt.Errorf("corrupted trie node: %T", child)
	}
}

func hasRightElement(node node, key []byte) (bool, error) {
	pos, key := 0, keybytesToHex(key)
	for node != nil {
		switch rn := node.(type) {
		case *fullNode:
			for i := key[pos] + 1; i < 16; i++ {
				if rn.Children[i] != nil {
					return true, nil
				}
			}
			node, pos = rn.Children[key[pos]], pos+1
		case *shortNode:
			if !bytes.HasPrefix(key[pos:], rn.Key) {
				return bytes.Compare(rn.Key, key[pos:]) > 0, nil
			}
			node, pos = rn.Val, pos+len(rn.Key)
		case valueNode:
			return false, nil
		default:
			return false, fmt.Errorf("corrupted trie node: %T", node)
		}
	}
	return false, nil
}

// get returns the child of the given node.
func get(tn node, key []byte, skipResolved bool) ([]byte, node, error) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if !bytes.HasPrefix(key, n.Key) {
				return nil, nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
			if !skipResolved {
				return key, tn, nil
			}
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
			if !skipResolved {
				return key, tn, nil
			}
		case hashNode:
			return key, n, nil
		case nil:
			return key, nil, nil
		case valueNode:
			return nil, n, nil
		default:
			return nil, nil, fmt.Errorf("corrupted trie node: %T", tn)
		}
	}
}
