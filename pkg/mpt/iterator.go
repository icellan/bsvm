// Copyright 2014 The go-ethereum Authors
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
	"container/heap"
	"errors"

	"github.com/icellan/bsvm/pkg/types"
)

// NodeResolver is used for looking up trie nodes before reaching into the real
// persistent layer.
type NodeResolver func(owner types.Hash, path []byte, hash types.Hash) []byte

// Iterator is a key-value trie iterator that traverses a Trie.
type Iterator struct {
	nodeIt NodeIterator
	Key    []byte
	Value  []byte
	Err    error
}

// NewIterator creates a new key-value iterator from a node iterator.
func NewIterator(it NodeIterator) *Iterator {
	return &Iterator{nodeIt: it}
}

// Next moves the iterator forward one key-value entry.
func (it *Iterator) Next() bool {
	for it.nodeIt.Next(true) {
		if it.nodeIt.Leaf() {
			it.Key = it.nodeIt.LeafKey()
			it.Value = it.nodeIt.LeafBlob()
			return true
		}
	}
	it.Key = nil
	it.Value = nil
	it.Err = it.nodeIt.Error()
	return false
}

// Prove generates the Merkle proof for the leaf node the iterator is currently positioned on.
func (it *Iterator) Prove() [][]byte {
	return it.nodeIt.LeafProof()
}

// NodeIterator is an iterator to traverse the trie pre-order.
type NodeIterator interface {
	Next(bool) bool
	Error() error
	Hash() types.Hash
	Parent() types.Hash
	Path() []byte
	NodeBlob() []byte
	Leaf() bool
	LeafKey() []byte
	LeafBlob() []byte
	LeafProof() [][]byte
	AddResolver(NodeResolver)
}

type nodeIteratorState struct {
	hash    types.Hash
	node    node
	parent  types.Hash
	index   int
	pathlen int
}

type nodeIterator struct {
	trie     *Trie
	stack    []*nodeIteratorState
	path     []byte
	err      error
	resolver NodeResolver
	pool     []*nodeIteratorState
}

var errIteratorEnd = errors.New("end of iteration")

type seekError struct {
	key []byte
	err error
}

func (e seekError) Error() string {
	return "seek error: " + e.err.Error()
}

func newNodeIterator(trie *Trie, start []byte) NodeIterator {
	if trie.Hash() == types.EmptyRootHash {
		return &nodeIterator{trie: trie, err: errIteratorEnd}
	}
	it := &nodeIterator{trie: trie}
	it.err = it.seek(start)
	return it
}

func (it *nodeIterator) putInPool(item *nodeIteratorState) {
	if len(it.pool) < 40 {
		item.node = nil
		it.pool = append(it.pool, item)
	}
}

func (it *nodeIterator) getFromPool() *nodeIteratorState {
	idx := len(it.pool) - 1
	if idx < 0 {
		return new(nodeIteratorState)
	}
	el := it.pool[idx]
	it.pool[idx] = nil
	it.pool = it.pool[:idx]
	return el
}

func (it *nodeIterator) AddResolver(resolver NodeResolver) { it.resolver = resolver }

func (it *nodeIterator) Hash() types.Hash {
	if len(it.stack) == 0 {
		return types.Hash{}
	}
	return it.stack[len(it.stack)-1].hash
}

func (it *nodeIterator) Parent() types.Hash {
	if len(it.stack) == 0 {
		return types.Hash{}
	}
	return it.stack[len(it.stack)-1].parent
}

func (it *nodeIterator) Leaf() bool { return hasTerm(it.path) }

func (it *nodeIterator) LeafKey() []byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			key, err := hexToKeybytes(it.path)
			if err != nil {
				it.err = err
				return nil
			}
			return key
		}
	}
	return nil // not at leaf
}

func (it *nodeIterator) LeafBlob() []byte {
	if len(it.stack) > 0 {
		if node, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return node
		}
	}
	return nil // not at leaf
}

func (it *nodeIterator) LeafProof() [][]byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(false)
			defer returnHasherToPool(hasher)
			proofs := make([][]byte, 0, len(it.stack))
			for i, item := range it.stack[:len(it.stack)-1] {
				node, hashed := hasher.proofHash(item.node)
				if _, ok := hashed.(hashNode); ok || i == 0 {
					proofs = append(proofs, nodeToBytes(node))
				}
			}
			return proofs
		}
	}
	return nil // not at leaf
}

func (it *nodeIterator) Path() []byte { return it.path }

func (it *nodeIterator) NodeBlob() []byte {
	if it.Hash() == (types.Hash{}) {
		return nil
	}
	blob, err := it.resolveBlob(it.Hash().Bytes(), it.Path())
	if err != nil {
		it.err = err
		return nil
	}
	return blob
}

func (it *nodeIterator) Error() error {
	if it.err == errIteratorEnd {
		return nil
	}
	if seek, ok := it.err.(seekError); ok {
		return seek.err
	}
	return it.err
}

func (it *nodeIterator) Next(descend bool) bool {
	if it.err == errIteratorEnd {
		return false
	}
	if seek, ok := it.err.(seekError); ok {
		if it.err = it.seek(seek.key); it.err != nil {
			return false
		}
	}
	state, parentIndex, path, err := it.peek(descend)
	it.err = err
	if it.err != nil {
		return false
	}
	it.push(state, parentIndex, path)
	return true
}

func (it *nodeIterator) seek(prefix []byte) error {
	key := keybytesToHex(prefix)
	key = key[:len(key)-1]
	for {
		state, parentIndex, path, err := it.peekSeek(key)
		if err == errIteratorEnd {
			return errIteratorEnd
		} else if err != nil {
			return seekError{prefix, err}
		} else if reachedPath(path, key) {
			return nil
		}
		it.push(state, parentIndex, path)
	}
}

func (it *nodeIterator) init() (*nodeIteratorState, error) {
	root := it.trie.Hash()
	state := &nodeIteratorState{node: it.trie.root, index: -1}
	if root != types.EmptyRootHash {
		state.hash = root
	}
	return state, state.resolve(it, nil)
}

func (it *nodeIterator) peek(descend bool) (*nodeIteratorState, *int, []byte, error) {
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !descend {
		it.pop()
	}
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == types.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChild(parent, ancestor)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

func (it *nodeIterator) peekSeek(seekKey []byte) (*nodeIteratorState, *int, []byte, error) {
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !bytes.HasPrefix(seekKey, it.path) {
		it.pop()
	}
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == types.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChildAt(parent, ancestor, seekKey)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

func (it *nodeIterator) resolveHash(hash hashNode, path []byte) (node, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, types.BytesToHash(hash)); len(blob) > 0 {
			if resolved, err := decodeNode(hash, blob); err == nil {
				return resolved, nil
			}
		}
	}
	blob, err := it.trie.reader.node(path, types.BytesToHash(hash))
	if err != nil {
		return nil, err
	}
	return decodeNodeUnsafe(hash, blob)
}

func (it *nodeIterator) resolveBlob(hash hashNode, path []byte) ([]byte, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, types.BytesToHash(hash)); len(blob) > 0 {
			return blob, nil
		}
	}
	return it.trie.reader.node(path, types.BytesToHash(hash))
}

func (st *nodeIteratorState) resolve(it *nodeIterator, path []byte) error {
	if hash, ok := st.node.(hashNode); ok {
		resolved, err := it.resolveHash(hash, path)
		if err != nil {
			return err
		}
		st.node = resolved
		st.hash = types.BytesToHash(hash)
	}
	return nil
}

func (it *nodeIterator) findChild(n *fullNode, index int, ancestor types.Hash) (node, *nodeIteratorState, []byte, int) {
	var (
		path      = it.path
		child     node
		state     *nodeIteratorState
		childPath []byte
	)
	for ; index < len(n.Children); index = nextChildIndex(index) {
		if n.Children[index] != nil {
			child = n.Children[index]
			hash, _ := child.cache()
			state = it.getFromPool()
			state.hash = types.BytesToHash(hash)
			state.node = child
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(path)
			childPath = append(childPath, path...)
			childPath = append(childPath, byte(index))
			return child, state, childPath, index
		}
	}
	return nil, nil, nil, 0
}

func (it *nodeIterator) nextChild(parent *nodeIteratorState, ancestor types.Hash) (*nodeIteratorState, []byte, bool) {
	switch node := parent.node.(type) {
	case *fullNode:
		if child, state, path, index := it.findChild(node, nextChildIndex(parent.index), ancestor); child != nil {
			parent.index = prevChildIndex(index)
			return state, path, true
		}
	case *shortNode:
		if parent.index < 0 {
			hash, _ := node.Val.cache()
			state := it.getFromPool()
			state.hash = types.BytesToHash(hash)
			state.node = node.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, node.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

func (it *nodeIterator) nextChildAt(parent *nodeIteratorState, ancestor types.Hash, key []byte) (*nodeIteratorState, []byte, bool) {
	switch n := parent.node.(type) {
	case *fullNode:
		child, state, path, index := it.findChild(n, nextChildIndex(parent.index), ancestor)
		if child == nil {
			return parent, it.path, false
		}
		if reachedPath(path, key) {
			parent.index = prevChildIndex(index)
			return state, path, true
		}
		for {
			nextChild, nextState, nextPath, nextIndex := it.findChild(n, nextChildIndex(index), ancestor)
			if nextChild == nil || reachedPath(nextPath, key) {
				parent.index = prevChildIndex(index)
				return state, path, true
			}
			state, path, index = nextState, nextPath, nextIndex
		}
	case *shortNode:
		if parent.index < 0 {
			hash, _ := n.Val.cache()
			state := it.getFromPool()
			state.hash = types.BytesToHash(hash)
			state.node = n.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, n.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

func (it *nodeIterator) push(state *nodeIteratorState, parentIndex *int, path []byte) {
	it.path = path
	it.stack = append(it.stack, state)
	if parentIndex != nil {
		*parentIndex = nextChildIndex(*parentIndex)
	}
}

func (it *nodeIterator) pop() {
	last := it.stack[len(it.stack)-1]
	it.path = it.path[:last.pathlen]
	it.stack[len(it.stack)-1] = nil
	it.stack = it.stack[:len(it.stack)-1]
	it.putInPool(last)
}

func reachedPath(path, target []byte) bool {
	if hasTerm(path) {
		path = path[:len(path)-1]
	}
	return bytes.Compare(path, target) >= 0
}

func prevChildIndex(index int) int {
	switch index {
	case 0:
		return 16
	case 16:
		return -1
	case 17:
		return 15
	default:
		return index - 1
	}
}

func nextChildIndex(index int) int {
	switch index {
	case -1:
		return 16
	case 15:
		return 17
	case 16:
		return 0
	default:
		return index + 1
	}
}

func compareNodes(a, b NodeIterator) int {
	if cmp := bytes.Compare(a.Path(), b.Path()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && !b.Leaf() {
		return -1
	} else if b.Leaf() && !a.Leaf() {
		return 1
	}
	if cmp := bytes.Compare(a.Hash().Bytes(), b.Hash().Bytes()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && b.Leaf() {
		return bytes.Compare(a.LeafBlob(), b.LeafBlob())
	}
	return 0
}

type differenceIterator struct {
	a, b  NodeIterator
	eof   bool
	count int
}

// NewDifferenceIterator constructs a NodeIterator that iterates over elements in b not in a.
func NewDifferenceIterator(a, b NodeIterator) (NodeIterator, *int) {
	a.Next(true)
	it := &differenceIterator{a: a, b: b}
	return it, &it.count
}

func (it *differenceIterator) Hash() types.Hash                  { return it.b.Hash() }
func (it *differenceIterator) Parent() types.Hash                { return it.b.Parent() }
func (it *differenceIterator) Leaf() bool                        { return it.b.Leaf() }
func (it *differenceIterator) LeafKey() []byte                   { return it.b.LeafKey() }
func (it *differenceIterator) LeafBlob() []byte                  { return it.b.LeafBlob() }
func (it *differenceIterator) LeafProof() [][]byte               { return it.b.LeafProof() }
func (it *differenceIterator) Path() []byte                      { return it.b.Path() }
func (it *differenceIterator) NodeBlob() []byte                  { return it.b.NodeBlob() }
func (it *differenceIterator) AddResolver(resolver NodeResolver) {}
func (it *differenceIterator) Error() error {
	if err := it.a.Error(); err != nil {
		return err
	}
	return it.b.Error()
}

func (it *differenceIterator) Next(bool) bool {
	if !it.b.Next(true) {
		return false
	}
	it.count++
	if it.eof {
		return true
	}
	for {
		switch compareNodes(it.a, it.b) {
		case -1:
			if !it.a.Next(true) {
				it.eof = true
				return true
			}
			it.count++
		case 1:
			return true
		case 0:
			hasHash := it.a.Hash() == types.Hash{}
			if !it.b.Next(hasHash) {
				return false
			}
			it.count++
			if !it.a.Next(hasHash) {
				it.eof = true
				return true
			}
			it.count++
		}
	}
}

type nodeIteratorHeap []NodeIterator

func (h nodeIteratorHeap) Len() int            { return len(h) }
func (h nodeIteratorHeap) Less(i, j int) bool  { return compareNodes(h[i], h[j]) < 0 }
func (h nodeIteratorHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeIteratorHeap) Push(x interface{}) { *h = append(*h, x.(NodeIterator)) }
func (h *nodeIteratorHeap) Pop() interface{} {
	n := len(*h)
	x := (*h)[n-1]
	*h = (*h)[0 : n-1]
	return x
}

type unionIterator struct {
	items *nodeIteratorHeap
	count int
}

// NewUnionIterator constructs a NodeIterator that iterates over elements in the union.
func NewUnionIterator(iters []NodeIterator) (NodeIterator, *int) {
	h := make(nodeIteratorHeap, len(iters))
	copy(h, iters)
	heap.Init(&h)
	ui := &unionIterator{items: &h}
	return ui, &ui.count
}

func (it *unionIterator) Hash() types.Hash                  { return (*it.items)[0].Hash() }
func (it *unionIterator) Parent() types.Hash                { return (*it.items)[0].Parent() }
func (it *unionIterator) Leaf() bool                        { return (*it.items)[0].Leaf() }
func (it *unionIterator) LeafKey() []byte                   { return (*it.items)[0].LeafKey() }
func (it *unionIterator) LeafBlob() []byte                  { return (*it.items)[0].LeafBlob() }
func (it *unionIterator) LeafProof() [][]byte               { return (*it.items)[0].LeafProof() }
func (it *unionIterator) Path() []byte                      { return (*it.items)[0].Path() }
func (it *unionIterator) NodeBlob() []byte                  { return (*it.items)[0].NodeBlob() }
func (it *unionIterator) AddResolver(resolver NodeResolver) {}
func (it *unionIterator) Error() error {
	for i := 0; i < len(*it.items); i++ {
		if err := (*it.items)[i].Error(); err != nil {
			return err
		}
	}
	return nil
}

func (it *unionIterator) Next(descend bool) bool {
	if len(*it.items) == 0 {
		return false
	}
	least := heap.Pop(it.items).(NodeIterator)
	for len(*it.items) > 0 && ((!descend && bytes.HasPrefix((*it.items)[0].Path(), least.Path())) || compareNodes(least, (*it.items)[0]) == 0) {
		skipped := heap.Pop(it.items).(NodeIterator)
		if skipped.Next(skipped.Hash() == types.Hash{}) {
			it.count++
			heap.Push(it.items, skipped)
		}
	}
	if least.Next(descend) {
		it.count++
		heap.Push(it.items, least)
	}
	return len(*it.items) > 0
}
