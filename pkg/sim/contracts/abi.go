package contracts

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// selector returns the first 4 bytes of keccak256(signature).
func selector(sig string) [4]byte {
	h := crypto.Keccak256([]byte(sig))
	var s [4]byte
	copy(s[:], h[:4])
	return s
}

// Precomputed 4-byte selectors. Using vars (not consts) because crypto.Keccak256
// requires a runtime call; the values are computed once on package init.
var (
	selERC20Transfer     = selector("transfer(address,uint256)")
	selERC20Approve      = selector("approve(address,uint256)")
	selERC20TransferFrom = selector("transferFrom(address,address,uint256)")
	selERC20BalanceOf    = selector("balanceOf(address)")

	selERC721Mint         = selector("mint(address)")
	selERC721Approve      = selector("approve(address,uint256)")
	selERC721TransferFrom = selector("transferFrom(address,address,uint256)")

	selWETHDeposit   = selector("deposit()")
	selWETHWithdraw  = selector("withdraw(uint256)")
	selWETHTransfer  = selector("transfer(address,uint256)")
	selWETHBalanceOf = selector("balanceOf(address)")

	selAMMAddLiquidity = selector("addLiquidity(uint112,uint112)")
	selAMMSwap         = selector("swap(address,uint256,uint256)")

	selMultisigSubmit  = selector("submit(address,uint256,bytes)")
	selMultisigConfirm = selector("confirm(uint256)")
	selMultisigExecute = selector("execute(uint256)")
	selMultisigTxCount = selector("txCount()")

	selStorageSet = selector("set(uint256,uint256)")
)

// EncodeERC20Deploy appends uint256(initialSupply) to the creation bytecode.
func EncodeERC20Deploy(initialSupply *uint256.Int) []byte {
	code, _ := hex.DecodeString(ERC20Bytecode)
	return append(code, packUint256(initialSupply)...)
}

// EncodeERC721Deploy returns the NFT creation bytecode (no constructor args).
func EncodeERC721Deploy() []byte {
	code, _ := hex.DecodeString(ERC721Bytecode)
	return code
}

// EncodeWETHDeploy returns the WETH creation bytecode (no constructor args).
func EncodeWETHDeploy() []byte {
	code, _ := hex.DecodeString(WETHBytecode)
	return code
}

// EncodeAMMDeploy appends (address,address) constructor args.
func EncodeAMMDeploy(token0, token1 types.Address) []byte {
	code, _ := hex.DecodeString(AMMBytecode)
	return append(append(code, packAddress(token0)...), packAddress(token1)...)
}

// EncodeMultisigDeploy appends (address[] owners, uint256 required).
func EncodeMultisigDeploy(owners []types.Address, required uint64) []byte {
	code, _ := hex.DecodeString(MultisigBytecode)
	// Dynamic encoding: head has two 32-byte slots (offset-of-array, required).
	// Then the array: uint256(length) || word-packed addresses.
	offset := uint64(64) // two head slots
	head := make([]byte, 0, 64+32+len(owners)*32)
	head = append(head, packUint64(offset)...)
	head = append(head, packUint64(required)...)
	arr := packUint64(uint64(len(owners)))
	for _, a := range owners {
		arr = append(arr, packAddress(a)...)
	}
	return append(code, append(head, arr...)...)
}

// EncodeStorageDeploy returns the Storage creation bytecode (no constructor args).
func EncodeStorageDeploy() []byte {
	code, _ := hex.DecodeString(StorageBytecode)
	return code
}

// EncodeERC20Transfer encodes transfer(to, amount).
func EncodeERC20Transfer(to types.Address, amount *uint256.Int) []byte {
	return buildCall(selERC20Transfer[:], packAddress(to), packUint256(amount))
}

// EncodeERC20Approve encodes approve(spender, amount).
func EncodeERC20Approve(spender types.Address, amount *uint256.Int) []byte {
	return buildCall(selERC20Approve[:], packAddress(spender), packUint256(amount))
}

// EncodeERC20TransferFrom encodes transferFrom(from, to, amount).
func EncodeERC20TransferFrom(from, to types.Address, amount *uint256.Int) []byte {
	return buildCall(selERC20TransferFrom[:], packAddress(from), packAddress(to), packUint256(amount))
}

// EncodeERC20BalanceOf encodes balanceOf(addr).
func EncodeERC20BalanceOf(addr types.Address) []byte {
	return buildCall(selERC20BalanceOf[:], packAddress(addr))
}

// EncodeERC721Mint encodes mint(to).
func EncodeERC721Mint(to types.Address) []byte {
	return buildCall(selERC721Mint[:], packAddress(to))
}

// EncodeERC721TransferFrom encodes transferFrom(from, to, id).
func EncodeERC721TransferFrom(from, to types.Address, id *uint256.Int) []byte {
	return buildCall(selERC721TransferFrom[:], packAddress(from), packAddress(to), packUint256(id))
}

// EncodeWETHDeposit encodes deposit().
func EncodeWETHDeposit() []byte {
	return append([]byte{}, selWETHDeposit[:]...)
}

// EncodeWETHWithdraw encodes withdraw(amount).
func EncodeWETHWithdraw(amount *uint256.Int) []byte {
	return buildCall(selWETHWithdraw[:], packUint256(amount))
}

// EncodeWETHTransfer encodes transfer(to, amount).
func EncodeWETHTransfer(to types.Address, amount *uint256.Int) []byte {
	return buildCall(selWETHTransfer[:], packAddress(to), packUint256(amount))
}

// EncodeWETHBalanceOf encodes balanceOf(addr).
func EncodeWETHBalanceOf(addr types.Address) []byte {
	return buildCall(selWETHBalanceOf[:], packAddress(addr))
}

// EncodeAMMAddLiquidity encodes addLiquidity(amount0, amount1) — uint112 args
// are fully encoded as uint256 on the wire.
func EncodeAMMAddLiquidity(amount0, amount1 *uint256.Int) []byte {
	return buildCall(selAMMAddLiquidity[:], packUint256(amount0), packUint256(amount1))
}

// EncodeAMMSwap encodes swap(tokenIn, amountIn, minOut).
func EncodeAMMSwap(tokenIn types.Address, amountIn, minOut *uint256.Int) []byte {
	return buildCall(selAMMSwap[:], packAddress(tokenIn), packUint256(amountIn), packUint256(minOut))
}

// EncodeMultisigSubmit encodes submit(to, value, data) — `data` is dynamic.
func EncodeMultisigSubmit(to types.Address, value *uint256.Int, data []byte) []byte {
	// Head: to (32) || value (32) || offset-of-data (32)
	// Tail: len(data) (32) || data padded to 32-byte multiple.
	head := make([]byte, 0, 96)
	head = append(head, packAddress(to)...)
	head = append(head, packUint256(value)...)
	head = append(head, packUint64(96)...) // offset = 3*32 (after the 3 head slots)
	tail := packUint64(uint64(len(data)))
	padLen := (32 - len(data)%32) % 32
	tail = append(tail, data...)
	tail = append(tail, make([]byte, padLen)...)
	return buildCallRaw(selMultisigSubmit[:], append(head, tail...))
}

// EncodeMultisigConfirm encodes confirm(id).
func EncodeMultisigConfirm(id *uint256.Int) []byte {
	return buildCall(selMultisigConfirm[:], packUint256(id))
}

// EncodeMultisigExecute encodes execute(id).
func EncodeMultisigExecute(id *uint256.Int) []byte {
	return buildCall(selMultisigExecute[:], packUint256(id))
}

// EncodeMultisigTxCount encodes txCount().
func EncodeMultisigTxCount() []byte {
	return append([]byte{}, selMultisigTxCount[:]...)
}

// EncodeStorageSet encodes set(key, value).
func EncodeStorageSet(key, value *uint256.Int) []byte {
	return buildCall(selStorageSet[:], packUint256(key), packUint256(value))
}

func buildCall(sel []byte, argWords ...[]byte) []byte {
	out := make([]byte, 0, 4+32*len(argWords))
	out = append(out, sel...)
	for _, w := range argWords {
		out = append(out, w...)
	}
	return out
}

func buildCallRaw(sel, body []byte) []byte {
	out := make([]byte, 0, 4+len(body))
	out = append(out, sel...)
	out = append(out, body...)
	return out
}

func packAddress(a types.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a[:])
	return out
}

func packUint256(v *uint256.Int) []byte {
	var b [32]byte
	if v != nil {
		v.WriteToSlice(b[:])
	}
	return b[:]
}

func packUint64(v uint64) []byte {
	out := make([]byte, 32)
	binary.BigEndian.PutUint64(out[32-8:], v)
	return out
}

// DecodeUint256 reads a 32-byte big-endian word from the return data.
func DecodeUint256(ret []byte, wordIndex int) *uint256.Int {
	v := new(uint256.Int)
	if len(ret) < (wordIndex+1)*32 {
		return v
	}
	v.SetBytes(ret[wordIndex*32 : (wordIndex+1)*32])
	return v
}

// DecodeAddress reads a 32-byte address-padded word.
func DecodeAddress(ret []byte, wordIndex int) types.Address {
	var a types.Address
	if len(ret) < (wordIndex+1)*32 {
		return a
	}
	copy(a[:], ret[wordIndex*32+12:(wordIndex+1)*32])
	return a
}
