// Package evmtest provides test runners for the ethereum/tests suite.
// It validates the BSVM EVM implementation against the canonical
// Ethereum test vectors (GeneralStateTests and VMTests).
package evmtest

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// hexToBytes converts a hex string (with or without 0x prefix) to bytes.
// Returns nil for empty strings.
func hexToBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ := hex.DecodeString(s)
	return b
}

// hexToBigInt converts a hex string to *big.Int.
// Returns 0 for empty or invalid strings.
func hexToBigInt(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return new(big.Int)
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return new(big.Int)
	}
	return n
}

// hexToUint256 converts a hex string to *uint256.Int.
func hexToUint256(s string) *uint256.Int {
	b := hexToBigInt(s)
	v, _ := uint256.FromBig(b)
	if v == nil {
		return new(uint256.Int)
	}
	return v
}

// hexToUint64 converts a hex string to uint64.
func hexToUint64(s string) uint64 {
	b := hexToBigInt(s)
	if !b.IsUint64() {
		return 0
	}
	return b.Uint64()
}

// hexToAddress converts a hex string to types.Address.
func hexToAddress(s string) types.Address {
	return types.HexToAddress(s)
}

// hexToHash converts a hex string to types.Hash.
func hexToHash(s string) types.Hash {
	return types.HexToHash(s)
}

// setupMemoryPreState creates a MemoryStateDB and populates it with the
// pre-state accounts. Used for quick VM tests where trie root verification
// is not needed.
func setupMemoryPreState(pre map[string]PreAccountJSON) *state.MemoryStateDB {
	sdb := state.NewMemoryStateDB()
	for addrHex, acct := range pre {
		addr := hexToAddress(addrHex)
		sdb.CreateAccount(addr)

		// Set balance.
		balance := hexToUint256(acct.Balance)
		sdb.AddBalance(addr, balance, tracing.BalanceChangeUnspecified)

		// Set nonce.
		nonce := hexToUint64(acct.Nonce)
		if nonce > 0 {
			sdb.SetNonce(addr, nonce, tracing.NonceChangeUnspecified)
		}

		// Set code.
		code := hexToBytes(acct.Code)
		if len(code) > 0 {
			sdb.SetCode(addr, code, tracing.CodeChangeCreation)
		}

		// Set storage.
		for keyHex, valHex := range acct.Storage {
			key := hexToHash(keyHex)
			val := hexToHash(valHex)
			sdb.SetState(addr, key, val)
		}
	}
	return sdb
}

// setupTriePreState creates a real StateDB backed by MPT and populates it
// with the pre-state accounts. The resulting state root can be compared
// against expected values.
func setupTriePreState(pre map[string]PreAccountJSON) (*state.StateDB, error) {
	memDB := db.NewMemoryDB()
	sdb, err := state.New(types.EmptyRootHash, memDB)
	if err != nil {
		return nil, err
	}
	for addrHex, acct := range pre {
		addr := hexToAddress(addrHex)
		sdb.CreateAccount(addr)

		// Set balance.
		balance := hexToUint256(acct.Balance)
		sdb.AddBalance(addr, balance, tracing.BalanceChangeUnspecified)

		// Set nonce.
		nonce := hexToUint64(acct.Nonce)
		if nonce > 0 {
			sdb.SetNonce(addr, nonce, tracing.NonceChangeUnspecified)
		}

		// Set code.
		code := hexToBytes(acct.Code)
		if len(code) > 0 {
			sdb.SetCode(addr, code, tracing.CodeChangeCreation)
		}

		// Set storage.
		for keyHex, valHex := range acct.Storage {
			key := hexToHash(keyHex)
			val := hexToHash(valHex)
			sdb.SetState(addr, key, val)
		}
	}
	// Commit the pre-state so it is reflected in the trie root.
	if _, err := sdb.Commit(false); err != nil {
		return nil, err
	}
	return sdb, nil
}

// getChainConfigForFork returns a ChainConfig for the given fork name.
// Fork names are matched case-insensitively.
func getChainConfigForFork(fork string) *vm.ChainConfig {
	lf := strings.ToLower(fork)
	zero := uint64(0)
	big0 := big.NewInt(0)

	switch lf {
	case "frontier":
		return &vm.ChainConfig{
			ChainID: big.NewInt(1),
		}
	case "homestead":
		return &vm.ChainConfig{
			ChainID:        big.NewInt(1),
			HomesteadBlock: big0,
		}
	case "eip150", "tangerinewhistle":
		return &vm.ChainConfig{
			ChainID:        big.NewInt(1),
			HomesteadBlock: big0,
			EIP150Block:    big0,
		}
	case "eip158", "spuriousdragon":
		return &vm.ChainConfig{
			ChainID:        big.NewInt(1),
			HomesteadBlock: big0,
			EIP150Block:    big0,
			EIP155Block:    big0,
			EIP158Block:    big0,
		}
	case "byzantium":
		return &vm.ChainConfig{
			ChainID:        big.NewInt(1),
			HomesteadBlock: big0,
			EIP150Block:    big0,
			EIP155Block:    big0,
			EIP158Block:    big0,
			ByzantiumBlock: big0,
		}
	case "constantinople":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
		}
	case "istanbul":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
		}
	case "berlin":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
		}
	case "london":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
		}
	case "merge", "paris":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
		}
	case "shanghai":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
			ShanghaiTime:        &zero,
		}
	case "cancun":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
			ShanghaiTime:        &zero,
			CancunTime:          &zero,
		}
	case "prague":
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
			ShanghaiTime:        &zero,
			CancunTime:          &zero,
			PragueTime:          &zero,
		}
	default:
		// Unknown fork, return Cancun config as default.
		return &vm.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big0,
			EIP150Block:         big0,
			EIP155Block:         big0,
			EIP158Block:         big0,
			ByzantiumBlock:      big0,
			ConstantinopleBlock: big0,
			PetersburgBlock:     big0,
			IstanbulBlock:       big0,
			BerlinBlock:         big0,
			LondonBlock:         big0,
			ShanghaiTime:        &zero,
			CancunTime:          &zero,
		}
	}
}

// makeBlockContext constructs a BlockContext from test env data.
func makeBlockContext(env EnvJSON) vm.BlockContext {
	blockNumber := hexToBigInt(env.CurrentNumber)
	baseFee := hexToBigInt(env.CurrentBaseFee)
	if baseFee.Sign() == 0 {
		baseFee = big.NewInt(0)
	}

	difficulty := hexToBigInt(env.CurrentDifficulty)

	ctx := vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			// Hash block numbers by their string representation, matching
			// geth's vmTestBlockHash function.
			return types.BytesToHash(crypto.Keccak256([]byte(new(big.Int).SetUint64(n).String())))
		},
		Coinbase:    hexToAddress(env.CurrentCoinbase),
		GasLimit:    hexToUint64(env.CurrentGasLimit),
		BlockNumber: blockNumber,
		Time:        hexToUint64(env.CurrentTimestamp),
		Difficulty:  difficulty,
		BaseFee:     baseFee,
	}

	if env.CurrentRandom != "" {
		random := hexToHash(env.CurrentRandom)
		ctx.Random = &random
		// Post-merge: difficulty should be 0 (matching geth's test runner).
		ctx.Difficulty = big.NewInt(0)
	}

	// EIP-4844: compute blob base fee from excess blob gas.
	if env.CurrentExcessBlobGas != "" {
		excessBlobGas := hexToUint64(env.CurrentExcessBlobGas)
		ctx.BlobBaseFee = calcBlobFee(excessBlobGas)
	}

	return ctx
}

// calcBlobFee computes the blob base fee from excess blob gas (EIP-4844).
// blob_base_fee = fake_exponential(1, excess_blob_gas, 3338477)
func calcBlobFee(excessBlobGas uint64) *big.Int {
	return fakeExponential(big.NewInt(1), new(big.Int).SetUint64(excessBlobGas), big.NewInt(3338477))
}

// fakeExponential approximates factor * e^(numerator/denominator) using
// a Taylor series expansion, matching the EIP-4844 specification.
func fakeExponential(factor, numerator, denominator *big.Int) *big.Int {
	i := new(big.Int).SetUint64(1)
	output := new(big.Int)
	numeratorAccum := new(big.Int).Set(factor)
	numeratorAccum.Mul(numeratorAccum, denominator)
	for numeratorAccum.Sign() > 0 {
		output.Add(output, numeratorAccum)
		numeratorAccum.Mul(numeratorAccum, numerator)
		numeratorAccum.Div(numeratorAccum, new(big.Int).Mul(denominator, i))
		i.Add(i, big.NewInt(1))
	}
	output.Div(output, denominator)
	return output
}

// isSupportedFork returns true if we support the given fork.
// We skip EOF-related forks and any fork we do not implement.
func isSupportedFork(fork string) bool {
	lf := strings.ToLower(fork)
	switch lf {
	case "frontier", "homestead", "eip150", "tangerinewhistle",
		"eip158", "spuriousdragon", "byzantium", "constantinople",
		"istanbul", "berlin", "london", "merge", "paris",
		"shanghai", "cancun", "prague":
		return true
	default:
		return false
	}
}
