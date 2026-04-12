package vm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/big"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
	"golang.org/x/crypto/ripemd160"
)

// ErrBSVPrecompileNotActive is returned for BSV precompiles that are not yet active.
var ErrBSVPrecompileNotActive = errors.New("BSV precompile not yet active")

// PrecompiledContract is the basic interface for native Go precompiled contracts.
type PrecompiledContract interface {
	// RequiredGas calculates the contract gas use.
	RequiredGas(input []byte) uint64
	// Run runs the precompiled contract.
	Run(input []byte) ([]byte, error)
}

// PrecompiledContracts contains the precompiled contracts supported at the given fork.
type PrecompiledContracts map[types.Address]PrecompiledContract

// activePrecompiledContracts returns the precompile map for the given rules.
func activePrecompiledContracts(rules Rules) PrecompiledContracts {
	return precompileMap(rules)
}

// ActivePrecompiledContracts returns the precompile map for the given rules (exported).
func ActivePrecompiledContracts(rules Rules) PrecompiledContracts {
	return precompileMap(rules)
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
// It returns the output and the remaining gas.
func RunPrecompiledContract(p PrecompiledContract, input []byte, suppliedGas uint64, logger *tracing.Hooks) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	if logger != nil && logger.OnGasChange != nil {
		logger.OnGasChange(suppliedGas, suppliedGas-gasCost, tracing.GasChangeCallPrecompiledContract)
	}
	suppliedGas -= gasCost
	output, err := p.Run(input)
	return output, suppliedGas, err
}

// precompileMap returns the precompile map for the given rules.
func precompileMap(rules Rules) map[types.Address]PrecompiledContract {
	m := make(map[types.Address]PrecompiledContract)
	m[types.BytesToAddress([]byte{1})] = &ecRecover{}
	m[types.BytesToAddress([]byte{2})] = &sha256hash{}
	m[types.BytesToAddress([]byte{3})] = &ripemd160hash{}
	m[types.BytesToAddress([]byte{4})] = &dataCopy{}
	if rules.IsByzantium {
		m[types.BytesToAddress([]byte{5})] = &bigModExp{eip2565: rules.IsBerlin}
		m[types.BytesToAddress([]byte{6})] = &bn256AddByzantium{}
		m[types.BytesToAddress([]byte{7})] = &bn256ScalarMulByzantium{}
		m[types.BytesToAddress([]byte{8})] = &bn256PairingByzantium{}
	}
	if rules.IsIstanbul {
		m[types.BytesToAddress([]byte{6})] = &bn256AddIstanbul{}
		m[types.BytesToAddress([]byte{7})] = &bn256ScalarMulIstanbul{}
		m[types.BytesToAddress([]byte{8})] = &bn256PairingIstanbul{}
		m[types.BytesToAddress([]byte{9})] = &blake2F{}
	}
	if rules.IsCancun {
		m[types.BytesToAddress([]byte{0x0a})] = &pointEvaluation{}
	}
	// BSV precompiles: registered as stubs that revert with
	// ErrBSVPrecompileNotActive and consume all provided gas. Per Spec 01,
	// these must be present so that calls to 0x80-0x82 revert rather than
	// silently succeeding with empty return data.
	//
	// These addresses are NOT included in ActivePrecompiles() to avoid
	// affecting EIP-2929 access-list warming in ethereum/tests. They are
	// registered in the execution map only so the EVM recognises them as
	// precompiles during CALL.
	m[types.BytesToAddress([]byte{0x80})] = &stubBSVPrecompile{} // BSV_VERIFY_TX
	m[types.BytesToAddress([]byte{0x81})] = &stubBSVPrecompile{} // BSV_VERIFY_SCRIPT
	m[types.BytesToAddress([]byte{0x82})] = &stubBSVPrecompile{} // BSV_BLOCK_HASH
	return m
}

// isBSVPrecompile returns true if the address is a BSV stub precompile
// (0x80-0x82). These are excluded from the warm access list to preserve
// correct EIP-2929 gas semantics in ethereum/tests.
func isBSVPrecompile(addr types.Address) bool {
	return addr == types.BytesToAddress([]byte{0x80}) ||
		addr == types.BytesToAddress([]byte{0x81}) ||
		addr == types.BytesToAddress([]byte{0x82})
}

// ActivePrecompiles returns the list of active precompile addresses for the given rules.
// BSV stub precompiles (0x80-0x82) are excluded because they must not be
// warmed via EIP-2929 — they exist for revert semantics only.
func ActivePrecompiles(rules Rules) []types.Address {
	m := precompileMap(rules)
	addrs := make([]types.Address, 0, len(m))
	for addr := range m {
		if isBSVPrecompile(addr) {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// SetCode for initNewContract needs CodeChangeReason but our StateDB.SetCode already takes it
// so the call in evm.go will pass tracing.CodeChangeCreation

// ecRecover implements the ecRecover precompile at address 0x01.
type ecRecover struct{}

// RequiredGas returns the gas required for ecRecover.
func (c *ecRecover) RequiredGas(input []byte) uint64 { return 3000 }

// Run executes ecRecover.
func (c *ecRecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128
	input = padInput(input, ecRecoverInputLength)

	// The input is: hash(32) + v(32) + r(32) + s(32)
	// v is at byte offset 32..63, must be 27 or 28
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// The leading 31 bytes of v must be zero (v should be 27 or 28 as a
	// 256-bit big-endian integer). If any of bytes 32..62 are non-zero
	// the input is malformed. Also validate r and s via the standard
	// signature validation function. This matches geth's ecrecover.
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}

	// Recover public key using our crypto package
	hash := input[:32]
	sig := make([]byte, 65)
	copy(sig, input[64:128])
	sig[64] = v

	pubKey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return nil, nil
	}

	// Return the address (keccak256 of public key without the 0x04 prefix, take last 20 bytes)
	addr := crypto.Keccak256(pubKey[1:])
	result := make([]byte, 32)
	copy(result[12:], addr[12:])
	return result, nil
}

// sha256hash implements the SHA-256 precompile at address 0x02.
type sha256hash struct{}

// RequiredGas returns the gas required for SHA-256.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(60 + 12*((len(input)+31)/32))
}

// Run executes SHA-256.
func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// ripemd160hash implements the RIPEMD-160 precompile at address 0x03.
type ripemd160hash struct{}

// RequiredGas returns the gas required for RIPEMD-160.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(600 + 120*((len(input)+31)/32))
}

// Run executes RIPEMD-160.
func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	hash := ripemd.Sum(nil)
	// Left-pad to 32 bytes
	result := make([]byte, 32)
	copy(result[12:], hash)
	return result, nil
}

// dataCopy implements the identity (data copy) precompile at address 0x04.
type dataCopy struct{}

// RequiredGas returns the gas required for data copy.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(15 + 3*((len(input)+31)/32))
}

// Run copies input to output.
func (c *dataCopy) Run(input []byte) ([]byte, error) {
	out := make([]byte, len(input))
	copy(out, input)
	return out, nil
}

var (
	bigInt1      = big.NewInt(1)
	bigInt3      = big.NewInt(3)
	bigInt7      = big.NewInt(7)
	bigInt20     = big.NewInt(20)
	bigInt32     = big.NewInt(32)
	bigInt64     = big.NewInt(64)
	bigInt96     = big.NewInt(96)
	bigInt480    = big.NewInt(480)
	bigInt1024   = big.NewInt(1024)
	bigInt199680 = big.NewInt(199680)
)

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198.
func modexpMultComplexity(x *big.Int) *big.Int {
	switch {
	case x.Cmp(bigInt64) <= 0:
		x.Mul(x, x) // x ** 2
	case x.Cmp(bigInt1024) <= 0:
		// (x ** 2 // 4) + (96 * x - 3072)
		x = new(big.Int).Add(
			new(big.Int).Rsh(new(big.Int).Mul(x, x), 2),
			new(big.Int).Sub(new(big.Int).Mul(bigInt96, x), big.NewInt(3072)),
		)
	default:
		// (x ** 2 // 16) + (480 * x - 199680)
		x = new(big.Int).Add(
			new(big.Int).Rsh(new(big.Int).Mul(x, x), 4),
			new(big.Int).Sub(new(big.Int).Mul(bigInt480, x), bigInt199680),
		)
	}
	return x
}

// bigModExp implements the modular exponentiation precompile at address 0x05.
type bigModExp struct {
	eip2565 bool
}

// RequiredGas returns the gas required for modular exponentiation.
// This implementation uses big.Int arithmetic throughout to handle
// arbitrarily large length parameters correctly, matching geth's behavior.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(bigInt32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(bigInt32) > 0 {
		adjExpLen.Sub(expLen, bigInt32)
		adjExpLen.Lsh(adjExpLen, 3)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))
	// Calculate the gas cost of the operation
	gas := new(big.Int)
	if modLen.Cmp(baseLen) < 0 {
		gas.Set(baseLen)
	} else {
		gas.Set(modLen)
	}
	if c.eip2565 {
		// EIP-2565: mult_complexity(x) = ceil(x/8)^2
		gas.Add(gas, bigInt7)
		gas.Rsh(gas, 3)
		gas.Mul(gas, gas)

		if adjExpLen.Cmp(bigInt1) > 0 {
			gas.Mul(gas, adjExpLen)
		}
		gas.Div(gas, bigInt3)
		if gas.BitLen() > 64 {
			return math.MaxUint64
		}
		if gas.Uint64() < 200 {
			return 200
		}
		return gas.Uint64()
	}
	gas = modexpMultComplexity(gas)
	if adjExpLen.Cmp(bigInt1) > 0 {
		gas.Mul(gas, adjExpLen)
	}
	gas.Div(gas, bigInt20)

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

// Run executes modular exponentiation.
func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	base := new(big.Int).SetBytes(getData(input, 96, baseLen))
	exp := new(big.Int).SetBytes(getData(input, 96+baseLen, expLen))
	mod := new(big.Int).SetBytes(getData(input, 96+baseLen+expLen, modLen))

	if mod.Sign() == 0 {
		return make([]byte, modLen), nil
	}
	result := new(big.Int).Exp(base, exp, mod)
	resultBytes := result.Bytes()

	// Left-pad to modLen
	if uint64(len(resultBytes)) < modLen {
		ret := make([]byte, modLen)
		copy(ret[modLen-uint64(len(resultBytes)):], resultBytes)
		return ret, nil
	}
	return resultBytes[:modLen], nil
}

func adjustedExpLen(expLen uint64, expData []byte) uint64 {
	if expLen <= 32 {
		exp := new(big.Int).SetBytes(expData)
		if exp.BitLen() == 0 {
			return 0
		}
		return uint64(exp.BitLen()) - 1
	}
	// If > 32 bytes
	firstWord := new(big.Int).SetBytes(getData(expData, 0, 32))
	if firstWord.BitLen() == 0 {
		return 8 * (expLen - 32)
	}
	return uint64(firstWord.BitLen()) - 1 + 8*(expLen-32)
}

func adjustedExpLen2565(adjExpLen uint64) uint64 {
	if adjExpLen > 1 {
		return adjExpLen
	}
	return 1
}

func uint64Max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// bn256AddByzantium implements the bn256 point addition precompile (Byzantium gas costs).
type bn256AddByzantium struct{}

// RequiredGas returns the gas required.
func (c *bn256AddByzantium) RequiredGas(input []byte) uint64 { return 500 }

// Run executes bn256 point addition.
func (c *bn256AddByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// bn256AddIstanbul implements the bn256 point addition precompile (Istanbul gas costs).
type bn256AddIstanbul struct{}

// RequiredGas returns the gas required.
func (c *bn256AddIstanbul) RequiredGas(input []byte) uint64 { return 150 }

// Run executes bn256 point addition.
func (c *bn256AddIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// bn256ScalarMulByzantium implements the bn256 scalar multiplication precompile (Byzantium gas).
type bn256ScalarMulByzantium struct{}

// RequiredGas returns the gas required.
func (c *bn256ScalarMulByzantium) RequiredGas(input []byte) uint64 { return 40000 }

// Run executes bn256 scalar multiplication.
func (c *bn256ScalarMulByzantium) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256ScalarMulIstanbul implements the bn256 scalar multiplication precompile (Istanbul gas).
type bn256ScalarMulIstanbul struct{}

// RequiredGas returns the gas required.
func (c *bn256ScalarMulIstanbul) RequiredGas(input []byte) uint64 { return 6000 }

// Run executes bn256 scalar multiplication.
func (c *bn256ScalarMulIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256PairingByzantium implements the bn256 pairing check precompile (Byzantium gas).
type bn256PairingByzantium struct{}

// RequiredGas returns the gas required.
func (c *bn256PairingByzantium) RequiredGas(input []byte) uint64 {
	return 100000 + uint64(len(input)/192)*80000
}

// Run executes bn256 pairing check.
func (c *bn256PairingByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

// bn256PairingIstanbul implements the bn256 pairing check precompile (Istanbul gas).
type bn256PairingIstanbul struct{}

// RequiredGas returns the gas required.
func (c *bn256PairingIstanbul) RequiredGas(input []byte) uint64 {
	return 45000 + uint64(len(input)/192)*34000
}

// Run executes bn256 pairing check.
func (c *bn256PairingIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

// blake2F implements the Blake2F precompile at address 0x09.
type blake2F struct{}

// RequiredGas returns the gas required for Blake2F.
func (c *blake2F) RequiredGas(input []byte) uint64 {
	if len(input) != 213 {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

// Run executes Blake2F.
func (c *blake2F) Run(input []byte) ([]byte, error) {
	if len(input) != 213 {
		return nil, errors.New("invalid input length for blake2f")
	}
	// Parse input
	rounds := binary.BigEndian.Uint32(input[0:4])
	var h [8]uint64
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint64(input[4+i*8 : 12+i*8])
	}
	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(input[68+i*8 : 76+i*8])
	}
	var t [2]uint64
	t[0] = binary.LittleEndian.Uint64(input[196:204])
	t[1] = binary.LittleEndian.Uint64(input[204:212])

	f := input[212]
	if f != 0 && f != 1 {
		return nil, errors.New("invalid final block flag for blake2f")
	}

	blake2FCompress(&h, m, t, f == 1, rounds)

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(output[i*8:], h[i])
	}
	return output, nil
}

// blake2FCompress is the Blake2b compression function.
func blake2FCompress(h *[8]uint64, m [16]uint64, t [2]uint64, f bool, rounds uint32) {
	// Blake2b IV
	var iv = [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	// Sigma schedule
	var sigma = [10][16]byte{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	}

	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], iv[:])
	v[12] ^= t[0]
	v[13] ^= t[1]
	if f {
		v[14] = ^v[14]
	}

	for i := uint32(0); i < rounds; i++ {
		s := &sigma[i%10]

		v[0] = v[0] + v[4] + m[s[0]]
		v[12] ^= v[0]
		v[12] = v[12]>>32 | v[12]<<32
		v[8] = v[8] + v[12]
		v[4] ^= v[8]
		v[4] = v[4]>>24 | v[4]<<40

		v[0] = v[0] + v[4] + m[s[1]]
		v[12] ^= v[0]
		v[12] = v[12]>>16 | v[12]<<48
		v[8] = v[8] + v[12]
		v[4] ^= v[8]
		v[4] = v[4]>>63 | v[4]<<1

		v[1] = v[1] + v[5] + m[s[2]]
		v[13] ^= v[1]
		v[13] = v[13]>>32 | v[13]<<32
		v[9] = v[9] + v[13]
		v[5] ^= v[9]
		v[5] = v[5]>>24 | v[5]<<40

		v[1] = v[1] + v[5] + m[s[3]]
		v[13] ^= v[1]
		v[13] = v[13]>>16 | v[13]<<48
		v[9] = v[9] + v[13]
		v[5] ^= v[9]
		v[5] = v[5]>>63 | v[5]<<1

		v[2] = v[2] + v[6] + m[s[4]]
		v[14] ^= v[2]
		v[14] = v[14]>>32 | v[14]<<32
		v[10] = v[10] + v[14]
		v[6] ^= v[10]
		v[6] = v[6]>>24 | v[6]<<40

		v[2] = v[2] + v[6] + m[s[5]]
		v[14] ^= v[2]
		v[14] = v[14]>>16 | v[14]<<48
		v[10] = v[10] + v[14]
		v[6] ^= v[10]
		v[6] = v[6]>>63 | v[6]<<1

		v[3] = v[3] + v[7] + m[s[6]]
		v[15] ^= v[3]
		v[15] = v[15]>>32 | v[15]<<32
		v[11] = v[11] + v[15]
		v[7] ^= v[11]
		v[7] = v[7]>>24 | v[7]<<40

		v[3] = v[3] + v[7] + m[s[7]]
		v[15] ^= v[3]
		v[15] = v[15]>>16 | v[15]<<48
		v[11] = v[11] + v[15]
		v[7] ^= v[11]
		v[7] = v[7]>>63 | v[7]<<1

		// Diagonals
		v[0] = v[0] + v[5] + m[s[8]]
		v[15] ^= v[0]
		v[15] = v[15]>>32 | v[15]<<32
		v[10] = v[10] + v[15]
		v[5] ^= v[10]
		v[5] = v[5]>>24 | v[5]<<40

		v[0] = v[0] + v[5] + m[s[9]]
		v[15] ^= v[0]
		v[15] = v[15]>>16 | v[15]<<48
		v[10] = v[10] + v[15]
		v[5] ^= v[10]
		v[5] = v[5]>>63 | v[5]<<1

		v[1] = v[1] + v[6] + m[s[10]]
		v[12] ^= v[1]
		v[12] = v[12]>>32 | v[12]<<32
		v[11] = v[11] + v[12]
		v[6] ^= v[11]
		v[6] = v[6]>>24 | v[6]<<40

		v[1] = v[1] + v[6] + m[s[11]]
		v[12] ^= v[1]
		v[12] = v[12]>>16 | v[12]<<48
		v[11] = v[11] + v[12]
		v[6] ^= v[11]
		v[6] = v[6]>>63 | v[6]<<1

		v[2] = v[2] + v[7] + m[s[12]]
		v[13] ^= v[2]
		v[13] = v[13]>>32 | v[13]<<32
		v[8] = v[8] + v[13]
		v[7] ^= v[8]
		v[7] = v[7]>>24 | v[7]<<40

		v[2] = v[2] + v[7] + m[s[13]]
		v[13] ^= v[2]
		v[13] = v[13]>>16 | v[13]<<48
		v[8] = v[8] + v[13]
		v[7] ^= v[8]
		v[7] = v[7]>>63 | v[7]<<1

		v[3] = v[3] + v[4] + m[s[14]]
		v[14] ^= v[3]
		v[14] = v[14]>>32 | v[14]<<32
		v[9] = v[9] + v[14]
		v[4] ^= v[9]
		v[4] = v[4]>>24 | v[4]<<40

		v[3] = v[3] + v[4] + m[s[15]]
		v[14] ^= v[3]
		v[14] = v[14]>>16 | v[14]<<48
		v[9] = v[9] + v[14]
		v[4] ^= v[9]
		v[4] = v[4]>>63 | v[4]<<1
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// pointEvaluation implements the EIP-4844 point evaluation precompile (0x0a).
type pointEvaluation struct{}

// RequiredGas returns the gas required for point evaluation.
func (c *pointEvaluation) RequiredGas(input []byte) uint64 { return 50000 }

// Run executes the EIP-4844 point evaluation precompile. It validates the
// input format and versioned hash, then performs the KZG pairing check.
//
// Input: 192 bytes = versioned_hash (32) + z (32) + y (32) + commitment (48) + proof (48)
// Output: FIELD_ELEMENTS_PER_BLOB (32 bytes big-endian) || BLS_MODULUS (32 bytes big-endian)
func (c *pointEvaluation) Run(input []byte) ([]byte, error) {
	if len(input) != 192 {
		return nil, errors.New("invalid input length for point evaluation")
	}

	// Parse fields.
	var versionedHash [32]byte
	copy(versionedHash[:], input[0:32])
	z := input[32:64]
	y := input[64:96]
	commitment := input[96:144]
	proof := input[144:192]

	// Verify versioned hash matches commitment.
	expectedHash := kzgVersionedHash(commitment)
	if versionedHash != expectedHash {
		return nil, errors.New("versioned hash does not match commitment")
	}

	// Verify the KZG proof.
	if !crypto.KZGReady() {
		return nil, ErrKZGNotReady
	}
	if err := crypto.VerifyKZGProof(commitment, z, y, proof); err != nil {
		return nil, errors.New("kzg proof verification failed")
	}

	// EIP-4844 specifies that the return value is:
	// FIELD_ELEMENTS_PER_BLOB (4096) as 32-byte big-endian || BLS_MODULUS as 32-byte big-endian
	return pointEvaluationReturnValue, nil
}

// pointEvaluationReturnValue is the constant return value for a successful
// point evaluation precompile call. It encodes FIELD_ELEMENTS_PER_BLOB (4096)
// and the BLS12-381 scalar field modulus, each as 32-byte big-endian values.
var pointEvaluationReturnValue = func() []byte {
	ret := make([]byte, 64)
	// FIELD_ELEMENTS_PER_BLOB = 4096 = 0x1000
	ret[30] = 0x10
	ret[31] = 0x00
	// BLS_MODULUS = 0x73eda753...00000001
	copy(ret[32:], []byte{
		0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
		0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
		0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	})
	return ret
}()

// stubBSVPrecompile returns an error for BSV precompiles that are not yet active.
type stubBSVPrecompile struct{}

// RequiredGas returns gas proportional to the input length.
func (c *stubBSVPrecompile) RequiredGas(input []byte) uint64 { return uint64(len(input)) }

// Run returns ErrBSVPrecompileNotActive.
func (c *stubBSVPrecompile) Run(input []byte) ([]byte, error) {
	return nil, ErrBSVPrecompileNotActive
}

// padInput pads the input to the required length with zeros.
func padInput(input []byte, size int) []byte {
	if len(input) >= size {
		return input[:size]
	}
	padded := make([]byte, size)
	copy(padded, input)
	return padded
}
