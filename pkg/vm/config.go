package vm

import (
	"math/big"

	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// ChainConfig contains the chain parameters for determining which
// hardfork rules to apply at a given block number or timestamp.
type ChainConfig struct {
	ChainID             *big.Int `json:"chainId"`
	HomesteadBlock      *big.Int `json:"homesteadBlock,omitempty"`
	EIP150Block         *big.Int `json:"eip150Block,omitempty"`
	EIP155Block         *big.Int `json:"eip155Block,omitempty"`
	EIP158Block         *big.Int `json:"eip158Block,omitempty"`
	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"`
	PetersburgBlock     *big.Int `json:"petersburgBlock,omitempty"`
	IstanbulBlock       *big.Int `json:"istanbulBlock,omitempty"`
	BerlinBlock         *big.Int `json:"berlinBlock,omitempty"`
	LondonBlock         *big.Int `json:"londonBlock,omitempty"`
	ShanghaiTime        *uint64  `json:"shanghaiTime,omitempty"`
	CancunTime          *uint64  `json:"cancunTime,omitempty"`
	PragueTime          *uint64  `json:"pragueTime,omitempty"`
	FusakaTime          *uint64  `json:"fusakaTime,omitempty"`
	// BSVM enables BSVM-specific features (BSV stub precompiles at 0x80-0x82).
	// Set by DefaultL2Config. Not set for ethereum/tests chain configs.
	BSVM bool `json:"bsvm,omitempty"`
}

// DefaultL2Config returns a ChainConfig with all hardforks enabled from genesis.
// This is the standard configuration for BSVM L2 shards.
func DefaultL2Config(chainID int64) *ChainConfig {
	zero := uint64(0)
	return &ChainConfig{
		ChainID:             big.NewInt(chainID),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ShanghaiTime:        &zero,
		CancunTime:          &zero,
		PragueTime:          &zero,
		BSVM:                true,
	}
}

func isBlockForked(s *big.Int, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func isTimestampForked(s *uint64, head uint64) bool {
	if s == nil {
		return false
	}
	return *s <= head
}

// IsHomestead returns whether num is at or past the homestead block.
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isBlockForked(c.HomesteadBlock, num)
}

// IsEIP150 returns whether num is at or past the EIP-150 (Tangerine Whistle) block.
func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isBlockForked(c.EIP150Block, num)
}

// IsEIP155 returns whether num is at or past the EIP-155 block.
func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isBlockForked(c.EIP155Block, num)
}

// IsEIP158 returns whether num is at or past the EIP-158 (Spurious Dragon) block.
func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isBlockForked(c.EIP158Block, num)
}

// IsByzantium returns whether num is at or past the Byzantium block.
func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isBlockForked(c.ByzantiumBlock, num)
}

// IsConstantinople returns whether num is at or past the Constantinople block.
func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isBlockForked(c.ConstantinopleBlock, num)
}

// IsPetersburg returns whether num is at or past the Petersburg block.
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isBlockForked(c.PetersburgBlock, num)
}

// IsIstanbul returns whether num is at or past the Istanbul block.
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isBlockForked(c.IstanbulBlock, num)
}

// IsBerlin returns whether num is at or past the Berlin block.
func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	return isBlockForked(c.BerlinBlock, num)
}

// IsLondon returns whether num is at or past the London block.
func (c *ChainConfig) IsLondon(num *big.Int) bool {
	return isBlockForked(c.LondonBlock, num)
}

// IsShanghai returns whether timestamp is at or past Shanghai activation.
func (c *ChainConfig) IsShanghai(num *big.Int, timestamp uint64) bool {
	return isTimestampForked(c.ShanghaiTime, timestamp)
}

// IsCancun returns whether timestamp is at or past Cancun activation.
func (c *ChainConfig) IsCancun(num *big.Int, timestamp uint64) bool {
	return isTimestampForked(c.CancunTime, timestamp)
}

// IsPrague returns whether timestamp is at or past Prague activation.
func (c *ChainConfig) IsPrague(num *big.Int, timestamp uint64) bool {
	return isTimestampForked(c.PragueTime, timestamp)
}

// IsFusakaActive returns whether timestamp is at or past Fusaka activation.
func (c *ChainConfig) IsFusakaActive(num *big.Int, timestamp uint64) bool {
	return isTimestampForked(c.FusakaTime, timestamp)
}

// Rules returns the active chain rules at the given block number and timestamp.
func (c *ChainConfig) Rules(num *big.Int, isMerge bool, timestamp uint64) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	return Rules{
		ChainID:          new(big.Int).Set(chainID),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsBerlin:         c.IsBerlin(num),
		IsLondon:         c.IsLondon(num),
		IsMerge:          isMerge,
		IsShanghai:       c.IsShanghai(num, timestamp),
		IsCancun:         c.IsCancun(num, timestamp),
		IsPrague:         c.IsPrague(num, timestamp),
		IsFusaka:         c.IsFusakaActive(num, timestamp),
		IsBSVM:           c.BSVM,
	}
}

// Rules represents which protocol changes are active for a given block.
type Rules struct {
	ChainID                                                 *big.Int
	IsHomestead, IsEIP150, IsEIP155, IsEIP158               bool
	IsByzantium, IsConstantinople, IsPetersburg, IsIstanbul bool
	IsBerlin, IsLondon                                      bool
	IsMerge                                                 bool
	IsShanghai, IsCancun, IsPrague, IsFusaka                bool
	// IsBSVM enables BSVM-specific features: BSV stub precompiles at
	// 0x80-0x82. Set automatically for chains using DefaultL2Config.
	// Not set when running ethereum/tests (where 0x80 is a regular address).
	IsBSVM bool
}

// Config specifies configuration options for the EVM.
type Config struct {
	// Tracer is the optional tracing hooks for EVM execution.
	Tracer *tracing.Hooks
	// NoBaseFee forces the EIP-1559 base fee to zero for testing.
	NoBaseFee bool
	// EnablePreimageRecording enables recording of SHA3/keccak preimages.
	EnablePreimageRecording bool
	// ExtraEips lists additional EIPs to enable.
	ExtraEips []int
}
