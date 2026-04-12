package vm

import (
	"math/big"
	"testing"
)

func TestRulesFusakaNilNotActive(t *testing.T) {
	config := &ChainConfig{
		ChainID:    big.NewInt(1),
		FusakaTime: nil, // not activated
	}
	rules := config.Rules(big.NewInt(0), true, 0)
	if rules.IsFusaka {
		t.Fatal("IsFusaka should be false when FusakaTime is nil")
	}
}

func TestRulesFusakaZeroActive(t *testing.T) {
	zero := uint64(0)
	config := &ChainConfig{
		ChainID:    big.NewInt(1),
		FusakaTime: &zero,
	}
	rules := config.Rules(big.NewInt(0), true, 0)
	if !rules.IsFusaka {
		t.Fatal("IsFusaka should be true when FusakaTime is &0 and timestamp is 0")
	}
}

func TestRulesFusakaFutureTimestamp(t *testing.T) {
	fusakaTime := uint64(1000)
	config := &ChainConfig{
		ChainID:    big.NewInt(1),
		FusakaTime: &fusakaTime,
	}
	// Timestamp 999 is before Fusaka.
	rules := config.Rules(big.NewInt(0), true, 999)
	if rules.IsFusaka {
		t.Fatal("IsFusaka should be false when timestamp < FusakaTime")
	}

	// Timestamp 1000 is at Fusaka.
	rules = config.Rules(big.NewInt(0), true, 1000)
	if !rules.IsFusaka {
		t.Fatal("IsFusaka should be true when timestamp == FusakaTime")
	}

	// Timestamp 1001 is after Fusaka.
	rules = config.Rules(big.NewInt(0), true, 1001)
	if !rules.IsFusaka {
		t.Fatal("IsFusaka should be true when timestamp > FusakaTime")
	}
}

func TestDefaultL2ConfigFusakaNil(t *testing.T) {
	config := DefaultL2Config(1337)
	if config.FusakaTime != nil {
		t.Fatalf("DefaultL2Config should have nil FusakaTime, got %v", *config.FusakaTime)
	}
	rules := config.Rules(big.NewInt(0), true, 0)
	if rules.IsFusaka {
		t.Fatal("IsFusaka should be false for DefaultL2Config")
	}
}

func TestIsFusakaActiveMethod(t *testing.T) {
	config := &ChainConfig{ChainID: big.NewInt(1)}

	// Nil FusakaTime.
	if config.IsFusakaActive(big.NewInt(0), 0) {
		t.Fatal("IsFusakaActive should be false when FusakaTime is nil")
	}

	// Set FusakaTime.
	ft := uint64(500)
	config.FusakaTime = &ft
	if config.IsFusakaActive(big.NewInt(0), 499) {
		t.Fatal("IsFusakaActive should be false before FusakaTime")
	}
	if !config.IsFusakaActive(big.NewInt(0), 500) {
		t.Fatal("IsFusakaActive should be true at FusakaTime")
	}
	if !config.IsFusakaActive(big.NewInt(0), 501) {
		t.Fatal("IsFusakaActive should be true after FusakaTime")
	}
}
