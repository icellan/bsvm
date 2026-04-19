package shard

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/types"
)

// HardhatAccount is one deterministic prefunded account from the Hardhat
// default mnemonic. Spec 16 devnet prefunds ten of these so Solidity
// developers can use the standard Hardhat test wallet out of the box.
//
// PrivateKey is plaintext because these keys are published in every
// Hardhat installation. They must NEVER be used on mainnet or to hold
// funds of any value.
type HardhatAccount struct {
	Address    types.Address
	PrivateKey string // 0x-prefixed hex, public test key — NOT FOR PRODUCTION
}

// HardhatDefaultAccounts returns the ten deterministic test accounts seeded
// by Hardhat's default "test test test test test test test test test test
// test junk" mnemonic. Addresses and private keys match the values every
// Hardhat / Foundry user expects to see when running against a local node.
//
// Spec 16 pre-funds each of these with 1000 wBSV when --prefund-accounts
// hardhat is passed to `bsvm init`.
func HardhatDefaultAccounts() []HardhatAccount {
	return []HardhatAccount{
		{
			Address:    types.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			PrivateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		},
		{
			Address:    types.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
			PrivateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
		},
		{
			Address:    types.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
			PrivateKey: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
		},
		{
			Address:    types.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
			PrivateKey: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
		},
		{
			Address:    types.HexToAddress("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
			PrivateKey: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
		},
		{
			Address:    types.HexToAddress("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
			PrivateKey: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
		},
		{
			Address:    types.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"),
			PrivateKey: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
		},
		{
			Address:    types.HexToAddress("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"),
			PrivateKey: "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
		},
		{
			Address:    types.HexToAddress("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"),
			PrivateKey: "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
		},
		{
			Address:    types.HexToAddress("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"),
			PrivateKey: "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
		},
	}
}

// DevnetGovernanceKey returns the compressed secp256k1 public key that
// the spec 16 devnet uses as both the governance key (freeze/unfreeze/
// upgrade) AND the dev advance key (DevKeyRollupContract's
// AdvanceState CheckSig). The corresponding private key is Hardhat
// account #0 — reusing it keeps the devnet to a single well-known
// secret and lets developers sign covenant admin transactions using
// the wallet they already have configured for L2 contract deployment.
//
// This is devnet-only. Never use this key on a shard holding real funds.
func DevnetGovernanceKey() ([]byte, error) {
	const hardhat0PrivHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privBytes, err := hex.DecodeString(hardhat0PrivHex)
	if err != nil {
		return nil, fmt.Errorf("decoding devnet governance private key: %w", err)
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	return priv.PubKey().SerializeCompressed(), nil
}

// DevnetGovernancePrivateKey returns the hex-encoded private key that
// signs under DevnetGovernanceKey. Used by the admin CLI and by
// covenant advance broadcasts in devnet. NEVER use on mainnet.
func DevnetGovernancePrivateKey() string {
	return "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}

// HardhatPrefundAlloc returns a genesis allocation crediting each Hardhat
// test account with the given balance (in wei). The balance is typically
// 1000 * 10^18 for spec 16 devnet ("1000 wBSV each"). The returned map
// is ready to merge into InitShardParams.Alloc.
func HardhatPrefundAlloc(balancePerAccount *uint256.Int) map[types.Address]block.GenesisAccount {
	accounts := HardhatDefaultAccounts()
	alloc := make(map[types.Address]block.GenesisAccount, len(accounts))
	for _, a := range accounts {
		bal := new(uint256.Int).Set(balancePerAccount)
		alloc[a.Address] = block.GenesisAccount{Balance: bal}
	}
	return alloc
}
