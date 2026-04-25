// Genesis manifest — the self-describing payload embedded in the BSVM
// deploy transaction's OP_RETURN output. Together with the covenant
// locking script at vout 0, this manifest lets any node bootstrap a
// shard from nothing more than the genesis covenant txid + a BSV RPC
// endpoint.
//
// The manifest is the authoritative source for fields that would
// otherwise need to be shipped out-of-band:
//
//   - chainId, gasLimit      — informational; chainId is also baked
//     into the covenant as a readonly property so we can cross-check.
//   - verificationMode       — informational; the actual deployed mode
//     is re-derived from the script template by DetectVerificationMode.
//   - sp1VK                  — the FULL SP1 verifying key (the script
//     only carries its sha256 digest). sha256(manifest.sp1VK) MUST
//     equal the script's SP1VerifyingKeyHash or the deriver rejects.
//   - governance             — full mode + threshold + keys.
//   - alloc                  — every account's genesis balance / nonce
//     / code / storage. InitGenesis replays this to reproduce the
//     genesis state root the covenant binds.
//
// On-chain layout (vout 1 of the deploy tx, OP_RETURN):
//
//	OP_FALSE OP_RETURN <pushdata: [5 magic][4 len-be][len bytes JSON]>
//
// The deriver reads the OP_RETURN payload, strips the pushdata opcode,
// matches the 5-byte magic, reads the 4-byte big-endian length prefix,
// and unmarshals the canonical JSON. Every structural error is fatal:
// a malformed genesis tx is unrecoverable.
package shard

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// GenesisManifestMagic is the 5-byte prefix on the BSVM genesis
// OP_RETURN (vout 1 of the deploy transaction). It disambiguates the
// genesis manifest from the spec-12 advance-time BSVM\x02 batch-data
// output. The trailing 0x00 identifies this as the v0 manifest envelope;
// a future format revision can bump the byte without invalidating the
// disambiguation property.
const GenesisManifestMagic = "BSVM\x00"

// GenesisManifestVersion is the schema version currently emitted by
// EncodeManifest. Bump whenever the JSON layout changes in a way that
// existing decoders can't handle; readers MAY reject versions they
// don't understand rather than silently misinterpreting fields.
const GenesisManifestVersion = 1

// GenesisManifest is the self-describing payload embedded in the
// deploy transaction's OP_RETURN output. Every field a new node
// needs to boot the shard — beyond what's already baked into the
// covenant locking script — lives here.
//
// Readers MUST validate the script-derived fields (chainID, governance,
// SP1 VK hash, verification mode) match the manifest values before
// trusting the alloc / gasLimit. See DeriveShardFromTx for the
// cross-validation logic.
type GenesisManifest struct {
	// Version is the manifest schema version (currently 1).
	Version int `json:"version"`
	// ChainID is the EIP-155 chain identifier. Must match the chainId
	// readonly property baked into the covenant locking script.
	ChainID int64 `json:"chainId"`
	// GasLimit is the initial block gas limit used by InitGenesis.
	// Informational — the covenant doesn't bind this directly.
	GasLimit uint64 `json:"gasLimit"`
	// VerificationMode is one of "fri" | "groth16" | "groth16-wa" |
	// "devkey". Must match the script template detected by
	// covenant.DetectVerificationMode.
	VerificationMode string `json:"verificationMode"`
	// SP1VerifyingKey is the hex-encoded FULL SP1 VK. The covenant
	// carries only sha256(SP1VerifyingKey); readers verify the hash
	// matches before trusting it.
	SP1VerifyingKey string `json:"sp1VK"`
	// Governance is the shard's governance config at genesis.
	Governance GenesisGovernance `json:"governance"`
	// Alloc maps hex-encoded 20-byte addresses (lowercase, no 0x) to
	// their genesis account state. Order-independent on the wire;
	// InitGenesis iterates the map directly.
	Alloc map[string]GenesisAllocEntry `json:"alloc"`
	// CovenantSats is the satoshi amount the deployed covenant UTXO
	// carries. Informational — the actual UTXO value is authoritative.
	CovenantSats uint64 `json:"covenantSats"`
	// Timestamp is the Unix epoch (seconds) at which the shard was
	// deployed. Informational.
	Timestamp int64 `json:"timestamp"`
}

// GenesisGovernance is the JSON-friendly governance section of a
// manifest. Keys are hex-encoded compressed secp256k1 pubkeys (33
// bytes each, 66 hex chars); Threshold is 1 for single_key, 0 for
// none, and M for M-of-N multisig.
type GenesisGovernance struct {
	Mode      string   `json:"mode"`
	Threshold int      `json:"threshold"`
	Keys      []string `json:"keys"`
}

// GenesisAllocEntry matches block.GenesisAccount's shape but uses
// JSON-friendly types (decimal balance string, hex code/storage) so
// the manifest is human-readable when inspected on-chain. The decoder
// converts back to uint256.Int and types.Hash.
type GenesisAllocEntry struct {
	// BalanceWei is a decimal string encoding a non-negative integer
	// in wei. Empty or "0" yields a zero balance.
	BalanceWei string `json:"balance"`
	// Nonce is the account nonce at genesis (usually 0).
	Nonce uint64 `json:"nonce,omitempty"`
	// Code is the contract bytecode at genesis, hex-encoded without
	// the 0x prefix. Empty for EOAs.
	Code string `json:"code,omitempty"`
	// Storage maps hex-encoded storage slot keys (32 bytes, no 0x) to
	// hex-encoded values (32 bytes, no 0x).
	Storage map[string]string `json:"storage,omitempty"`
}

// EncodeManifest serializes the manifest with the magic prefix and a
// 4-byte big-endian length prefix so the decoder can pick it out of a
// larger OP_RETURN stream without regex.
//
// Layout: [5 magic][4 len-be][len bytes canonical JSON].
func EncodeManifest(m *GenesisManifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("manifest must not be nil")
	}
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	// Envelope: magic || len(4 BE) || json
	out := make([]byte, 0, len(GenesisManifestMagic)+4+len(jsonBytes))
	out = append(out, []byte(GenesisManifestMagic)...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(jsonBytes)))
	out = append(out, lenBuf[:]...)
	out = append(out, jsonBytes...)
	return out, nil
}

// DecodeManifest parses a GenesisManifestMagic-prefixed byte slice
// (typically the OP_RETURN payload after the OP_RETURN/OP_PUSHDATA4
// script opcodes are stripped). Returns an error if the magic is
// missing, the length prefix is malformed, or the JSON is invalid.
//
// Extra trailing bytes after the declared JSON length are tolerated
// — some Bitcoin Script pushes naturally round to opcode boundaries.
// Missing bytes (declared len > remaining) is fatal.
func DecodeManifest(data []byte) (*GenesisManifest, error) {
	magic := []byte(GenesisManifestMagic)
	if len(data) < len(magic)+4 {
		return nil, fmt.Errorf("manifest: too short (%d bytes) to contain magic+length", len(data))
	}
	if string(data[:len(magic)]) != GenesisManifestMagic {
		return nil, fmt.Errorf("manifest: magic mismatch; expected %q prefix", GenesisManifestMagic)
	}
	length := binary.BigEndian.Uint32(data[len(magic) : len(magic)+4])
	payloadStart := len(magic) + 4
	if uint32(len(data)-payloadStart) < length {
		return nil, fmt.Errorf("manifest: truncated payload (declared %d bytes, have %d)", length, len(data)-payloadStart)
	}
	payload := data[payloadStart : payloadStart+int(length)]
	var m GenesisManifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("manifest: unmarshal JSON: %w", err)
	}
	return &m, nil
}

// BuildAlloc converts the manifest's alloc map into the in-memory
// block.GenesisAccount map that InitGenesis expects. Invalid hex or
// out-of-range balances return an error rather than silently dropping
// the entry — a malformed alloc is unrecoverable for genesis replay.
func (m *GenesisManifest) BuildAlloc() (map[types.Address]block.GenesisAccount, error) {
	if m == nil {
		return nil, fmt.Errorf("manifest must not be nil")
	}
	out := make(map[types.Address]block.GenesisAccount, len(m.Alloc))
	for addrHex, entry := range m.Alloc {
		addr := types.HexToAddress(addrHex)

		bal := new(uint256.Int)
		if entry.BalanceWei != "" && entry.BalanceWei != "0" {
			if err := bal.SetFromDecimal(entry.BalanceWei); err != nil {
				return nil, fmt.Errorf("alloc %s: decode balance %q: %w", addrHex, entry.BalanceWei, err)
			}
		}

		acc := block.GenesisAccount{
			Balance: bal,
			Nonce:   entry.Nonce,
		}

		if entry.Code != "" {
			code, err := hex.DecodeString(entry.Code)
			if err != nil {
				return nil, fmt.Errorf("alloc %s: decode code: %w", addrHex, err)
			}
			acc.Code = code
		}

		if len(entry.Storage) > 0 {
			store := make(map[types.Hash]types.Hash, len(entry.Storage))
			for k, v := range entry.Storage {
				slot := types.HexToHash(k)
				val := types.HexToHash(v)
				store[slot] = val
			}
			acc.Storage = store
		}

		out[addr] = acc
	}
	return out, nil
}

// ToGovernanceConfig converts the manifest's governance section into
// the typed covenant.GovernanceConfig. Hex key decoding errors are
// fatal — those keys never get through the covenant's own validation
// either.
func (m *GenesisManifest) ToGovernanceConfig() (covenant.GovernanceConfig, error) {
	var gc covenant.GovernanceConfig
	if m == nil {
		return gc, fmt.Errorf("manifest must not be nil")
	}
	switch m.Governance.Mode {
	case "none":
		gc.Mode = covenant.GovernanceNone
	case "single_key":
		gc.Mode = covenant.GovernanceSingleKey
	case "multisig":
		gc.Mode = covenant.GovernanceMultiSig
	default:
		return gc, fmt.Errorf("manifest governance: unknown mode %q", m.Governance.Mode)
	}
	gc.Threshold = m.Governance.Threshold
	for i, keyHex := range m.Governance.Keys {
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			return gc, fmt.Errorf("manifest governance: decode key %d: %w", i, err)
		}
		gc.Keys = append(gc.Keys, keyBytes)
	}
	return gc, nil
}

// ToVerificationMode parses the manifest's verificationMode string
// into the typed covenant.VerificationMode. An unknown mode is fatal —
// we refuse to guess which on-chain script template the manifest
// refers to.
func (m *GenesisManifest) ToVerificationMode() (covenant.VerificationMode, error) {
	if m == nil {
		return 0, fmt.Errorf("manifest must not be nil")
	}
	switch m.VerificationMode {
	case "fri":
		return covenant.VerifyFRI, nil
	case "groth16":
		return covenant.VerifyGroth16, nil
	case "groth16-wa":
		return covenant.VerifyGroth16WA, nil
	case "devkey":
		return covenant.VerifyDevKey, nil
	default:
		return 0, fmt.Errorf("manifest: unknown verification mode %q", m.VerificationMode)
	}
}

// AllocFromMap converts a block.GenesisAccount map (the in-memory
// form) into the manifest's JSON-friendly shape. Used by deploy-shard
// when building the manifest to embed in the OP_RETURN.
func AllocFromMap(alloc map[types.Address]block.GenesisAccount) map[string]GenesisAllocEntry {
	out := make(map[string]GenesisAllocEntry, len(alloc))
	for addr, acc := range alloc {
		addrHex := hex.EncodeToString(addr[:])
		entry := GenesisAllocEntry{
			Nonce: acc.Nonce,
		}
		if acc.Balance != nil {
			entry.BalanceWei = acc.Balance.Dec()
		} else {
			entry.BalanceWei = "0"
		}
		if len(acc.Code) > 0 {
			entry.Code = hex.EncodeToString(acc.Code)
		}
		if len(acc.Storage) > 0 {
			stor := make(map[string]string, len(acc.Storage))
			for k, v := range acc.Storage {
				stor[hex.EncodeToString(k[:])] = hex.EncodeToString(v[:])
			}
			entry.Storage = stor
		}
		out[addrHex] = entry
	}
	return out
}

// GovernanceFromConfig converts a covenant.GovernanceConfig into the
// manifest's JSON-friendly shape. Used by deploy-shard.
func GovernanceFromConfig(gc covenant.GovernanceConfig) GenesisGovernance {
	keys := make([]string, 0, len(gc.Keys))
	for _, k := range gc.Keys {
		keys = append(keys, hex.EncodeToString(k))
	}
	return GenesisGovernance{
		Mode:      gc.Mode.String(),
		Threshold: gc.Threshold,
		Keys:      keys,
	}
}
