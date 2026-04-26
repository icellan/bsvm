package covenant

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// buildConsolidationTx builds a single-output P2PKH self-spend that
// drains every input UTXO into one consolidated output paying back to
// the wallet's own address. The fee is estimated at 1 sat/byte from
// the unsigned tx size — adequate for BSV's near-zero fee floor and
// matches the placeholder used elsewhere in pkg/bsvclient for
// regtest. Production deployments that want a richer fee policy can
// adapt this helper after broadcast lands.
//
// Signing is delegated to the PrivateKey via SignInput. The function
// returns the fully-signed tx in raw hex form plus the fee that was
// budgeted, so the caller can sanity-check totalSats > fee before
// broadcasting.
//
// The serialization here is the BSV consensus tx encoding. We use a
// hand-rolled minimal serializer to keep the package free of an
// outright dependency on the BSV-SDK transaction type at this layer
// (the FeeWallet's consolidation is the only path here that builds a
// transaction). pkg/covenant code that needs to interact with the
// SDK's Transaction type continues to do so via the runar broadcast
// client.
func buildConsolidationTx(inputs []UTXO, key PrivateKey) (rawHex string, fee uint64, err error) {
	if len(inputs) == 0 {
		return "", 0, errors.New("no inputs")
	}
	if key == nil {
		return "", 0, errors.New("nil signer")
	}

	addrHash, addrErr := decodeAddressHash(key.Address())
	if addrErr != nil {
		return "", 0, fmt.Errorf("decode address: %w", addrErr)
	}

	var totalSats uint64
	for _, u := range inputs {
		totalSats += u.Satoshis
	}

	// Conservative fee estimate: 10-byte version+locktime+counts envelope,
	// 148 bytes per signed input (32 prev txid + 4 vout + 1 script len +
	// ~107 unlock script + 4 sequence), 34 bytes per P2PKH output.
	const perInputBytes = 148
	const perOutputBytes = 34
	const envelopeBytes = 10
	estSize := uint64(envelopeBytes + len(inputs)*perInputBytes + perOutputBytes)
	fee = estSize // 1 sat/byte
	if fee >= totalSats {
		return "", fee, fmt.Errorf("fee %d exceeds total inputs %d", fee, totalSats)
	}
	outAmount := totalSats - fee

	// Step 1: serialize the unsigned skeleton (every input has an empty
	// unlocking script). We sign each input against this skeleton's hex
	// form via the PrivateKey.SignInput callback, then splice the
	// returned unlock hex into the final serialization.
	skeleton := serializeRawTx(inputs, addrHash, outAmount, nil)
	skeletonHex := hex.EncodeToString(skeleton)

	unlockScripts := make([][]byte, len(inputs))
	for i, u := range inputs {
		unlockHex, signErr := key.SignInput(skeletonHex, i, hex.EncodeToString(u.Script), u.Satoshis)
		if signErr != nil {
			return "", fee, fmt.Errorf("sign input %d: %w", i, signErr)
		}
		unlock, decodeErr := hex.DecodeString(unlockHex)
		if decodeErr != nil {
			return "", fee, fmt.Errorf("decode unlock %d: %w", i, decodeErr)
		}
		unlockScripts[i] = unlock
	}

	final := serializeRawTx(inputs, addrHash, outAmount, unlockScripts)
	return hex.EncodeToString(final), fee, nil
}

// serializeRawTx writes the BSV-consensus encoding of a transaction
// with one P2PKH output paying outAmount to addrHash. unlockScripts
// may be nil (skeleton) or have len == len(inputs) (signed). The
// version is 1 and the locktime is 0.
func serializeRawTx(inputs []UTXO, addrHash []byte, outAmount uint64, unlockScripts [][]byte) []byte {
	var buf bytes.Buffer

	// Version (LE uint32).
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// Input count varint.
	writeVarInt(&buf, uint64(len(inputs)))

	for i, u := range inputs {
		// Prev tx hash (32 bytes, already in chainhash little-endian
		// order in types.Hash, which matches BSV's wire format).
		buf.Write(u.TxID[:])
		// Prev vout (LE uint32).
		binary.Write(&buf, binary.LittleEndian, u.Vout)
		// Unlocking script.
		var script []byte
		if unlockScripts != nil {
			script = unlockScripts[i]
		}
		writeVarInt(&buf, uint64(len(script)))
		buf.Write(script)
		// Sequence (0xFFFFFFFF, finalized).
		binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	}

	// Output count varint (1).
	writeVarInt(&buf, 1)
	// Output amount (LE uint64).
	binary.Write(&buf, binary.LittleEndian, outAmount)
	// Output script: P2PKH back to wallet address.
	out := buildP2PKHScript(addrHash)
	writeVarInt(&buf, uint64(len(out)))
	buf.Write(out)

	// Locktime (LE uint32).
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

// buildP2PKHScript returns the standard 25-byte P2PKH locking script
// for the given 20-byte pubkey hash.
func buildP2PKHScript(pkh []byte) []byte {
	out := make([]byte, 25)
	out[0] = 0x76 // OP_DUP
	out[1] = 0xa9 // OP_HASH160
	out[2] = 0x14 // push 20 bytes
	copy(out[3:23], pkh)
	out[23] = 0x88 // OP_EQUALVERIFY
	out[24] = 0xac // OP_CHECKSIG
	return out
}

// writeVarInt encodes the BSV-consensus varint form to buf.
func writeVarInt(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 0xfd:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	default:
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

// decodeAddressHash extracts the 20-byte pubkey hash from a wallet
// address. The wallet address may arrive in two forms:
//
//   - 40-char hex (raw pubkey hash) — used by tests and internal
//     callers that already have the hash.
//   - Base58Check-encoded P2PKH — the canonical mainnet/testnet form.
//
// We accept the hex form directly and return ErrUnsupportedAddress for
// anything else. The bsv-sdk address codec lives in a sibling package
// the FeeWallet does not import; full base58check decode happens in
// the production wiring layer that constructs the PrivateKey.
func decodeAddressHash(addr string) ([]byte, error) {
	if len(addr) == 40 {
		b, err := hex.DecodeString(addr)
		if err == nil && len(b) == 20 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("fee wallet: address %q not in supported form (expected 40-hex pubkey hash)", addr)
}

// parseTxIDHex converts the txid hex returned by BroadcastTx into the
// chainhash little-endian byte form stored in types.Hash. BSV nodes
// return txids in big-endian display form (reversed byte order from
// the consensus wire format), so we reverse here. Empty / 0x-prefixed
// inputs are tolerated.
func parseTxIDHex(s string) (types.Hash, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	if len(b) != 32 {
		return types.Hash{}, fmt.Errorf("expected 32-byte txid, got %d", len(b))
	}
	var h types.Hash
	for i := 0; i < 32; i++ {
		h[i] = b[31-i]
	}
	return h, nil
}
