package bridge

import (
	"bytes"

	"github.com/icellan/bsvm/pkg/types"
)

// DepositMagic is the 4-byte magic prefix in OP_RETURN outputs that
// identifies a BSVM deposit transaction.
var DepositMagic = []byte("BSVM")

// DepositMsgType is the message type byte for deposits (0x03).
const DepositMsgType = 0x03

// ParseDeposit extracts deposit info from a BSV transaction.
// It looks for:
//   - An output paying to the bridge covenant (identified by bridgeScriptHash)
//   - An OP_RETURN output containing "BSVM" 0x03 <shard_id:4> <l2_address:20>
//
// Returns nil if the transaction is not a valid deposit.
//
// The OP_RETURN format is:
//
//	OP_RETURN OP_FALSE (0x6a 0x00) or just OP_RETURN (0x6a)
//	followed by push of: "BSVM" || 0x03 || shard_id (4 bytes, big-endian uint32) || l2_address (20 bytes)
//
// Total payload: 4 + 1 + 4 + 20 = 29 bytes.
//
// For simplicity, we scan for the OP_RETURN data pattern in the raw script.
func ParseDeposit(tx *BSVTransaction, bridgeScriptHash []byte) *Deposit {
	// Find the deposit amount: look for output paying to bridge covenant.
	var depositAmount uint64
	for _, out := range tx.Outputs {
		if len(bridgeScriptHash) > 0 && matchesBridgeCovenant(out.Script, bridgeScriptHash) {
			depositAmount = out.Value
			break
		}
	}
	if depositAmount == 0 {
		return nil
	}

	// Find the OP_RETURN with deposit metadata.
	var l2Addr types.Address
	found := false
	for _, out := range tx.Outputs {
		addr, ok := parseDepositOpReturn(out.Script)
		if ok {
			l2Addr = addr
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	dep := NewDeposit(tx.TxID, tx.BlockHeight, l2Addr, depositAmount)
	dep.TxIndex = tx.TxIndex
	return dep
}

// matchesBridgeCovenant checks whether the output script matches the
// bridge covenant. It compares the script hash (the script itself or
// a hash of it) against the expected bridge script hash.
func matchesBridgeCovenant(script []byte, bridgeScriptHash []byte) bool {
	return bytes.Equal(script, bridgeScriptHash)
}

// parseDepositOpReturn attempts to parse an OP_RETURN output script
// for deposit metadata. The expected format after the OP_RETURN opcode(s)
// is a data push containing:
//
//	"BSVM" (4 bytes) || 0x03 (1 byte) || shard_id (4 bytes, big-endian uint32) || l2_address (20 bytes)
//
// Total data payload: 29 bytes.
//
// Returns the L2 address and true if successfully parsed, or the zero
// address and false otherwise.
func parseDepositOpReturn(script []byte) (types.Address, bool) {
	// OP_RETURN = 0x6a. The script may start with:
	//   0x6a <push_data>                 (standard OP_RETURN)
	//   0x6a 0x00 <push_data>            (OP_RETURN OP_FALSE - "safe" variant)
	if len(script) < 2 || script[0] != 0x6a {
		return types.Address{}, false
	}

	// Skip OP_RETURN byte(s).
	data := script[1:]
	if len(data) > 0 && data[0] == 0x00 {
		data = data[1:]
	}

	// Extract the pushed data. Handle common push opcodes:
	//   0x01-0x4b: direct push of N bytes
	//   0x4c: OP_PUSHDATA1 (1-byte length prefix)
	//   0x4d: OP_PUSHDATA2 (2-byte length prefix, little-endian)
	if len(data) == 0 {
		return types.Address{}, false
	}

	var payload []byte
	pushOp := data[0]
	data = data[1:]

	switch {
	case pushOp >= 0x01 && pushOp <= 0x4b:
		n := int(pushOp)
		if len(data) < n {
			return types.Address{}, false
		}
		payload = data[:n]
	case pushOp == 0x4c: // OP_PUSHDATA1
		if len(data) < 1 {
			return types.Address{}, false
		}
		n := int(data[0])
		data = data[1:]
		if len(data) < n {
			return types.Address{}, false
		}
		payload = data[:n]
	case pushOp == 0x4d: // OP_PUSHDATA2
		if len(data) < 2 {
			return types.Address{}, false
		}
		n := int(data[0]) | int(data[1])<<8
		data = data[2:]
		if len(data) < n {
			return types.Address{}, false
		}
		payload = data[:n]
	default:
		return types.Address{}, false
	}

	// Expected payload: "BSVM" (4) + msg_type (1) + shard_id (4) + l2_address (20) = 29 bytes
	if len(payload) < 29 {
		return types.Address{}, false
	}

	if !bytes.Equal(payload[:4], DepositMagic) {
		return types.Address{}, false
	}

	if payload[4] != DepositMsgType {
		return types.Address{}, false
	}

	// Bytes 5..8 are the shard_id (4 bytes, big-endian uint32) --
	// skipped for now, the monitor validates shard_id separately.

	// Bytes 9..28 are the L2 address (20 bytes).
	var addr types.Address
	copy(addr[:], payload[9:29])

	return addr, true
}
