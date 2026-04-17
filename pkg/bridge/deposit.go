package bridge

import (
	"bytes"
	"encoding/binary"

	"github.com/icellan/bsvm/pkg/types"
)

// DepositMagic is the 4-byte magic prefix in OP_RETURN outputs that
// identifies a BSVM deposit transaction.
var DepositMagic = []byte("BSVM")

// DepositMsgType is the message type byte for deposits (0x03).
const DepositMsgType = 0x03

// ParseDeposit extracts deposit info from a BSV transaction for the
// local shard identified by localShardID. It looks for:
//   - An output paying to the bridge covenant (identified by bridgeScriptHash)
//   - An OP_RETURN output containing "BSVM" 0x03 <shard_id:4> <l2_address:20>
//     whose shard_id matches localShardID.
//
// Cross-shard deposits (OP_RETURN shard_id != localShardID) are rejected
// to prevent one shard's bridge from crediting UTXOs intended for another
// shard — see review finding on shard_id validation.
//
// Returns nil if the transaction is not a valid deposit for this shard.
//
// The OP_RETURN format is:
//
//	OP_RETURN OP_FALSE (0x6a 0x00) or just OP_RETURN (0x6a)
//	followed by push of: "BSVM" || 0x03 || shard_id (4 bytes, big-endian uint32) || l2_address (20 bytes)
//
// Total payload: 4 + 1 + 4 + 20 = 29 bytes.
func ParseDeposit(tx *BSVTransaction, bridgeScriptHash []byte, localShardID uint32) *Deposit {
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

	// Find the OP_RETURN with deposit metadata. The returned shardID is
	// compared against localShardID; a mismatch rejects the deposit
	// regardless of the presence of a covenant-paying output, so that a
	// BSV tx destined for a foreign shard never credits this one.
	var l2Addr types.Address
	found := false
	for _, out := range tx.Outputs {
		addr, shardID, ok := parseDepositOpReturn(out.Script)
		if !ok {
			continue
		}
		if shardID != localShardID {
			// Cross-shard deposit: not for this shard.
			return nil
		}
		l2Addr = addr
		found = true
		break
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
// Returns the L2 address, the decoded shard_id, and true if successfully
// parsed, or the zero values and false otherwise. Callers MUST compare
// the returned shard_id against the local shard's id and reject
// mismatches — ParseDeposit does this.
func parseDepositOpReturn(script []byte) (types.Address, uint32, bool) {
	// OP_RETURN = 0x6a. The script may start with:
	//   0x6a <push_data>                 (standard OP_RETURN)
	//   0x6a 0x00 <push_data>            (OP_RETURN OP_FALSE - "safe" variant)
	if len(script) < 2 || script[0] != 0x6a {
		return types.Address{}, 0, false
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
		return types.Address{}, 0, false
	}

	var payload []byte
	pushOp := data[0]
	data = data[1:]

	switch {
	case pushOp >= 0x01 && pushOp <= 0x4b:
		n := int(pushOp)
		if len(data) < n {
			return types.Address{}, 0, false
		}
		payload = data[:n]
	case pushOp == 0x4c: // OP_PUSHDATA1
		if len(data) < 1 {
			return types.Address{}, 0, false
		}
		n := int(data[0])
		data = data[1:]
		if len(data) < n {
			return types.Address{}, 0, false
		}
		payload = data[:n]
	case pushOp == 0x4d: // OP_PUSHDATA2
		if len(data) < 2 {
			return types.Address{}, 0, false
		}
		n := int(data[0]) | int(data[1])<<8
		data = data[2:]
		if len(data) < n {
			return types.Address{}, 0, false
		}
		payload = data[:n]
	default:
		return types.Address{}, 0, false
	}

	// Expected payload: "BSVM" (4) + msg_type (1) + shard_id (4) + l2_address (20) = 29 bytes
	if len(payload) < 29 {
		return types.Address{}, 0, false
	}

	if !bytes.Equal(payload[:4], DepositMagic) {
		return types.Address{}, 0, false
	}

	if payload[4] != DepositMsgType {
		return types.Address{}, 0, false
	}

	// Bytes 5..8 are the shard_id (4 bytes, big-endian uint32).
	shardID := binary.BigEndian.Uint32(payload[5:9])

	// Bytes 9..28 are the L2 address (20 bytes).
	var addr types.Address
	copy(addr[:], payload[9:29])

	return addr, shardID, true
}
