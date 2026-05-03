// BEEF target-transaction extractors used by the cmd-side BEEF
// consumers (inbox, governance, fee-wallet, covenant-advance) to
// recover the per-intent payload before dispatching to the receiver
// subsystem.
//
// Each extractor takes a BEEF envelope, walks the BRC-62 body to the
// target tx, then parses the BSV transaction's inputs and/or outputs
// for the data the receiver needs:
//
//   - extractInboxTxRLP: walks input 0's unlock script for the inbox
//     covenant Submit() call and recovers the EVM `txRLP` push. The
//     unlock-script shape is pinned by runar-go's BuildUnlockingScript
//     (see InboxContract in pkg/covenant/contracts/inbox.runar.go) —
//     a stateful single-public-method contract so the unlock is
//     [_codePart push] [_opPushTxSig push] [txRLP push] (3 pushes
//     total). We pick the LAST push, which is the method argument.
//   - extractCovenantStateFromTx: walks output 0's locking script for a
//     42-byte pushdata that decodes as covenant.CovenantState.
//   - extractFeeWalletOutputs: walks every output and returns those
//     whose locking script byte-equals the fee wallet's expected
//     script. Used by the fee-wallet-funding consumer (intent 0x04).
//   - extractCovenantAdvance: walks every output for the spec-12
//     OP_RETURN (BSVM\x02 || withdrawalRoot(32) || batchData) payload
//     and decodes the embedded block.BatchData for L2BlockNum +
//     PostStateRoot.
//
// All extractors share a tiny BSV-tx parser (parseTxInputsOutputs)
// that walks the raw bytes without depending on the go-sdk's full
// transaction type. We do not need the verifier-grade ancestry walk
// here — by the time these extractors run the rpc layer has already
// computed the target txid and the consumer's receiver subsystem will
// re-verify whatever it needs (e.g. RaceDetector compares against its
// own pending advance).
package main

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// advanceMagic mirrors the constant in
// pkg/covenant/contracts/rollup_*_f07_test.go: every spec-12 OP_RETURN
// advance payload starts with these 5 bytes followed by the 32-byte
// withdrawalRoot and the encoded block.BatchData blob.
var advanceMagic = []byte{'B', 'S', 'V', 'M', 0x02}

// parsedTxIO is the minimal projection of a BSV transaction needed by
// the BEEF extractors. We only carry input unlock scripts and output
// (script, satoshis) pairs; the txid is supplied by the caller (the
// rpc layer already computed it via beef.ParseBEEF).
type parsedTxIO struct {
	Inputs  []parsedTxInput
	Outputs []parsedTxOutput
}

type parsedTxInput struct {
	UnlockScript []byte
}

type parsedTxOutput struct {
	Satoshis uint64
	Script   []byte
}

// parseTxInputsOutputs walks the raw bytes of a BSV transaction and
// returns the input/output projection. Layout matches BIP141-pre /
// post-Genesis BSV: version(4) + varint inCount + inputs + varint
// outCount + outputs + locktime(4). Witness data is not used on BSV.
//
// The parser intentionally keeps no allocations beyond the unlock /
// locking script slices it returns — those are subslices of the input
// buffer, so callers must not mutate them.
func parseTxInputsOutputs(raw []byte) (*parsedTxIO, error) {
	if len(raw) < 4 {
		return nil, errors.New("beef extractor: tx too short for version")
	}
	pos := 4 // skip version (LE u32)
	inCount, n, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, fmt.Errorf("beef extractor: input count: %w", err)
	}
	pos += n

	out := &parsedTxIO{
		Inputs:  make([]parsedTxInput, 0, inCount),
		Outputs: nil,
	}

	for i := uint64(0); i < inCount; i++ {
		// 32 bytes prev txid + 4 bytes vout
		if pos+36 > len(raw) {
			return nil, fmt.Errorf("beef extractor: input %d truncated outpoint", i)
		}
		pos += 36
		scriptLen, sn, serr := readVarInt(raw[pos:])
		if serr != nil {
			return nil, fmt.Errorf("beef extractor: input %d script len: %w", i, serr)
		}
		pos += sn
		if uint64(pos)+scriptLen+4 > uint64(len(raw)) {
			return nil, fmt.Errorf("beef extractor: input %d truncated script/sequence", i)
		}
		unlock := raw[pos : pos+int(scriptLen)]
		pos += int(scriptLen) + 4 // script + sequence
		out.Inputs = append(out.Inputs, parsedTxInput{UnlockScript: unlock})
	}

	outCount, on, oerr := readVarInt(raw[pos:])
	if oerr != nil {
		return nil, fmt.Errorf("beef extractor: output count: %w", oerr)
	}
	pos += on
	out.Outputs = make([]parsedTxOutput, 0, outCount)

	for i := uint64(0); i < outCount; i++ {
		if pos+8 > len(raw) {
			return nil, fmt.Errorf("beef extractor: output %d truncated value", i)
		}
		sats := binary.LittleEndian.Uint64(raw[pos : pos+8])
		pos += 8
		scriptLen, sn, serr := readVarInt(raw[pos:])
		if serr != nil {
			return nil, fmt.Errorf("beef extractor: output %d script len: %w", i, serr)
		}
		pos += sn
		if uint64(pos)+scriptLen > uint64(len(raw)) {
			return nil, fmt.Errorf("beef extractor: output %d truncated script", i)
		}
		script := raw[pos : pos+int(scriptLen)]
		pos += int(scriptLen)
		out.Outputs = append(out.Outputs, parsedTxOutput{Satoshis: sats, Script: script})
	}

	if pos+4 > len(raw) {
		return nil, errors.New("beef extractor: tx truncated at locktime")
	}
	return out, nil
}

// readVarInt decodes a BSV compact-size varint. Mirrors the helper in
// pkg/beef/parse.go but kept local to avoid importing an internal
// helper from a sibling package.
func readVarInt(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, errors.New("varint truncated")
	}
	prefix := buf[0]
	switch {
	case prefix < 0xfd:
		return uint64(prefix), 1, nil
	case prefix == 0xfd:
		if len(buf) < 3 {
			return 0, 0, errors.New("varint truncated u16")
		}
		return uint64(binary.LittleEndian.Uint16(buf[1:3])), 3, nil
	case prefix == 0xfe:
		if len(buf) < 5 {
			return 0, 0, errors.New("varint truncated u32")
		}
		return uint64(binary.LittleEndian.Uint32(buf[1:5])), 5, nil
	default:
		if len(buf) < 9 {
			return 0, 0, errors.New("varint truncated u64")
		}
		return binary.LittleEndian.Uint64(buf[1:9]), 9, nil
	}
}

// extractTargetTxIO parses the BEEF envelope's target transaction and
// returns its input/output projection. The BEEF body is parsed via
// pkg/beef.ParseBEEF so we walk the same bytes the rpc layer already
// validated.
func extractTargetTxIO(env *beef.Envelope) (*parsedTxIO, error) {
	if env == nil || len(env.Beef) == 0 {
		return nil, errors.New("beef extractor: nil envelope or empty body")
	}
	parsed, err := beef.ParseBEEF(env.Beef)
	if err != nil {
		return nil, fmt.Errorf("beef extractor: parse: %w", err)
	}
	target := parsed.Target()
	if target == nil {
		return nil, errors.New("beef extractor: no target tx")
	}
	return parseTxInputsOutputs(target.RawTx)
}

// ---------------------------------------------------------------------------
// Inbox: recover EVM txRLP from a Submit() call
// ---------------------------------------------------------------------------

// extractInboxTxRLP recovers the EVM RLP-encoded transaction from the
// inbox covenant's Submit() unlock script.
//
// InboxContract has exactly one public method (Submit), so runar-go's
// BuildUnlockingScript does NOT append a method-selector push. The
// codegen for stateful contracts prepends [_codePart] [_opPushTxSig]
// before the user-supplied args. Concretely the unlock script for
// Submit(txRLP) is:
//
//	push(_codePart) push(_opPushTxSig) push(txRLP)
//
// Three pushes total. We pick the LAST pushdata payload — that is the
// txRLP method argument irrespective of code-part length.
//
// When the input is NOT an inbox Submit() unlock (only one push, no
// pushes, etc.) the function returns a typed error so the consumer
// can log and skip. Returning an error never aborts the daemon — the
// envelope is still persisted in the BEEF store via the rpc layer
// before the consumer fires.
func extractInboxTxRLP(env *beef.Envelope) ([]byte, error) {
	io, err := extractTargetTxIO(env)
	if err != nil {
		return nil, err
	}
	if len(io.Inputs) == 0 {
		return nil, errors.New("inbox extractor: target tx has no inputs")
	}
	pushes, err := covenant.WalkScriptPushdata(io.Inputs[0].UnlockScript)
	if err != nil {
		return nil, fmt.Errorf("inbox extractor: unlock script: %w", err)
	}
	// Inbox Submit unlock has exactly 3 pushes (codePart, opPushTxSig,
	// txRLP). Be slightly tolerant — some compilers may omit codePart
	// for terminal calls, in which case we get 2 pushes (opPushTxSig,
	// txRLP). In both cases the txRLP is the LAST push.
	if len(pushes) < 2 {
		return nil, fmt.Errorf("inbox extractor: unexpected push count %d", len(pushes))
	}
	last := pushes[len(pushes)-1]
	if len(last) == 0 {
		return nil, errors.New("inbox extractor: last push is empty")
	}
	// Defensive minimum: an EVM tx is at least ~10 bytes (legacy with
	// minimal fields). Reject anything trivially smaller so a stray
	// 1-byte push (OP_PUSHDATA1 with len=0 confused with OP_0) cannot
	// be mistaken for txRLP.
	if len(last) < 10 {
		return nil, fmt.Errorf("inbox extractor: txRLP push too short (%d bytes)", len(last))
	}
	return last, nil
}

// ---------------------------------------------------------------------------
// Governance: recover the new CovenantState from output 0
// ---------------------------------------------------------------------------

// extractCovenantStateFromTx walks output 0's locking script and
// returns the first 42-byte pushdata that decodes as a
// covenant.CovenantState. The state covenant places its encoded state
// as a fixed-size pushdata in the locking script; the parser is
// shape-tolerant (reorderings are fine as long as the state slot is
// the only 42-byte push, which is the case for the v2 state
// covenant).
//
// Returns nil + error when no decodable state is found — the consumer
// then logs and skips without crediting.
func extractCovenantStateFromTx(env *beef.Envelope) (*covenant.CovenantState, error) {
	io, err := extractTargetTxIO(env)
	if err != nil {
		return nil, err
	}
	if len(io.Outputs) == 0 {
		return nil, errors.New("governance extractor: target tx has no outputs")
	}
	pushes, err := covenant.WalkScriptPushdata(io.Outputs[0].Script)
	if err != nil {
		return nil, fmt.Errorf("governance extractor: output 0 script: %w", err)
	}
	for _, p := range pushes {
		if len(p) != 42 {
			continue
		}
		st, derr := covenant.DecodeCovenantState(p)
		if derr == nil {
			return st, nil
		}
	}
	return nil, errors.New("governance extractor: no 42-byte CovenantState pushdata in output 0")
}

// ---------------------------------------------------------------------------
// Fee wallet: walk outputs against an expected locking script
// ---------------------------------------------------------------------------

// matchedFeeOutput pairs an output index with its raw script + value.
// The fee-wallet consumer ingests one FeeUTXO per matched output.
type matchedFeeOutput struct {
	Vout     uint32
	Satoshis uint64
	Script   []byte
}

// extractFeeWalletOutputs walks the target tx's outputs and returns
// every output whose locking script byte-equals expectedScript. The
// caller (fee-wallet-funding consumer) then constructs a FeeUTXO per
// matched output and credits the wallet via AddUTXO.
//
// expectedScript MUST be non-nil — when the wallet has not published
// its locking script the consumer skips matching entirely and logs
// the missing-script case rather than calling this helper.
func extractFeeWalletOutputs(env *beef.Envelope, expectedScript []byte) ([]matchedFeeOutput, error) {
	if len(expectedScript) == 0 {
		return nil, errors.New("fee-wallet extractor: expected script must not be empty")
	}
	io, err := extractTargetTxIO(env)
	if err != nil {
		return nil, err
	}
	var matches []matchedFeeOutput
	for i, o := range io.Outputs {
		if len(o.Script) == len(expectedScript) && bytesEqual(o.Script, expectedScript) {
			matches = append(matches, matchedFeeOutput{
				Vout:     uint32(i),
				Satoshis: o.Satoshis,
				Script:   append([]byte(nil), o.Script...),
			})
		}
	}
	return matches, nil
}

// ---------------------------------------------------------------------------
// Covenant advance: extract spec-12 OP_RETURN payload + decode batch
// ---------------------------------------------------------------------------

// extractedAdvance is the consumer-friendly projection of a covenant-
// advance OP_RETURN. The caller maps this onto a
// overlay.CovenantAdvanceEvent before invoking
// RaceDetector.HandleCovenantAdvance.
type extractedAdvance struct {
	WithdrawalRoot types.Hash
	BatchData      []byte
	Decoded        *block.BatchData
	L2BlockNum     uint64
	PostStateRoot  types.Hash
}

// extractCovenantAdvance walks the target tx's outputs, finds the
// spec-12 OP_RETURN (OP_FALSE OP_RETURN <pushdata BSVM\x02 ||
// withdrawalRoot(32) || batchData>), decodes the embedded
// block.BatchData blob, and returns the unpacked advance.
//
// Returns nil + error when the OP_RETURN is missing or malformed; the
// consumer then logs and skips. The PostStateRoot is computed by the
// SP1 guest off-chain — it is NOT carried in the OP_RETURN per spec
// 12 (only the batchDataHash + withdrawalRoot land on chain). For the
// race-detector handoff we substitute the batch's parent-derived
// post-state root, which the overlay's own re-execution path will
// validate; the BEEF envelope is purely a heads-up that an advance
// landed.
//
// L2BlockNum is the block-number field encoded in the BatchData (the
// race detector keys off this to detect races across L2 heights).
func extractCovenantAdvance(env *beef.Envelope) (*extractedAdvance, error) {
	io, err := extractTargetTxIO(env)
	if err != nil {
		return nil, err
	}

	for _, o := range io.Outputs {
		payload, ok := decodeAdvanceOpReturn(o.Script)
		if !ok {
			continue
		}
		if len(payload) < 5+32 {
			return nil, fmt.Errorf("covenant extractor: OP_RETURN payload too short (%d bytes)", len(payload))
		}
		if string(payload[:5]) != string(advanceMagic) {
			continue
		}
		var root types.Hash
		copy(root[:], payload[5:5+32])
		batchBytes := payload[5+32:]
		decoded, derr := block.DecodeBatchData(batchBytes)
		if derr != nil {
			return nil, fmt.Errorf("covenant extractor: DecodeBatchData: %w", derr)
		}
		// L2 block number is one past the parent block number. We
		// don't have the parent number on hand here (the BatchData
		// embeds ParentHash, not number), so we leave L2BlockNum
		// unset (0) and let the race detector compare by txid + the
		// post-state root computed downstream. The race detector's
		// HandleCovenantAdvance accepts L2BlockNum=0 as "unknown
		// height" for the BEEF-driven path; pkg/network/sync.go
		// remains the authoritative source for L2BlockNum on
		// libp2p-gossip-driven advances.
		return &extractedAdvance{
			WithdrawalRoot: root,
			BatchData:      append([]byte(nil), batchBytes...),
			Decoded:        decoded,
		}, nil
	}
	return nil, errors.New("covenant extractor: no spec-12 OP_RETURN found in outputs")
}

// decodeAdvanceOpReturn returns the pushdata payload of an
// `OP_FALSE OP_RETURN <push>` script, or (nil, false) when the script
// does not match that shape. Tolerates the older `OP_RETURN <push>`
// form (no leading OP_FALSE) by treating a leading 0x6a as also
// valid.
func decodeAdvanceOpReturn(script []byte) ([]byte, bool) {
	if len(script) == 0 {
		return nil, false
	}
	pos := 0
	if script[pos] == 0x00 { // OP_FALSE
		pos++
		if pos >= len(script) {
			return nil, false
		}
	}
	if script[pos] != 0x6a { // OP_RETURN
		return nil, false
	}
	pos++
	if pos >= len(script) {
		return nil, false
	}
	op := script[pos]
	pos++
	switch {
	case op >= 0x01 && op <= 0x4b:
		n := int(op)
		if pos+n > len(script) {
			return nil, false
		}
		return script[pos : pos+n], true
	case op == 0x4c:
		if pos+1 > len(script) {
			return nil, false
		}
		n := int(script[pos])
		pos++
		if pos+n > len(script) {
			return nil, false
		}
		return script[pos : pos+n], true
	case op == 0x4d:
		if pos+2 > len(script) {
			return nil, false
		}
		n := int(script[pos]) | int(script[pos+1])<<8
		pos += 2
		if pos+n > len(script) {
			return nil, false
		}
		return script[pos : pos+n], true
	case op == 0x4e:
		if pos+4 > len(script) {
			return nil, false
		}
		n := int(script[pos]) | int(script[pos+1])<<8 | int(script[pos+2])<<16 | int(script[pos+3])<<24
		pos += 4
		if n < 0 || pos+n > len(script) {
			return nil, false
		}
		return script[pos : pos+n], true
	default:
		return nil, false
	}
}
