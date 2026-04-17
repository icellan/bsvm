package rpc

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"strconv"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// EthAPI implements the eth_* namespace of the JSON-RPC API.
type EthAPI struct {
	chainConfig *vm.ChainConfig
	chainDB     *block.ChainDB
	stateReader StateReader
	overlay     *overlay.OverlayNode
	vmConfig    vm.Config
	logIndex    *block.LogIndex
	// getLogsMaxRange caps the inclusive block span a single GetLogs call
	// may scan. Zero means unlimited (not recommended).
	getLogsMaxRange uint64
}

// NewEthAPI creates a new EthAPI instance.
func NewEthAPI(
	chainConfig *vm.ChainConfig,
	chainDB *block.ChainDB,
	stateReader StateReader,
	overlayNode *overlay.OverlayNode,
) *EthAPI {
	return &EthAPI{
		chainConfig: chainConfig,
		chainDB:     chainDB,
		stateReader: stateReader,
		overlay:     overlayNode,
		vmConfig: vm.Config{
			NoBaseFee: true,
		},
	}
}

// SetLogIndex sets the bloom-based log index for accelerated eth_getLogs
// queries. If nil, GetLogs falls back to scanning all blocks.
func (api *EthAPI) SetLogIndex(li *block.LogIndex) {
	api.logIndex = li
}

// SetGetLogsMaxRange configures the maximum inclusive block span
// (to - from + 1) a single eth_getLogs request may scan. Zero disables
// the cap. Negative values are clamped to zero.
func (api *EthAPI) SetGetLogsMaxRange(max uint64) {
	api.getLogsMaxRange = max
}

// ChainId returns the chain ID as a hex string.
// This implements eth_chainId.
func (api *EthAPI) ChainId() string {
	return EncodeBig(api.chainConfig.ChainID)
}

// BlockNumber returns the latest block number as a hex string.
// This implements eth_blockNumber.
func (api *EthAPI) BlockNumber() string {
	return EncodeUint64(api.overlay.ExecutionTip())
}

// GetBalance returns the balance of the given address at the specified block.
// This implements eth_getBalance.
func (api *EthAPI) GetBalance(address types.Address, blockNrOrHash BlockNumberOrHash) (string, error) {
	statedb, _, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return "", err
	}
	balance := statedb.GetBalance(address)
	return EncodeBig(balance.ToBig()), nil
}

// GetTransactionCount returns the nonce of the given address at the specified block.
// This implements eth_getTransactionCount.
func (api *EthAPI) GetTransactionCount(address types.Address, blockNrOrHash BlockNumberOrHash) (string, error) {
	statedb, _, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return "", err
	}
	nonce := statedb.GetNonce(address)
	return EncodeUint64(nonce), nil
}

// GetCode returns the code at the given address at the specified block.
// This implements eth_getCode.
func (api *EthAPI) GetCode(address types.Address, blockNrOrHash BlockNumberOrHash) (string, error) {
	statedb, _, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return "", err
	}
	code := statedb.GetCode(address)
	return EncodeBytes(code), nil
}

// GetStorageAt returns the value of a storage slot at the given address.
// This implements eth_getStorageAt.
func (api *EthAPI) GetStorageAt(address types.Address, slot types.Hash, blockNrOrHash BlockNumberOrHash) (string, error) {
	statedb, _, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return "", err
	}
	value := statedb.GetState(address, slot)
	return value.Hex(), nil
}

// Call executes a message against the state at the specified block without
// creating a transaction on the blockchain. Returns the output data.
// This implements eth_call.
func (api *EthAPI) Call(args TransactionArgs, blockNrOrHash BlockNumberOrHash) (string, error) {
	statedb, header, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return "", err
	}

	result, err := api.doCall(args, statedb, header)
	if err != nil {
		return "", err
	}

	if result.Err != nil {
		if result.Err == vm.ErrExecutionReverted {
			return EncodeBytes(result.ReturnData), fmt.Errorf("execution reverted: %s", EncodeBytes(result.ReturnData))
		}
		return "", result.Err
	}

	return EncodeBytes(result.ReturnData), nil
}

// EstimateGas estimates the gas needed to execute a transaction.
// This implements eth_estimateGas.
func (api *EthAPI) EstimateGas(args TransactionArgs, blockNrOrHash *BlockNumberOrHash) (string, error) {
	bNrOrHash := BlockNumberOrHashWithNumber(-1) // latest
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	statedb, header, err := api.stateAndHeaderByNumberOrHash(bNrOrHash)
	if err != nil {
		return "", err
	}

	// Determine the gas boundaries for binary search.
	lo := uint64(21000) // minimum gas for a transaction
	hi := header.GasLimit
	if args.Gas != nil && *args.Gas < hi {
		hi = *args.Gas
	}

	// If the gas is clearly enough, start with a higher minimum.
	cap := hi

	// Binary search for the minimum gas that succeeds.
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		argsCopy := args
		argsCopy.Gas = &mid

		result, callErr := api.doCall(argsCopy, statedb.Copy(), header)
		if callErr != nil || result.Failed() {
			lo = mid
		} else {
			hi = mid
		}
	}

	// Verify the final value works.
	argsFinal := args
	argsFinal.Gas = &hi
	result, callErr := api.doCall(argsFinal, statedb.Copy(), header)
	if callErr != nil {
		return "", callErr
	}
	if result.Failed() {
		if result.Err == vm.ErrExecutionReverted {
			return "", fmt.Errorf("execution reverted: %s", EncodeBytes(result.ReturnData))
		}
		return "", result.Err
	}

	// Add a small buffer to the estimate (10%).
	estimate := hi
	if estimate < cap {
		buffered := estimate + estimate/10
		if buffered > cap {
			buffered = cap
		}
		estimate = buffered
	}

	return EncodeUint64(estimate), nil
}

// SendRawTransaction decodes an RLP-encoded signed transaction and submits it
// to the overlay node for execution. Returns the transaction hash.
// This implements eth_sendRawTransaction.
func (api *EthAPI) SendRawTransaction(encodedTx []byte) (string, error) {
	tx, err := decodeRawTransaction(encodedTx)
	if err != nil {
		return "", fmt.Errorf("invalid transaction: %w", err)
	}

	// EIP-155 / EIP-2930 / EIP-1559 replay protection: reject any
	// transaction whose chainID does not match this shard before it
	// reaches validation or the batcher. Pre-EIP-155 legacy transactions
	// (v = 27 / 28) report chainID == 0 and are rejected here as well,
	// since this shard enforces EIP-155 replay protection.
	if err := api.assertChainID(tx); err != nil {
		return "", err
	}

	if err := api.overlay.ValidateTransaction(tx); err != nil {
		return "", err
	}

	if err := api.overlay.Batcher().Add(tx); err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

// assertChainID verifies that the transaction's chainID matches the shard's
// chainID. Pre-EIP-155 legacy transactions (v = 27 or 28) have no chainID
// and are rejected as replay-vulnerable.
func (api *EthAPI) assertChainID(tx *types.Transaction) error {
	want := api.chainConfig.ChainID
	if want == nil || want.Sign() == 0 {
		return nil
	}
	got := tx.ChainId()
	if got == nil || got.Sign() == 0 {
		// Legacy pre-EIP-155 transactions carry no replay protection and
		// are disallowed on a shard with a configured chainID.
		if tx.Type() == types.LegacyTxType {
			v, _, _ := tx.RawSignatureValues()
			if v != nil && (v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0) {
				return fmt.Errorf("invalid chain id: pre-EIP-155 transactions are not accepted (shard chainID %s)", want.String())
			}
		}
		return fmt.Errorf("invalid chain id: have 0 want %s", want.String())
	}
	if got.Cmp(want) != 0 {
		return fmt.Errorf("invalid chain id: have %s want %s", got.String(), want.String())
	}
	return nil
}

// decodeRawTransaction decodes an RLP-encoded signed transaction from the
// wire format used by eth_sendRawTransaction. For legacy transactions this
// is a plain RLP list. For typed (EIP-2718) transactions this is type_byte
// followed by the RLP-encoded inner fields.
func decodeRawTransaction(data []byte) (*types.Transaction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty transaction data")
	}

	// Determine if this is a typed transaction or a legacy transaction.
	// If the first byte is >= 0xc0, it is an RLP list (legacy transaction).
	if data[0] >= 0xc0 {
		return decodeLegacyRawTx(data)
	}

	// Typed transaction: first byte is type, rest is RLP.
	txType := data[0]
	body := data[1:]
	switch txType {
	case types.AccessListTxType:
		return decodeAccessListRawTx(body)
	case types.DynamicFeeTxType:
		return decodeDynamicFeeRawTx(body)
	default:
		return nil, fmt.Errorf("unsupported transaction type: %d", txType)
	}
}

// legacyRLPDecode is the RLP-decodable form of a legacy transaction.
// It mirrors the encoding format which uses *big.Int for Value.
type legacyRLPDecode struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *types.Address
	Value    *big.Int
	Data     []byte
	V        *big.Int
	R        *big.Int
	S        *big.Int
}

// accessListRLPDecode is the RLP-decodable form of an EIP-2930 transaction.
type accessListRLPDecode struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	Gas        uint64
	To         *types.Address
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

// dynamicFeeRLPDecode is the RLP-decodable form of an EIP-1559 transaction.
type dynamicFeeRLPDecode struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *types.Address
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

// decodeLegacyRawTx decodes a legacy RLP-encoded transaction.
func decodeLegacyRawTx(data []byte) (*types.Transaction, error) {
	var decoded legacyRLPDecode
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		return nil, fmt.Errorf("legacy decode failed: %w", err)
	}
	value, _ := uint256.FromBig(decoded.Value)
	if value == nil {
		value = new(uint256.Int)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    decoded.Nonce,
		GasPrice: decoded.GasPrice,
		Gas:      decoded.Gas,
		To:       decoded.To,
		Value:    value,
		Data:     decoded.Data,
		V:        decoded.V,
		R:        decoded.R,
		S:        decoded.S,
	})
	return tx, nil
}

// decodeAccessListRawTx decodes an EIP-2930 access list transaction.
func decodeAccessListRawTx(data []byte) (*types.Transaction, error) {
	var decoded accessListRLPDecode
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		return nil, fmt.Errorf("access list tx decode failed: %w", err)
	}
	value, _ := uint256.FromBig(decoded.Value)
	if value == nil {
		value = new(uint256.Int)
	}
	tx := types.NewTx(&types.AccessListTx{
		ChainID:    decoded.ChainID,
		Nonce:      decoded.Nonce,
		GasPrice:   decoded.GasPrice,
		Gas:        decoded.Gas,
		To:         decoded.To,
		Value:      value,
		Data:       decoded.Data,
		AccessList: decoded.AccessList,
		V:          decoded.V,
		R:          decoded.R,
		S:          decoded.S,
	})
	return tx, nil
}

// decodeDynamicFeeRawTx decodes an EIP-1559 dynamic fee transaction.
func decodeDynamicFeeRawTx(data []byte) (*types.Transaction, error) {
	var decoded dynamicFeeRLPDecode
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		return nil, fmt.Errorf("dynamic fee tx decode failed: %w", err)
	}
	value, _ := uint256.FromBig(decoded.Value)
	if value == nil {
		value = new(uint256.Int)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:    decoded.ChainID,
		Nonce:      decoded.Nonce,
		GasTipCap:  decoded.GasTipCap,
		GasFeeCap:  decoded.GasFeeCap,
		Gas:        decoded.Gas,
		To:         decoded.To,
		Value:      value,
		Data:       decoded.Data,
		AccessList: decoded.AccessList,
		V:          decoded.V,
		R:          decoded.R,
		S:          decoded.S,
	})
	return tx, nil
}

// GetTransactionByHash returns a transaction by its hash.
// This implements eth_getTransactionByHash.
func (api *EthAPI) GetTransactionByHash(hash types.Hash) (map[string]interface{}, error) {
	lookup, err := api.chainDB.ReadTxLookup(hash)
	if err != nil {
		return nil, nil // not found is not an error per Ethereum convention
	}

	txs := api.chainDB.ReadBody(lookup.BlockHash, lookup.BlockNumber)
	if txs == nil || int(lookup.Index) >= len(txs) {
		return nil, nil
	}

	tx := txs[lookup.Index]
	header := api.chainDB.ReadHeader(lookup.BlockHash, lookup.BlockNumber)

	return formatTransaction(tx, lookup.BlockHash, lookup.BlockNumber, lookup.Index, api.chainConfig, header), nil
}

// GetTransactionReceipt returns the receipt for a transaction by hash.
// This implements eth_getTransactionReceipt.
func (api *EthAPI) GetTransactionReceipt(hash types.Hash) (map[string]interface{}, error) {
	lookup, err := api.chainDB.ReadTxLookup(hash)
	if err != nil {
		return nil, nil // not found returns null
	}

	receipts := api.chainDB.ReadReceipts(lookup.BlockHash, lookup.BlockNumber)
	if receipts == nil || int(lookup.Index) >= len(receipts) {
		return nil, nil
	}

	receipt := receipts[lookup.Index]

	// Recover the sender from the transaction for the "from" field.
	txs := api.chainDB.ReadBody(lookup.BlockHash, lookup.BlockNumber)
	var from types.Address
	if txs != nil && int(lookup.Index) < len(txs) {
		signer := types.LatestSignerForChainID(api.chainConfig.ChainID)
		from, _ = types.Sender(signer, txs[lookup.Index])
	}

	return formatReceipt(receipt, lookup.BlockHash, lookup.BlockNumber, from, api.overlay.ProvenTip(), api.overlay.ConfirmedTip(), api.overlay.FinalizedTip()), nil
}

// GetBlockByNumber returns a block by number. If fullTxs is true, the full
// transaction objects are included; otherwise only hashes.
// This implements eth_getBlockByNumber.
func (api *EthAPI) GetBlockByNumber(blockNr int64, fullTxs bool) (map[string]interface{}, error) {
	number, err := api.resolveBlockNumber(blockNr)
	if err != nil {
		return nil, err
	}

	hash := api.chainDB.ReadCanonicalHash(number)
	if hash == (types.Hash{}) {
		return nil, nil
	}

	blk := api.chainDB.ReadBlock(hash, number)
	if blk == nil {
		return nil, nil
	}

	return formatBlock(blk, fullTxs, api.chainConfig), nil
}

// GetBlockByHash returns a block by its hash. If fullTxs is true, the full
// transaction objects are included; otherwise only hashes.
// This implements eth_getBlockByHash.
func (api *EthAPI) GetBlockByHash(hash types.Hash, fullTxs bool) (map[string]interface{}, error) {
	// Look up the block by searching the canonical chain.
	header := api.chainDB.ReadHeaderByHash(hash)
	if header == nil {
		return nil, nil
	}

	// Ensure Number is non-nil.
	if header.Number == nil {
		header.Number = new(big.Int)
	}

	blk := api.chainDB.ReadBlock(hash, header.Number.Uint64())
	if blk == nil {
		return nil, nil
	}

	return formatBlock(blk, fullTxs, api.chainConfig), nil
}

// GasPrice returns the suggested gas price as a hex string.
// This implements eth_gasPrice.
func (api *EthAPI) GasPrice() string {
	return EncodeBig(api.overlay.GasPriceOracleRef().SuggestGasPrice())
}

// GetLogs returns logs matching the given filter criteria.
// This implements eth_getLogs.
func (api *EthAPI) GetLogs(filter FilterQuery) ([]*logResult, error) {
	var from, to uint64

	if filter.BlockHash != nil {
		// Single block query by hash.
		header := api.chainDB.ReadHeaderByHash(*filter.BlockHash)
		if header == nil {
			return nil, fmt.Errorf("block not found: %s", filter.BlockHash.Hex())
		}
		if header.Number == nil {
			header.Number = new(big.Int)
		}
		from = header.Number.Uint64()
		to = from
	} else {
		// Block range query.
		tip := api.overlay.ExecutionTip()
		if filter.FromBlock != nil {
			if filter.FromBlock.Sign() < 0 {
				return nil, fmt.Errorf("invalid block range: from block %s is negative", filter.FromBlock.String())
			}
			from = filter.FromBlock.Uint64()
		}
		var requestedTo uint64
		toExplicit := filter.ToBlock != nil
		if toExplicit {
			if filter.ToBlock.Sign() < 0 {
				return nil, fmt.Errorf("invalid block range: to block %s is negative", filter.ToBlock.String())
			}
			requestedTo = filter.ToBlock.Uint64()
			to = requestedTo
		} else {
			to = tip
			requestedTo = tip
		}
		// Reject inverted ranges explicitly. Silently returning an empty
		// slice hides client bugs and diverges from geth behaviour. The
		// comparison uses the user-supplied `to` (before tip clamping) so
		// that "from > tip" (a perfectly valid forward-looking range) is
		// not misreported as inverted.
		if toExplicit && filter.FromBlock != nil && from > requestedTo {
			return nil, fmt.Errorf("invalid block range: from (%d) > to (%d)", from, requestedTo)
		}
		// Enforce the configured span cap against the user-requested
		// range. Validating AFTER tip clamping would let a malicious
		// client pass `to = 2^63-1` and silently have it reduced to the
		// tip, defeating the cap. The cap is inclusive so from == to (a
		// single-block query) always succeeds.
		if api.getLogsMaxRange > 0 && requestedTo >= from {
			span := requestedTo - from + 1
			if span > api.getLogsMaxRange {
				return nil, fmt.Errorf("block range too large: max %d blocks, got %d", api.getLogsMaxRange, span)
			}
		}
		if to > tip {
			to = tip
		}
	}

	var results []*logResult
	for n := from; n <= to; n++ {
		// If a log index is available, check the bloom filter first to
		// skip blocks that definitely do not contain matching logs.
		if api.logIndex != nil {
			mayContain, err := api.logIndex.BlockMayContainLog(n, filter.Addresses, filter.Topics)
			if err == nil && !mayContain {
				continue
			}
		}

		hash := api.chainDB.ReadCanonicalHash(n)
		if hash == (types.Hash{}) {
			continue
		}
		logs := getBlockLogs(api.chainDB, hash, n, filter.Addresses, filter.Topics)
		for _, log := range logs {
			results = append(results, formatLog(log))
		}
	}

	if results == nil {
		results = make([]*logResult, 0)
	}
	return results, nil
}

// GetBlockReceipts returns all receipts for a block by number or tag.
// This implements eth_getBlockReceipts.
func (api *EthAPI) GetBlockReceipts(blockNr int64) ([]map[string]interface{}, error) {
	number, err := api.resolveBlockNumber(blockNr)
	if err != nil {
		return nil, err
	}

	hash := api.chainDB.ReadCanonicalHash(number)
	if hash == (types.Hash{}) {
		return nil, nil
	}

	receipts := api.chainDB.ReadReceipts(hash, number)
	if receipts == nil {
		return nil, nil
	}

	txs := api.chainDB.ReadBody(hash, number)
	signer := types.LatestSignerForChainID(api.chainConfig.ChainID)

	var result []map[string]interface{}
	for i, receipt := range receipts {
		var from types.Address
		if txs != nil && i < len(txs) {
			from, _ = types.Sender(signer, txs[i])
		}
		result = append(result, formatReceipt(receipt, hash, number, from, api.overlay.ProvenTip(), api.overlay.ConfirmedTip(), api.overlay.FinalizedTip()))
	}
	return result, nil
}

// GetBlockTransactionCountByNumber returns the number of transactions in a
// block given the block number. This implements eth_getBlockTransactionCountByNumber.
func (api *EthAPI) GetBlockTransactionCountByNumber(blockNr int64) (string, error) {
	number, err := api.resolveBlockNumber(blockNr)
	if err != nil {
		return "", err
	}
	hash := api.chainDB.ReadCanonicalHash(number)
	if hash == (types.Hash{}) {
		return "", fmt.Errorf("block %d not found", number)
	}
	txs := api.chainDB.ReadBody(hash, number)
	return EncodeUint64(uint64(len(txs))), nil
}

// GetBlockTransactionCountByHash returns the number of transactions in a
// block given the block hash. This implements eth_getBlockTransactionCountByHash.
func (api *EthAPI) GetBlockTransactionCountByHash(hash types.Hash) (string, error) {
	header := api.chainDB.ReadHeaderByHash(hash)
	if header == nil {
		return "", fmt.Errorf("block not found: %s", hash.Hex())
	}
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	txs := api.chainDB.ReadBody(hash, header.Number.Uint64())
	return EncodeUint64(uint64(len(txs))), nil
}

// FeeHistory returns historical gas information for a range of blocks. For this
// L2, the base fee is always zero (no EIP-1559 dynamic pricing). The returned
// baseFeePerGas array has blockCount+1 entries (includes next block prediction).
// gasUsedRatio is computed from actual header data.
func (api *EthAPI) FeeHistory(blockCount uint64, newestBlock uint64) (map[string]interface{}, error) {
	if blockCount == 0 {
		return map[string]interface{}{
			"oldestBlock":   EncodeUint64(newestBlock),
			"baseFeePerGas": []string{"0x0"},
			"gasUsedRatio":  []float64{},
		}, nil
	}

	// Cap blockCount to available blocks (0..newestBlock inclusive).
	available := newestBlock + 1
	if blockCount > available {
		blockCount = available
	}

	oldestBlock := newestBlock - blockCount + 1

	baseFees := make([]string, blockCount+1)
	gasUsedRatios := make([]float64, blockCount)

	for i := uint64(0); i < blockCount; i++ {
		num := oldestBlock + i
		baseFees[i] = "0x0"

		header := api.chainDB.ReadHeaderByNumber(num)
		if header != nil && header.GasLimit > 0 {
			gasUsedRatios[i] = float64(header.GasUsed) / float64(header.GasLimit)
		}
	}
	// The extra entry is the predicted base fee for the block after newestBlock.
	baseFees[blockCount] = "0x0"

	return map[string]interface{}{
		"oldestBlock":   EncodeUint64(oldestBlock),
		"baseFeePerGas": baseFees,
		"gasUsedRatio":  gasUsedRatios,
	}, nil
}

// Syncing returns false when the node is fully synced, or a sync progress
// object when actively syncing. For this L2, which has no traditional sync
// mechanism, the node either has state or it doesn't. Returns false (synced)
// in all current cases; returns interface{} to match the Ethereum spec which
// allows either false or a progress object.
func (api *EthAPI) Syncing() interface{} {
	// For an L2 without a traditional sync mechanism, returning false is
	// correct. The node either has state or it doesn't. If SyncFromBSV is
	// actively running in the future, this should return a sync object.
	return false
}

// Accounts returns an empty list since the node holds no local accounts.
// This implements eth_accounts.
func (api *EthAPI) Accounts() []types.Address {
	return []types.Address{}
}

// MaxPriorityFeePerGas returns the suggested max priority fee per gas.
// This implements eth_maxPriorityFeePerGas.
func (api *EthAPI) MaxPriorityFeePerGas() string {
	return EncodeBig(api.overlay.GasPriceOracleRef().SuggestGasPrice())
}

// resolveBlockNumber converts a special block number constant (-1 for latest,
// -2 for safe, -3 for finalized, 0+ for specific block) to a concrete number.
func (api *EthAPI) resolveBlockNumber(blockNr int64) (uint64, error) {
	switch blockNr {
	case -1: // latest, pending
		return api.overlay.ExecutionTip(), nil
	case -2: // safe
		return api.overlay.ProvenTip(), nil
	case -3: // finalized
		return api.overlay.FinalizedTip(), nil
	case -4: // confirmed
		return api.overlay.ConfirmedTip(), nil
	default:
		if blockNr < 0 {
			return 0, fmt.Errorf("invalid block number: %d", blockNr)
		}
		return uint64(blockNr), nil
	}
}

// stateAndHeaderByNumberOrHash returns a state database and header for the
// given block identifier.
func (api *EthAPI) stateAndHeaderByNumberOrHash(blockNrOrHash BlockNumberOrHash) (*state.StateDB, *block.L2Header, error) {
	if blockNrOrHash.BlockHash != nil {
		header := api.chainDB.ReadHeaderByHash(*blockNrOrHash.BlockHash)
		if header == nil {
			return nil, nil, fmt.Errorf("block not found: %s", blockNrOrHash.BlockHash.Hex())
		}
		if header.Number == nil {
			header.Number = new(big.Int)
		}
		statedb, err := api.stateReader.StateAt(header.StateRoot)
		if err != nil {
			return nil, nil, err
		}
		return statedb, header, nil
	}

	if blockNrOrHash.BlockNumber == nil {
		return nil, nil, errors.New("invalid block identifier: no number or hash")
	}

	number, err := api.resolveBlockNumber(*blockNrOrHash.BlockNumber)
	if err != nil {
		return nil, nil, err
	}

	header := api.chainDB.ReadHeaderByNumber(number)
	if header == nil {
		return nil, nil, fmt.Errorf("block %d not found", number)
	}
	if header.Number == nil {
		header.Number = new(big.Int).SetUint64(number)
	}
	if header.BaseFee == nil {
		header.BaseFee = new(big.Int)
	}

	statedb, err := api.stateReader.StateAt(header.StateRoot)
	if err != nil {
		return nil, nil, err
	}
	return statedb, header, nil
}

// doCall executes a call against the given state. The state may be mutated
// by the call.
func (api *EthAPI) doCall(args TransactionArgs, statedb *state.StateDB, header *block.L2Header) (*block.ExecutionResult, error) {
	args.setDefaults(header.GasLimit)

	msg := args.toMessage(header.GasLimit, header.BaseFee)

	blockCtx := vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			h := api.chainDB.ReadHeaderByNumber(n)
			if h != nil {
				return h.Hash()
			}
			return types.Hash{}
		},
		Coinbase:    header.Coinbase,
		GasLimit:    header.GasLimit,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Timestamp,
		Difficulty:  big.NewInt(0),
		BaseFee:     new(big.Int).Set(header.BaseFee),
		BlobBaseFee: big.NewInt(1),
	}

	evmInst := vm.NewEVM(blockCtx, statedb, api.chainConfig, api.vmConfig)

	gp := new(block.GasPool)
	gp.SetGas(math.MaxUint64)

	result, err := block.ApplyMessage(evmInst, msg, gp)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// formatBlock converts a block to the Ethereum JSON-RPC response format.
func formatBlock(blk *block.L2Block, fullTxs bool, config *vm.ChainConfig) map[string]interface{} {
	header := blk.Header
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	if header.BaseFee == nil {
		header.BaseFee = new(big.Int)
	}

	result := map[string]interface{}{
		"number":           EncodeUint64(header.Number.Uint64()),
		"hash":             blk.Hash().Hex(),
		"parentHash":       header.ParentHash.Hex(),
		"nonce":            "0x0000000000000000",
		"sha3Uncles":       types.EmptyRootHash.Hex(),
		"logsBloom":        EncodeBytes(header.LogsBloom.Bytes()),
		"transactionsRoot": header.TxHash.Hex(),
		"stateRoot":        header.StateRoot.Hex(),
		"receiptsRoot":     header.ReceiptHash.Hex(),
		"miner":            EncodeAddress(header.Coinbase),
		"difficulty":       "0x0",
		"totalDifficulty":  "0x0",
		"extraData":        EncodeBytes(header.Extra),
		"size":             EncodeUint64(0),
		"gasLimit":         EncodeUint64(header.GasLimit),
		"gasUsed":          EncodeUint64(header.GasUsed),
		"timestamp":        EncodeUint64(header.Timestamp),
		"baseFeePerGas":    EncodeBig(header.BaseFee),
		"uncles":           []string{},
		"mixHash":          types.Hash{}.Hex(),
	}

	if fullTxs {
		txObjects := make([]map[string]interface{}, 0, len(blk.Transactions))
		for i, tx := range blk.Transactions {
			txObjects = append(txObjects, formatTransaction(tx, blk.Hash(), header.Number.Uint64(), uint64(i), config, header))
		}
		result["transactions"] = txObjects
	} else {
		txHashes := make([]string, 0, len(blk.Transactions))
		for _, tx := range blk.Transactions {
			txHashes = append(txHashes, tx.Hash().Hex())
		}
		result["transactions"] = txHashes
	}

	return result
}

// formatTransaction converts a transaction to the Ethereum JSON-RPC response format.
func formatTransaction(tx *types.Transaction, blockHash types.Hash, blockNumber uint64, index uint64, config *vm.ChainConfig, header *block.L2Header) map[string]interface{} {
	signer := types.LatestSignerForChainID(config.ChainID)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()

	result := map[string]interface{}{
		"hash":             tx.Hash().Hex(),
		"nonce":            EncodeUint64(tx.Nonce()),
		"blockHash":        blockHash.Hex(),
		"blockNumber":      EncodeUint64(blockNumber),
		"transactionIndex": EncodeUint64(index),
		"from":             EncodeAddress(from),
		"value":            EncodeBig(tx.Value().ToBig()),
		"gas":              EncodeUint64(tx.Gas()),
		"gasPrice":         EncodeBig(tx.GasPrice()),
		"input":            EncodeBytes(tx.Data()),
		"type":             EncodeUint64(uint64(tx.Type())),
		"chainId":          EncodeBig(tx.ChainId()),
	}

	if tx.To() != nil {
		result["to"] = EncodeAddress(*tx.To())
	} else {
		result["to"] = nil
	}

	if v != nil {
		result["v"] = EncodeBig(v)
	} else {
		result["v"] = "0x0"
	}
	if r != nil {
		result["r"] = EncodeBig(r)
	} else {
		result["r"] = "0x0"
	}
	if s != nil {
		result["s"] = EncodeBig(s)
	} else {
		result["s"] = "0x0"
	}

	return result
}

// logResult is the JSON-RPC response format for a log entry.
type logResult struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockNumber      string   `json:"blockNumber"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	BlockHash        string   `json:"blockHash"`
	LogIndex         string   `json:"logIndex"`
	Removed          bool     `json:"removed"`
}

// formatLog converts a log to the JSON-RPC response format.
func formatLog(log *types.Log) *logResult {
	topics := make([]string, len(log.Topics))
	for i, t := range log.Topics {
		topics[i] = t.Hex()
	}
	return &logResult{
		Address:          EncodeAddress(log.Address),
		Topics:           topics,
		Data:             EncodeBytes(log.Data),
		BlockNumber:      EncodeUint64(log.BlockNumber),
		TransactionHash:  log.TxHash.Hex(),
		TransactionIndex: EncodeUint64(uint64(log.TxIndex)),
		BlockHash:        log.BlockHash.Hex(),
		LogIndex:         EncodeUint64(uint64(log.Index)),
		Removed:          log.Removed,
	}
}

// formatReceipt converts a receipt to the Ethereum JSON-RPC response format.
func formatReceipt(receipt *types.Receipt, blockHash types.Hash, blockNumber uint64, from types.Address, provenTip uint64, confirmedTip uint64, finalizedTip uint64) map[string]interface{} {
	logs := make([]*logResult, 0, len(receipt.Logs))
	for _, log := range receipt.Logs {
		log.BlockHash = blockHash
		log.BlockNumber = blockNumber
		logs = append(logs, formatLog(log))
	}
	if logs == nil {
		logs = make([]*logResult, 0)
	}

	// effectiveGasPrice: for our L2, gas price is always what the tx specified.
	// Standard Ethereum tooling (ethers.js, Hardhat) requires this field.
	effectiveGasPrice := "0x0"
	if receipt.EffectiveGasPrice != nil {
		effectiveGasPrice = EncodeBig(receipt.EffectiveGasPrice)
	}

	result := map[string]interface{}{
		"transactionHash":   receipt.TxHash.Hex(),
		"transactionIndex":  EncodeUint64(uint64(receipt.TransactionIndex)),
		"blockHash":         blockHash.Hex(),
		"blockNumber":       EncodeUint64(blockNumber),
		"from":              EncodeAddress(from),
		"cumulativeGasUsed": EncodeUint64(receipt.CumulativeGasUsed),
		"gasUsed":           EncodeUint64(receipt.GasUsed),
		"effectiveGasPrice": effectiveGasPrice,
		"logs":              logs,
		"logsBloom":         EncodeBytes(receipt.Bloom.Bytes()),
		"status":            EncodeUint64(receipt.Status),
		"type":              EncodeUint64(uint64(receipt.Type)),
	}

	if receipt.ContractAddress != (types.Address{}) {
		result["contractAddress"] = EncodeAddress(receipt.ContractAddress)
	} else {
		result["contractAddress"] = nil
	}

	// Look up the transaction to get the "to" address.
	result["to"] = nil
	if receipt.ContractAddress == (types.Address{}) {
		// For non-contract-creation, we'd need the tx to fill "to".
		// Since the receipt doesn't store it, leave it nil if unavailable.
	}

	// Add rollback fields only when the receipt has been rolled back.
	if receipt.RolledBack {
		result["rolledBack"] = true
		result["rolledBackAtBlock"] = EncodeUint64(receipt.RolledBackAtBlock)
	}

	// Add BSV confirmation status extension.
	if blockNumber <= finalizedTip {
		result["bsvConfirmationStatus"] = "finalized"
	} else if blockNumber <= confirmedTip {
		result["bsvConfirmationStatus"] = "confirmed"
	} else if blockNumber <= provenTip {
		result["bsvConfirmationStatus"] = "proven"
	} else {
		result["bsvConfirmationStatus"] = "speculative"
	}

	return result
}

// EncodeInt64 returns a hex string with 0x prefix for a signed int64.
//
// Negative values are returned as a "-" prefixed hex string (e.g. -1 maps
// to "-0x1"). In practice no Ethereum JSON-RPC field that flows through
// this encoder is legitimately negative, so the caller is almost certainly
// holding a bug — a warning is logged to surface it without returning the
// ambiguous "0x0" that silently collides with the legitimate encoding of
// zero.
func EncodeInt64(v int64) string {
	if v < 0 {
		slog.Warn("EncodeInt64 received negative value", "value", v)
		// Use the absolute value for the hex payload to avoid relying on
		// int64 two's-complement wraparound for math.MinInt64.
		abs := uint64(-(v + 1)) + 1
		return "-0x" + strconv.FormatUint(abs, 16)
	}
	return EncodeUint64(uint64(v))
}

// GetTransactionByBlockHashAndIndex returns a transaction by block hash and
// index position within that block. Returns nil if the block is not found or
// the index is out of range.
// This implements eth_getTransactionByBlockHashAndIndex.
func (api *EthAPI) GetTransactionByBlockHashAndIndex(blockHash types.Hash, index uint64) (map[string]interface{}, error) {
	header := api.chainDB.ReadHeaderByHash(blockHash)
	if header == nil {
		return nil, nil
	}
	if header.Number == nil {
		header.Number = new(big.Int)
	}

	txs := api.chainDB.ReadBody(blockHash, header.Number.Uint64())
	if txs == nil || index >= uint64(len(txs)) {
		return nil, nil
	}

	tx := txs[index]
	return formatTransaction(tx, blockHash, header.Number.Uint64(), index, api.chainConfig, header), nil
}

// GetTransactionByBlockNumberAndIndex returns a transaction by block number
// and index position within that block. Block number supports -1 (latest),
// -2 (safe), and -3 (finalized). Returns nil if the block is not found or
// the index is out of range.
// This implements eth_getTransactionByBlockNumberAndIndex.
func (api *EthAPI) GetTransactionByBlockNumberAndIndex(blockNr int64, index uint64) (map[string]interface{}, error) {
	number, err := api.resolveBlockNumber(blockNr)
	if err != nil {
		return nil, err
	}

	hash := api.chainDB.ReadCanonicalHash(number)
	if hash == (types.Hash{}) {
		return nil, nil
	}

	txs := api.chainDB.ReadBody(hash, number)
	if txs == nil || index >= uint64(len(txs)) {
		return nil, nil
	}

	tx := txs[index]
	header := api.chainDB.ReadHeader(hash, number)
	return formatTransaction(tx, hash, number, index, api.chainConfig, header), nil
}

// GetProof returns the Merkle-Patricia proof for an account and optional
// storage keys at a given block. This implements EIP-1186 (eth_getProof).
func (api *EthAPI) GetProof(addr types.Address, storageKeys []types.Hash, blockNrOrHash BlockNumberOrHash) (map[string]interface{}, error) {
	statedb, _, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
	if err != nil {
		return nil, err
	}

	// Get account proof.
	accountProof, err := statedb.GetProof(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get account proof: %w", err)
	}

	// Encode account proof nodes as hex strings.
	proofHex := make([]string, len(accountProof))
	for i, node := range accountProof {
		proofHex[i] = EncodeBytes(node)
	}

	// Get account data.
	balance := statedb.GetBalance(addr)
	nonce := statedb.GetNonce(addr)
	codeHash := statedb.GetCodeHash(addr)
	storageRoot := statedb.GetStorageRoot(addr)

	// Build storage proofs.
	storageProofs := make([]map[string]interface{}, len(storageKeys))
	for i, key := range storageKeys {
		proof, err := statedb.GetStorageProof(addr, key)
		if err != nil {
			return nil, fmt.Errorf("failed to get storage proof for key %s: %w", key.Hex(), err)
		}
		proofNodes := make([]string, len(proof))
		for j, node := range proof {
			proofNodes[j] = EncodeBytes(node)
		}
		value := statedb.GetState(addr, key)
		storageProofs[i] = map[string]interface{}{
			"key":   key.Hex(),
			"value": value.Hex(),
			"proof": proofNodes,
		}
	}

	return map[string]interface{}{
		"address":      EncodeAddress(addr),
		"accountProof": proofHex,
		"balance":      EncodeBig(balance.ToBig()),
		"codeHash":     codeHash.Hex(),
		"nonce":        EncodeUint64(nonce),
		"storageHash":  storageRoot.Hex(),
		"storageProof": storageProofs,
	}, nil
}

// CreateAccessList runs a transaction against the state and collects all
// addresses and storage slots accessed during execution. It returns the
// collected access list and the gas used.
// This implements eth_createAccessList.
func (api *EthAPI) CreateAccessList(args TransactionArgs, blockNrOrHash *BlockNumberOrHash) (map[string]interface{}, error) {
	bNrOrHash := BlockNumberOrHashWithNumber(-1) // latest
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	statedb, header, err := api.stateAndHeaderByNumberOrHash(bNrOrHash)
	if err != nil {
		return nil, err
	}

	// Execute the call to collect accesses.
	result, err := api.doCall(args, statedb, header)
	if err != nil {
		return nil, err
	}

	// Collect access list entries from the state after execution.
	entries := statedb.AccessListEntries()

	// Filter out the sender and destination from the access list (they are
	// always warm and should not be in the returned access list per EIP-2930).
	var sender types.Address
	if args.From != nil {
		sender = *args.From
	}

	accessList := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		// Skip sender and destination addresses.
		if entry.Address == sender {
			continue
		}
		if args.To != nil && entry.Address == *args.To {
			continue
		}

		keys := make([]string, 0, len(entry.StorageKeys))
		for _, key := range entry.StorageKeys {
			keys = append(keys, key.Hex())
		}
		accessList = append(accessList, map[string]interface{}{
			"address":     EncodeAddress(entry.Address),
			"storageKeys": keys,
		})
	}

	gasUsed := uint64(0)
	if result != nil {
		gasUsed = result.UsedGas
	}

	return map[string]interface{}{
		"accessList": accessList,
		"gasUsed":    EncodeUint64(gasUsed),
	}, nil
}

// ensure the uint256 import is used
var _ = uint256.NewInt
