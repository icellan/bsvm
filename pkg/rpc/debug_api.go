package rpc

import (
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// DebugAPI provides debug_* RPC methods for EVM tracing.
type DebugAPI struct {
	ethAPI  *EthAPI
	overlay *overlay.OverlayNode
}

// NewDebugAPI creates a new DebugAPI instance.
func NewDebugAPI(ethAPI *EthAPI, overlayNode *overlay.OverlayNode) *DebugAPI {
	return &DebugAPI{
		ethAPI:  ethAPI,
		overlay: overlayNode,
	}
}

// StructLog represents a single execution step captured by the StructLogger.
type StructLog struct {
	Pc      uint64            `json:"pc"`
	Op      string            `json:"op"`
	Gas     uint64            `json:"gas"`
	GasCost uint64            `json:"gasCost"`
	Depth   int               `json:"depth"`
	Stack   []string          `json:"stack"`
	Memory  []string          `json:"memory,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// TraceResult is the response format for debug_traceTransaction, matching
// geth's output.
type TraceResult struct {
	Gas         uint64      `json:"gas"`
	Failed      bool        `json:"failed"`
	ReturnValue string      `json:"returnValue"`
	StructLogs  []StructLog `json:"structLogs"`
}

// StructLogger is a tracer that captures each opcode executed during EVM
// execution. It implements the tracing hooks interface and produces output
// compatible with geth's debug_traceTransaction format.
type StructLogger struct {
	mu      sync.Mutex
	logs    []StructLog
	output  []byte
	err     error
	gasUsed uint64
	storage map[types.Address]map[types.Hash]types.Hash
}

// NewStructLogger creates a new StructLogger instance.
func NewStructLogger() *StructLogger {
	return &StructLogger{
		storage: make(map[types.Address]map[types.Hash]types.Hash),
	}
}

// Hooks returns the tracing.Hooks that capture EVM execution events.
func (sl *StructLogger) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnOpcode:        sl.onOpcode,
		OnStorageChange: sl.onStorageChange,
		OnTxEnd:         sl.onTxEnd,
	}
}

// onOpcode is called for each opcode executed.
func (sl *StructLogger) onOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Capture stack.
	stackData := scope.StackData()
	stack := make([]string, len(stackData))
	for i, v := range stackData {
		stack[i] = fmt.Sprintf("0x%x", v.Bytes32())
	}

	// Capture storage for the current address.
	addr := scope.Address()
	var storage map[string]string
	if addrStorage, ok := sl.storage[addr]; ok && len(addrStorage) > 0 {
		storage = make(map[string]string, len(addrStorage))
		for k, v := range addrStorage {
			storage[k.Hex()] = v.Hex()
		}
	}

	// Capture memory (in 32-byte words).
	memData := scope.MemoryData()
	var memory []string
	if len(memData) > 0 {
		for i := 0; i < len(memData); i += 32 {
			end := i + 32
			if end > len(memData) {
				end = len(memData)
			}
			memory = append(memory, fmt.Sprintf("0x%x", memData[i:end]))
		}
	}

	sl.logs = append(sl.logs, StructLog{
		Pc:      pc,
		Op:      vm.OpCode(op).String(),
		Gas:     gas,
		GasCost: cost,
		Depth:   depth,
		Stack:   stack,
		Memory:  memory,
		Storage: storage,
	})
}

// onStorageChange is called when a storage slot is modified.
func (sl *StructLogger) onStorageChange(addr types.Address, slot types.Hash, prev, new types.Hash) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.storage[addr] == nil {
		sl.storage[addr] = make(map[types.Hash]types.Hash)
	}
	sl.storage[addr][slot] = new
}

// onTxEnd is called when a transaction finishes.
func (sl *StructLogger) onTxEnd(gasUsed uint64, err error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.gasUsed = gasUsed
	sl.err = err
}

// Result returns the trace result after execution.
func (sl *StructLogger) Result() *TraceResult {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	logs := sl.logs
	if logs == nil {
		logs = []StructLog{}
	}

	return &TraceResult{
		Gas:         sl.gasUsed,
		Failed:      sl.err != nil,
		ReturnValue: EncodeBytes(sl.output),
		StructLogs:  logs,
	}
}

// TraceTransaction replays a transaction and returns the execution trace.
func (api *DebugAPI) TraceTransaction(txHash string) (interface{}, error) {
	hash := types.HexToHash(txHash)

	lookup, err := api.ethAPI.chainDB.ReadTxLookup(hash)
	if err != nil {
		return nil, fmt.Errorf("transaction %s not found", txHash)
	}

	// Read the block's transactions.
	txs := api.ethAPI.chainDB.ReadBody(lookup.BlockHash, lookup.BlockNumber)
	if txs == nil {
		return nil, fmt.Errorf("block body not found for %s", lookup.BlockHash.Hex())
	}

	// Get the parent block's state.
	header := api.ethAPI.chainDB.ReadHeaderByNumber(lookup.BlockNumber)
	if header == nil {
		return nil, fmt.Errorf("block %d not found", lookup.BlockNumber)
	}

	var parentHeader *block.L2Header
	if lookup.BlockNumber > 0 {
		parentHeader = api.ethAPI.chainDB.ReadHeaderByNumber(lookup.BlockNumber - 1)
	}
	if parentHeader == nil {
		// For genesis block or if parent not found, use current header.
		parentHeader = header
	}

	statedb, err := api.ethAPI.stateReader.StateAt(parentHeader.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("state not available at block %d: %v", lookup.BlockNumber-1, err)
	}

	// Replay preceding transactions to get to the right state.
	for i := uint64(0); i < lookup.Index; i++ {
		if int(i) >= len(txs) {
			break
		}
		msg := txToMessage(txs[i], api.ethAPI.chainConfig)
		blockCtx := api.makeBlockContext(header)
		evmInst := vm.NewEVM(blockCtx, statedb, api.ethAPI.chainConfig, vm.Config{NoBaseFee: true})
		gp := new(block.GasPool)
		gp.SetGas(header.GasLimit)
		block.ApplyMessage(evmInst, msg, gp)
	}

	// Now trace the target transaction.
	if int(lookup.Index) >= len(txs) {
		return nil, fmt.Errorf("transaction index %d out of range", lookup.Index)
	}

	targetTx := txs[lookup.Index]
	msg := txToMessage(targetTx, api.ethAPI.chainConfig)

	logger := NewStructLogger()
	blockCtx := api.makeBlockContext(header)
	evmInst := vm.NewEVM(blockCtx, statedb, api.ethAPI.chainConfig, vm.Config{
		Tracer:    logger.Hooks(),
		NoBaseFee: true,
	})
	gp := new(block.GasPool)
	gp.SetGas(header.GasLimit)
	result, err := block.ApplyMessage(evmInst, msg, gp)
	if err != nil {
		return nil, err
	}

	logger.mu.Lock()
	logger.output = result.ReturnData
	logger.gasUsed = result.UsedGas
	if result.Err != nil {
		logger.err = result.Err
	}
	logger.mu.Unlock()

	return logger.Result(), nil
}

// TraceCall executes a call and returns the execution trace.
func (api *DebugAPI) TraceCall(args TransactionArgs, blockNrOrHash string) (interface{}, error) {
	blockTag, err := resolveBlockTag(blockNrOrHash)
	if err != nil {
		return nil, fmt.Errorf("invalid block tag: %v", err)
	}

	bnh := BlockNumberOrHashWithNumber(blockTag)
	statedb, header, err := api.ethAPI.stateAndHeaderByNumberOrHash(bnh)
	if err != nil {
		return nil, err
	}

	args.setDefaults(header.GasLimit)
	msg := args.toMessage(header.GasLimit, header.BaseFee)

	logger := NewStructLogger()
	blockCtx := api.makeBlockContext(header)
	evmInst := vm.NewEVM(blockCtx, statedb, api.ethAPI.chainConfig, vm.Config{
		Tracer:    logger.Hooks(),
		NoBaseFee: true,
	})
	gp := new(block.GasPool)
	gp.SetGas(math.MaxUint64)
	result, err := block.ApplyMessage(evmInst, msg, gp)
	if err != nil {
		return nil, err
	}

	logger.mu.Lock()
	logger.output = result.ReturnData
	logger.gasUsed = result.UsedGas
	if result.Err != nil {
		logger.err = result.Err
	}
	logger.mu.Unlock()

	return logger.Result(), nil
}

// TraceBlockByNumber returns traces for all transactions in a block.
func (api *DebugAPI) TraceBlockByNumber(blockNr string) (interface{}, error) {
	blockTag, err := resolveBlockTag(blockNr)
	if err != nil {
		return nil, fmt.Errorf("invalid block number: %v", err)
	}

	number, err := api.ethAPI.resolveBlockNumber(blockTag)
	if err != nil {
		return nil, err
	}

	header := api.ethAPI.chainDB.ReadHeaderByNumber(number)
	if header == nil {
		return nil, fmt.Errorf("block %d not found", number)
	}

	return api.traceBlock(header)
}

// TraceBlockByHash returns traces for all transactions in a block.
func (api *DebugAPI) TraceBlockByHash(blockHash string) (interface{}, error) {
	hash := types.HexToHash(blockHash)

	header := api.ethAPI.chainDB.ReadHeaderByHash(hash)
	if header == nil {
		return nil, fmt.Errorf("block not found: %s", blockHash)
	}

	return api.traceBlock(header)
}

// EVMDisagreement returns diagnostic data about Go EVM / SP1 revm divergence.
func (api *DebugAPI) EVMDisagreement() (interface{}, error) {
	cb := api.overlay.CircuitBreaker()

	return map[string]interface{}{
		"tripped":             cb.IsTripped(),
		"consecutiveFailures": cb.ConsecutiveFailures(),
		"maxRetries":          cb.MaxRetries(),
	}, nil
}

// traceBlock traces all transactions in a block.
func (api *DebugAPI) traceBlock(header *block.L2Header) (interface{}, error) {
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	blockNumber := header.Number.Uint64()
	blockHash := header.Hash()

	txs := api.ethAPI.chainDB.ReadBody(blockHash, blockNumber)
	if txs == nil {
		return []interface{}{}, nil
	}

	// Get the parent block's state.
	var parentHeader *block.L2Header
	if blockNumber > 0 {
		parentHeader = api.ethAPI.chainDB.ReadHeaderByNumber(blockNumber - 1)
	}
	if parentHeader == nil {
		parentHeader = header
	}

	statedb, err := api.ethAPI.stateReader.StateAt(parentHeader.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("state not available at block %d: %v", blockNumber-1, err)
	}

	var results []interface{}

	for _, tx := range txs {
		msg := txToMessage(tx, api.ethAPI.chainConfig)

		logger := NewStructLogger()
		blockCtx := api.makeBlockContext(header)
		evmInst := vm.NewEVM(blockCtx, statedb, api.ethAPI.chainConfig, vm.Config{
			Tracer:    logger.Hooks(),
			NoBaseFee: true,
		})
		gp := new(block.GasPool)
		gp.SetGas(header.GasLimit)
		result, applyErr := block.ApplyMessage(evmInst, msg, gp)

		if applyErr != nil {
			results = append(results, map[string]interface{}{
				"txHash": tx.Hash().Hex(),
				"error":  applyErr.Error(),
			})
			continue
		}

		logger.mu.Lock()
		logger.output = result.ReturnData
		logger.gasUsed = result.UsedGas
		if result.Err != nil {
			logger.err = result.Err
		}
		logger.mu.Unlock()

		traceResult := logger.Result()
		results = append(results, map[string]interface{}{
			"txHash": tx.Hash().Hex(),
			"result": traceResult,
		})
	}

	return results, nil
}

// makeBlockContext creates a VM block context from a header.
func (api *DebugAPI) makeBlockContext(header *block.L2Header) vm.BlockContext {
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	if header.BaseFee == nil {
		header.BaseFee = new(big.Int)
	}

	return vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			h := api.ethAPI.chainDB.ReadHeaderByNumber(n)
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
}

// txToMessage converts a stored transaction to a Message for replay.
func txToMessage(tx *types.Transaction, chainConfig *vm.ChainConfig) *block.Message {
	signer := types.LatestSignerForChainID(chainConfig.ChainID)
	from, _ := types.Sender(signer, tx)

	msg := &block.Message{
		From:     from,
		GasLimit: tx.Gas(),
		To:       tx.To(),
		Data:     tx.Data(),
	}

	if v := tx.Value(); v != nil {
		msg.Value = new(uint256.Int).Set(v)
	} else {
		msg.Value = new(uint256.Int)
	}

	// Set gas price fields.
	msg.GasPrice = new(big.Int)
	msg.GasFeeCap = new(big.Int)
	msg.GasTipCap = new(big.Int)

	if tx.GasPrice() != nil {
		msg.GasPrice.Set(tx.GasPrice())
		msg.GasFeeCap.Set(tx.GasPrice())
		msg.GasTipCap.Set(tx.GasPrice())
	}
	if tx.GasFeeCap() != nil {
		msg.GasFeeCap.Set(tx.GasFeeCap())
	}
	if tx.GasTipCap() != nil {
		msg.GasTipCap.Set(tx.GasTipCap())
	}

	if tx.AccessList() != nil {
		msg.AccessList = tx.AccessList()
	}

	// Set nonce from tx.
	msg.Nonce = tx.Nonce()

	return msg
}
