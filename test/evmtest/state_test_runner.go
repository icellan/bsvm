package evmtest

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// StateTest represents a GeneralStateTest from the ethereum/tests suite.
type StateTest struct {
	Info        json.RawMessage           `json:"_info"`
	Env         EnvJSON                   `json:"env"`
	Pre         map[string]PreAccountJSON `json:"pre"`
	Transaction StTransactionJSON         `json:"transaction"`
	Post        map[string][]PostState    `json:"post"`
	Config      json.RawMessage           `json:"config"`
}

// EnvJSON holds the block environment for a test.
type EnvJSON struct {
	CurrentCoinbase      string `json:"currentCoinbase"`
	CurrentDifficulty    string `json:"currentDifficulty"`
	CurrentGasLimit      string `json:"currentGasLimit"`
	CurrentNumber        string `json:"currentNumber"`
	CurrentTimestamp     string `json:"currentTimestamp"`
	CurrentBaseFee       string `json:"currentBaseFee"`
	CurrentRandom        string `json:"currentRandom"`
	CurrentExcessBlobGas string `json:"currentExcessBlobGas"`
}

// PreAccountJSON holds account state in test JSON.
type PreAccountJSON struct {
	Balance string            `json:"balance"`
	Code    string            `json:"code"`
	Nonce   string            `json:"nonce"`
	Storage map[string]string `json:"storage"`
}

// PostAccountJSON holds expected post-state account data.
type PostAccountJSON struct {
	Balance string            `json:"balance"`
	Code    string            `json:"code"`
	Nonce   string            `json:"nonce"`
	Storage map[string]string `json:"storage"`
}

// StTransactionJSON holds the transaction data for a state test.
type StTransactionJSON struct {
	Data      []string `json:"data"`
	GasLimit  []string `json:"gasLimit"`
	GasPrice  string   `json:"gasPrice"`
	Nonce     string   `json:"nonce"`
	SecretKey string   `json:"secretKey"`
	Sender    string   `json:"sender"`
	To        string   `json:"to"`
	Value     []string `json:"value"`

	MaxFeePerGas         string            `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string            `json:"maxPriorityFeePerGas"`
	AccessLists          []json.RawMessage `json:"accessLists"`

	// EIP-4844 blob transaction fields.
	MaxFeePerBlobGas    string   `json:"maxFeePerBlobGas"`
	BlobVersionedHashes []string `json:"blobVersionedHashes"`
}

// PostState holds expected post-state for a specific fork.
type PostState struct {
	Hash    string `json:"hash"`
	Logs    string `json:"logs"`
	Indexes struct {
		Data  int `json:"data"`
		Gas   int `json:"gas"`
		Value int `json:"value"`
	} `json:"indexes"`
	TxBytes string                     `json:"txbytes"`
	State   map[string]PostAccountJSON `json:"state"`
}

// RunStateTest runs a single general state test for the specified fork.
func RunStateTest(test *StateTest, fork string) []error {
	posts, ok := test.Post[fork]
	if !ok {
		return nil
	}

	var errs []error
	for i, post := range posts {
		if err := runSingleStateTest(test, fork, post, i); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func runSingleStateTest(test *StateTest, fork string, post PostState, index int) error {
	chainConfig := getChainConfigForFork(fork)

	memDB := db.NewMemoryDB()
	sdb, err := state.New(types.EmptyRootHash, memDB)
	if err != nil {
		return fmt.Errorf("post[%d]: failed to create statedb: %w", index, err)
	}

	for addrHex, acct := range test.Pre {
		addr := hexToAddress(addrHex)
		sdb.CreateAccount(addr)

		balance := hexToUint256(acct.Balance)
		sdb.AddBalance(addr, balance, tracing.BalanceChangeUnspecified)

		nonce := hexToUint64(acct.Nonce)
		if nonce > 0 {
			sdb.SetNonce(addr, nonce, tracing.NonceChangeUnspecified)
		}

		code := hexToBytes(acct.Code)
		if len(code) > 0 {
			sdb.SetCode(addr, code, tracing.CodeChangeCreation)
		}

		for keyHex, valHex := range acct.Storage {
			key := hexToHash(keyHex)
			val := hexToHash(valHex)
			sdb.SetState(addr, key, val)
		}
	}

	preRoot, err := sdb.Commit(false)
	if err != nil {
		return fmt.Errorf("post[%d]: failed to commit pre-state: %w", index, err)
	}

	sdb, err = state.New(preRoot, memDB)
	if err != nil {
		return fmt.Errorf("post[%d]: failed to reopen statedb: %w", index, err)
	}

	dataIdx := post.Indexes.Data
	gasIdx := post.Indexes.Gas
	valueIdx := post.Indexes.Value

	txData := getIndexed(test.Transaction.Data, dataIdx)
	txGasLimit := getIndexed(test.Transaction.GasLimit, gasIdx)
	txValue := getIndexed(test.Transaction.Value, valueIdx)

	data := hexToBytes(txData)
	gasLimit := hexToUint64(txGasLimit)
	value := hexToBigInt(txValue)
	valueU256, _ := uint256.FromBig(value)
	if valueU256 == nil {
		valueU256 = new(uint256.Int)
	}

	gasPrice := hexToBigInt(test.Transaction.GasPrice)
	var gasFeeCap, gasTipCap *big.Int
	if test.Transaction.MaxFeePerGas != "" {
		gasFeeCap = hexToBigInt(test.Transaction.MaxFeePerGas)
		gasTipCap = hexToBigInt(test.Transaction.MaxPriorityFeePerGas)
	}
	// For legacy transactions, GasFeeCap and GasTipCap default to GasPrice
	// (matching geth's tx.GasFeeCap() / tx.GasTipCap() behavior).
	if gasFeeCap == nil {
		gasFeeCap = new(big.Int).Set(gasPrice)
	}
	if gasTipCap == nil {
		gasTipCap = new(big.Int).Set(gasPrice)
	}

	// Compute effective gas price (matching geth's toMessage in
	// tests/state_test_util.go). For EIP-1559 transactions, the effective
	// gas price is min(maxPriorityFeePerGas + baseFee, maxFeePerGas).
	baseFee := hexToBigInt(test.Env.CurrentBaseFee)
	if baseFee.Sign() > 0 {
		gasPrice = new(big.Int).Add(gasTipCap, baseFee)
		if gasPrice.Cmp(gasFeeCap) > 0 {
			gasPrice = new(big.Int).Set(gasFeeCap)
		}
	}
	if gasPrice == nil || gasPrice.Sign() == 0 {
		// If gasPrice is still zero and we have a gasFeeCap, use it.
		if gasFeeCap != nil && gasFeeCap.Sign() > 0 {
			gasPrice = new(big.Int).Set(gasFeeCap)
		}
	}

	var sender types.Address
	secretKey := hexToBytes(test.Transaction.SecretKey)
	if len(secretKey) > 0 {
		privKey, err := crypto.ToECDSA(secretKey)
		if err != nil {
			return fmt.Errorf("post[%d]: invalid secret key: %w", index, err)
		}
		sender = types.Address(crypto.PubkeyToAddress(privKey.PublicKey))
	} else if test.Transaction.Sender != "" {
		sender = hexToAddress(test.Transaction.Sender)
	}

	var to *types.Address
	if test.Transaction.To != "" {
		toAddr := hexToAddress(test.Transaction.To)
		to = &toAddr
	}

	nonce := hexToUint64(test.Transaction.Nonce)

	var accessList types.AccessList
	if len(test.Transaction.AccessLists) > 0 {
		alIdx := dataIdx
		if alIdx >= len(test.Transaction.AccessLists) {
			alIdx = len(test.Transaction.AccessLists) - 1
		}
		if alIdx >= 0 && alIdx < len(test.Transaction.AccessLists) {
			raw := test.Transaction.AccessLists[alIdx]
			if len(raw) > 0 && string(raw) != "null" {
				if err := json.Unmarshal(raw, &accessList); err != nil {
					accessList = nil
				}
			}
		}
	}

	// EIP-4844: parse blob transaction fields for EVM context.
	// We don't support blob txs on L2, but the EVM context needs them
	// for ethereum/tests compatibility.
	var txBlobHashes []types.Hash
	for _, h := range test.Transaction.BlobVersionedHashes {
		txBlobHashes = append(txBlobHashes, hexToHash(h))
	}
	var txBlobFeeCap *big.Int
	if test.Transaction.MaxFeePerBlobGas != "" {
		txBlobFeeCap = hexToBigInt(test.Transaction.MaxFeePerBlobGas)
	}

	blockCtx := makeBlockContext(test.Env)
	rules := chainConfig.Rules(blockCtx.BlockNumber, true, blockCtx.Time)

	msg := &block.Message{
		From:             sender,
		To:               to,
		Nonce:            nonce,
		Value:            valueU256,
		GasLimit:         gasLimit,
		GasPrice:         gasPrice,
		GasFeeCap:        gasFeeCap,
		GasTipCap:        gasTipCap,
		Data:             data,
		AccessList:       accessList,
		SkipNonceChecks:  false,
		SkipFromEOACheck: false,
	}

	evmInstance := vm.NewEVM(blockCtx, sdb, chainConfig, vm.Config{})

	// Stash blob context fields. ApplyMessage will call SetTxContext,
	// so we restore blob fields afterwards by setting them directly.
	// We don't support blob txs on L2, but ethereum/tests may set them.
	savedBlobHashes := txBlobHashes
	savedBlobFeeCap := txBlobFeeCap

	gp := new(block.GasPool)
	gp.AddGas(blockCtx.GasLimit)

	// Pre-set the TxContext with blob fields. ApplyMessage will overwrite
	// Origin/GasPrice but we need blob fields for BLOBHASH opcode.
	evmInstance.TxContext = vm.TxContext{
		Origin:     sender,
		GasPrice:   gasPrice,
		BlobHashes: savedBlobHashes,
		BlobFeeCap: savedBlobFeeCap,
	}
	_ = savedBlobHashes
	_ = savedBlobFeeCap

	// Take a snapshot before applying the message. If the message fails
	// validation (e.g., intrinsic gas too low, initcode too large), we
	// revert to the snapshot so no state changes are visible.
	snapshot := sdb.Snapshot()

	_, err = block.ApplyMessage(evmInstance, msg, gp)
	if err != nil {
		sdb.RevertToSnapshot(snapshot)
		stateRoot := sdb.IntermediateRoot(rules.IsEIP158)
		return checkStateRoot(post, stateRoot, index)
	}

	// Add 0-value mining reward. This only makes a difference in the cases
	// where the coinbase self-destructed, or there are only 'bad' transactions.
	// This "touches" the coinbase account which matters for EIP-158 empty
	// account cleanup. Matches geth's tests/state_test_util.go.
	sdb.AddBalance(blockCtx.Coinbase, new(uint256.Int), tracing.BalanceChangeUnspecified)

	stateRoot := sdb.IntermediateRoot(rules.IsEIP158)
	return checkStateRoot(post, stateRoot, index)
}

func checkStateRoot(post PostState, computed types.Hash, index int) error {
	expected := hexToHash(post.Hash)
	if computed != expected {
		return fmt.Errorf("post[%d]: state root mismatch: got %s, want %s",
			index, computed.Hex(), expected.Hex())
	}
	return nil
}

func getIndexed(s []string, i int) string {
	if len(s) == 0 {
		return ""
	}
	if i >= len(s) {
		return s[len(s)-1]
	}
	if i < 0 {
		return s[0]
	}
	return s[i]
}
