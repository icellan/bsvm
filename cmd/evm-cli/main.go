// Package main implements the evm-cli binary, a command-line tool for
// debugging EVM operations. It provides subcommands to execute bytecode,
// disassemble instructions, and compute keccak256 hashes.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		if err := runEVM(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "disasm":
		if err := disassemble(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "hash":
		if err := hashInput(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("evm-cli v0.1.0 (bsvm)")
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: evm-cli <command> [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  run <hex>     Execute EVM bytecode and print result")
	fmt.Fprintln(os.Stderr, "  disasm <hex>  Disassemble EVM bytecode")
	fmt.Fprintln(os.Stderr, "  hash <hex>    Compute keccak256 hash")
	fmt.Fprintln(os.Stderr, "  version       Print version")
}

// readHexInput reads hex-encoded input from the command-line argument or stdin.
func readHexInput(args []string) ([]byte, error) {
	var hexStr string
	if len(args) > 2 {
		hexStr = args[2]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		hexStr = strings.TrimSpace(string(data))
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	if hexStr == "" {
		return []byte{}, nil
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex input: %w", err)
	}
	return b, nil
}

// runEVM executes EVM bytecode and prints the return data and gas used.
func runEVM() error {
	code, err := readHexInput(os.Args)
	if err != nil {
		return err
	}

	statedb := state.NewMemoryStateDB()
	sender := types.HexToAddress("0x1000000000000000000000000000000000000001")
	contractAddr := types.HexToAddress("0x2000000000000000000000000000000000000002")

	// Give the sender some balance for gas.
	senderBalance := new(uint256.Int).Mul(
		uint256.NewInt(1_000_000_000),
		uint256.NewInt(1_000_000_000),
	)
	statedb.AddBalance(sender, senderBalance, 0)

	// Deploy the code to the contract address.
	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, code, 0)

	chainCfg := vm.DefaultL2Config(1)
	blockCtx := vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			return types.Hash{}
		},
		Coinbase:    types.Address{},
		GasLimit:    30_000_000,
		BlockNumber: big.NewInt(1),
		Time:        1,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(0),
	}

	txCtx := vm.TxContext{
		Origin:   sender,
		GasPrice: big.NewInt(0),
	}

	evm := vm.NewEVM(blockCtx, statedb, chainCfg, vm.Config{})
	evm.TxContext = txCtx

	// Prepare access list for the transaction.
	rules := chainCfg.Rules(blockCtx.BlockNumber, false, blockCtx.Time)
	statedb.Prepare(rules, sender, types.Address{}, &contractAddr, nil, nil)

	gas := uint64(10_000_000)
	ret, leftOverGas, err := evm.Call(sender, contractAddr, nil, gas, uint256.NewInt(0))

	gasUsed := gas - leftOverGas
	fmt.Printf("Return:   0x%s\n", hex.EncodeToString(ret))
	fmt.Printf("Gas used: %d\n", gasUsed)
	if err != nil {
		fmt.Printf("Error:    %v\n", err)
	}
	return nil
}

// disassemble decodes EVM bytecode into human-readable opcode mnemonics.
func disassemble() error {
	code, err := readHexInput(os.Args)
	if err != nil {
		return err
	}
	fmt.Print(disasmToString(code))
	return nil
}

// disasmToString returns the disassembly of bytecode as a string.
func disasmToString(code []byte) string {
	var sb strings.Builder
	for pc := 0; pc < len(code); {
		op := vm.OpCode(code[pc])
		if op.IsPush() {
			// PUSH1 through PUSH32: the number of immediate bytes
			// equals (opcode - PUSH0).
			n := int(op) - int(vm.PUSH0)
			if pc+1+n > len(code) {
				n = len(code) - pc - 1
			}
			imm := code[pc+1 : pc+1+n]
			fmt.Fprintf(&sb, "%04x: %s 0x%s\n", pc, op.String(), hex.EncodeToString(imm))
			pc += 1 + n
		} else {
			fmt.Fprintf(&sb, "%04x: %s\n", pc, op.String())
			pc++
		}
	}
	return sb.String()
}

// hashInput computes the keccak256 hash of hex-encoded input.
func hashInput() error {
	data, err := readHexInput(os.Args)
	if err != nil {
		return err
	}
	hash := crypto.Keccak256(data)
	fmt.Printf("0x%s\n", hex.EncodeToString(hash))
	return nil
}
