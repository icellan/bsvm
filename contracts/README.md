# Simulator contract sources

Solidity sources for the contract library driven by `bsvm-sim`. The compiled bytecode is checked in under `pkg/sim/contracts/bytecode.go` — **regenerate after editing these files** and paste the `.bin` output into the Go constants.

## Pinned compiler

- **solc 0.8.28**
- **optimizer: on, runs 200**
- EVM target: `paris` (implicit default)

## Regenerate bytecode

```bash
# Uses npx to avoid a system-wide solc install. No-op if already cached.
npx --yes solc@0.8.28 --bin --optimize --optimize-runs 200 \
    contracts/src/*.sol -o /tmp/bsvm-sim-bin
```

Then copy the runtime `.bin` payloads from `/tmp/bsvm-sim-bin/*.bin` into the matching `var <Name>Bytecode = "…"` constants in `pkg/sim/contracts/bytecode.go`. Each constant is the **creation** (deploy) bytecode — solc emits that as `<File>_sol_<Name>.bin`.

## Contracts

| File | Go constant | Role |
|------|-------------|------|
| `MinimalERC20.sol` | `ERC20Bytecode` | Fungible token workload |
| `MinimalERC721.sol` | `ERC721Bytecode` | NFT workload |
| `MinimalWETH.sol` | `WETHBytecode` | Wrap/unwrap workload |
| `SimpleAMM.sol` | `AMMBytecode` | Uniswap V2-style swap workload |
| `MinimalMultisig.sol` | `MultisigBytecode` | M-of-N coordination workload |
| `Storage.sol` | `StorageBytecode` | Plain state-churn workload |
