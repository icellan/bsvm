# hardhat-bsvm

Hardhat plugin for [BSVM](../../README.md) — an Ethereum-compatible L2
on BSV. Adds a `bsvm` network type, a `hre.bsvm` helper namespace
wrapping the `bsv_*` JSON-RPC methods, and tasks for proving status,
bridge deposits/withdrawals, and the prover fee wallet.

## Install

```bash
npm install --save-dev hardhat-bsvm ethers hardhat
```

The plugin targets Hardhat `^2.22.0` and ethers `^6.13.0` (peer
dependencies).

## Configure

```js
// hardhat.config.js
require("hardhat-bsvm");

module.exports = {
  solidity: "0.8.24",
  bsvm: {
    devnet: {
      url: "http://localhost:8545",
      chainId: 31337,
      proveMode: "mock", // "mock" | "execute" | "prove"
    },
    devnet_node2: {
      url: "http://localhost:8546",
      chainId: 31337,
      proveMode: "mock",
    },
  },
};
```

For each entry under `bsvm`, the plugin also registers a sibling
Hardhat HTTP network of the same name, so `--network devnet` works with
ethers, `cast`, and any other Hardhat-native tooling.

## Helpers

```ts
const status = await hre.bsvm.provingStatus();
const deposits = await hre.bsvm.bridgeDeposits(/* fromBlock */ 0);
const withdrawals = await hre.bsvm.bridgeWithdrawals(/* fromNonce */ 0);
const fee = await hre.bsvm.feeWalletBalance();
const bridge = await hre.bsvm.bridgeStatus();

// Escape hatch for any other bsv_* method:
const tip = await hre.bsvm.call("bsv_getCovenantTip");
```

## Tasks

```bash
npx hardhat bsvm:status                       # proving status JSON
npx hardhat bsvm:deposits 0xf39F...2266       # bridge deposits for address
npx hardhat bsvm:withdrawals 1A1zP1eP...      # withdrawals for BSV address
npx hardhat bsvm:fee-wallet                   # prover fee wallet balance
```

All tasks honour `--network <name>`, so you can target a specific node
in a multi-node devnet:

```bash
npx hardhat --network devnet_node2 bsvm:status
```

## Build

```bash
npm install
npm run build
```

Output is written to `dist/`.
