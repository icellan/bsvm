# create-bsvm-devnet

`npx`-friendly scaffolder for a local [BSVM](../../README.md) developer
devnet. Generates a project directory with `docker-compose.yml`, a
sample Solidity contract, a Hardhat config wired to the
[`hardhat-bsvm`](../hardhat-bsvm/) plugin, and convenience npm scripts.

## Quickstart

```bash
npx create-bsvm-devnet my-shard
cd my-shard
npm install
npm run up
```

The CLI prompts for chain ID (default 9001), proving mode
(`mock` / `execute` / `prove`), and node count (1 or 3).

Pass `--yes` (or `-y`) to skip the prompts and use defaults
(`chainId=9001`, `proveMode=mock`, 3 nodes).

## What gets generated

```
my-shard/
├── .env.example
├── .gitignore
├── README.md
├── bsvm.json
├── contracts/
│   └── Hello.sol
├── docker-compose.yml
├── hardhat.config.ts
├── package.json
└── scripts/
    └── deploy.ts
```

The generated `package.json` depends on `hardhat-bsvm@^0.1.0`, so the
two tools work together out of the box.

## Build

```bash
npm install
npm run build
```

Compiles `src/index.ts` to `dist/`. The `bin/create-bsvm-devnet.js`
shim defers to the compiled output.
