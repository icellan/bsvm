# Spec 16: Developer Devnet — One-Command Local BSVM

## Goal

A developer runs one command and gets a fully functional multi-node BSVM shard running locally, connected to BSV regtest, with pre-funded accounts and the explorer UI. They can immediately deploy Solidity contracts using Hardhat, Foundry, or Remix — and observe multi-node gossip, sync, and competitive proving behaviour.

The devnet runs the **production code path** — the same EVM execution, batch encoding, public values layout, state root computation, covenant state management, gossip protocol, and sync logic as a mainnet shard. The only configurable difference is how the STARK proof is generated and verified, with three modes from fastest-to-most-realistic.

```bash
docker compose up
```

30 seconds later:
- BSV regtest node running (auto-mining every 10 seconds)
- **3 BSVM overlay nodes** running (ports 8545, 8546, 8547)
- Explorer UI on each node (http://localhost:8545, :8546, :8547)
- All nodes in the same shard, gossiping transactions and racing to advance the covenant
- Pre-initialized shard with chain ID 31337 (Hardhat default)
- 10 pre-funded accounts with 1000 wBSV each (Hardhat default keys)
- Governance mode: `single_key` (developer has full control)

---

## Proving Modes

The devnet supports three proving modes, each running more of the production code path:

### Mode 1: `mock` (default)

**What runs like production:**
- Go EVM executes transactions identically to production
- Batch data is encoded in the canonical format (spec 11, byte-level)
- SP1 guest program runs in SP1's mock/execute mode (no cryptographic proof, but the guest program executes on the inputs and produces real public values)
- Public values are committed: pre-state root, post-state root, receipts hash, gas used, batch data hash, chain ID, withdrawal root — all computed correctly
- The overlay node builds the BSV covenant-advance transaction with the batch data in OP_RETURN
- Covenant state management (state root, block number, frozen flag) is production logic
- Gossip, sync, competitive proving, speculative receipts — all production

**What is simplified:**
- The covenant's FRI verification step is replaced by a dev key signature check
- The proof bytes in the unlocking script are a signature instead of a STARK proof

**Why this is still valuable:**
- Catches bugs in batch encoding (Go/Rust disagreement → hash mismatch)
- Catches bugs in public values layout (wrong offset → covenant rejects)
- Catches bugs in state root computation (EVM execution error → state divergence between nodes)
- Catches bugs in covenant state management (block number, frozen flag, etc.)
- Catches bugs in gossip, sync, and competitive proving
- Tests the full BSV transaction chain (covenant UTXO chaining on regtest)
- Sub-second "proving" — no GPU, no waiting

**What it does NOT catch:**
- Bugs in the Rúnar FRI verifier Script
- Proof serialisation format mismatches between SP1 and the covenant

**Startup time:** ~30 seconds. **Proving time:** < 100ms.

### Mode 2: `execute` 

**What additionally runs:**
- The SP1 guest program runs in SP1's execute mode with full RISC-V emulation (not just mock). This actually executes revm inside the SP1 runtime, verifying that the Rust EVM produces identical state roots to the Go EVM.
- The dual-EVM consistency check is fully exercised.

**What is still simplified:**
- No cryptographic proof is generated (execute mode verifies correctness but doesn't produce a STARK)
- The covenant still uses dev key signature verification

**Why this matters:**
- This is the first mode that exercises the **dual-EVM architecture**. If the Go EVM and Rust revm disagree on any opcode, gas computation, or state access, this mode catches it.
- Much slower than mock (~1-5 seconds per batch on CPU) but no GPU needed.

**Startup time:** ~30 seconds. **Proving time:** 1-5 seconds per batch (CPU).

### Mode 3: `prove`

**Full production code path. Nothing is simplified.**

- SP1 generates a real STARK proof
- The covenant is the production covenant with full FRI verification in Rúnar-compiled Bitcoin Script
- The proof is verified on BSV regtest identically to how it would be on mainnet

**Requirements:**
- SP1 toolchain installed
- GPU recommended (CPU works but ~60 seconds per batch)
- Significantly slower block production

**When to use:**
- Final integration testing before deploying a shard
- Testing the Rúnar FRI verifier against real proofs
- Measuring proof sizes and verification times
- Gate 0 validation

**Startup time:** ~1 minute. **Proving time:** 5-60 seconds per batch.

### Mode comparison

| Aspect | `mock` | `execute` | `prove` |
|---|---|---|---|
| Go EVM execution | ✅ Production | ✅ Production | ✅ Production |
| Batch encoding | ✅ Production | ✅ Production | ✅ Production |
| Public values layout | ✅ Production | ✅ Production | ✅ Production |
| Covenant state mgmt | ✅ Production | ✅ Production | ✅ Production |
| Gossip / sync | ✅ Production | ✅ Production | ✅ Production |
| Competitive proving | ✅ Production | ✅ Production | ✅ Production |
| Speculative receipts | ✅ Production | ✅ Production | ✅ Production |
| BSV UTXO chaining | ✅ Production | ✅ Production | ✅ Production |
| SP1 guest (revm) | Mock (values only) | ✅ Full execute | ✅ Full prove |
| Dual-EVM check | ❌ | ✅ | ✅ |
| STARK proof | ❌ Signature | ❌ Signature | ✅ Real STARK |
| FRI verification | ❌ Signature | ❌ Signature | ✅ Rúnar Script |
| GPU required | No | No | Recommended |
| Proving time | < 100ms | 1-5s | 5-60s |
| Good for | Solidity dev, UI dev | Integration testing | Pre-deployment, Gate 0 |

---

## Architecture

```
docker compose up
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Docker Compose Network: bsvm-devnet                              │
│                                                                   │
│  ┌──────────────┐                                                │
│  │  bsv-regtest │  BSV regtest node (port 18332)                 │
│  │  + auto-mine │  Mines a block every 10 seconds                │
│  └──────┬───────┘                                                │
│         │                                                        │
│    ┌────┼──────────────────────┬──────────────────────┐          │
│    │    │                      │                      │          │
│    ▼    ▼                      ▼                      ▼          │
│  ┌────────────┐  gossip  ┌────────────┐  gossip  ┌────────────┐ │
│  │  Node 1    │◄────────►│  Node 2    │◄────────►│  Node 3    │ │
│  │  :8545     │          │  :8546     │          │  :8547     │ │
│  │  Prover    │          │  Prover    │          │  Follower  │ │
│  │  Explorer  │          │  Explorer  │          │  Explorer  │ │
│  └────────────┘          └────────────┘          └────────────┘ │
│         ▲                       ▲                       ▲        │
└─────────┼───────────────────────┼───────────────────────┼────────┘
     Port 8545               Port 8546               Port 8547
```

### Node roles

| Node | Port | Role | Purpose |
|---|---|---|---|
| Node 1 | 8545 | Prover (primary) | Default RPC endpoint. Builds batches and advances the covenant. |
| Node 2 | 8546 | Prover (competing) | Competes with Node 1. Tests race dynamics and speculative receipt invalidation. |
| Node 3 | 8547 | Follower (read-only) | Does not prove. Syncs from BSV, serves RPC. Tests sync protocol. |

---

## Covenant Design

The devnet covenant is parameterised by proving mode at shard genesis.

### `mock` and `execute` modes

The covenant uses the **production contract structure** — same state fields (`stateRoot`, `blockNumber`, `frozen`), same governance methods (`freeze`, `unfreeze`, `upgrade`), same state continuity checks, same batch data binding via OP_RETURN and `hashOutputs`. The only difference is how the `advanceState` method authorises the advance:

```go
func RollupContract(mode string, sp1VK []byte, devKey []byte, chainID uint64, gov GovernanceConfig) *runar.Contract {
    c := runar.NewStatefulContract("Rollup")

    c.State("stateRoot",   runar.Bytes32)
    c.State("blockNumber", runar.Uint64)
    c.State("frozen",      runar.Uint8)

    c.Prop("chainID", runar.Uint64, chainID)

    c.Method("advanceState", func(m *runar.MethodBuilder) {
        // Frozen check — production logic
        m.Require(
            m.Equal(c.GetState("frozen"), runar.Uint8Literal(0)),
            "shard is frozen",
        )

        batchData    := m.Param("batchData", runar.VarBytes)
        newStateRoot := m.Param("newStateRoot", runar.Bytes32)
        newBlockNum  := m.Param("newBlockNumber", runar.Uint64)
        publicValues := m.Param("publicValues", runar.VarBytes)

        // --- Public values extraction — PRODUCTION LOGIC ---
        // Extract and verify public values regardless of proving mode.
        // This tests the entire public values layout.
        preStateRoot  := m.ExtractBytes32(publicValues, 0)
        postStateRoot := m.ExtractBytes32(publicValues, 32)
        batchDataHash := m.ExtractBytes32(publicValues, 104)
        committedChainID := m.ExtractUint64(publicValues, 136)

        // State continuity — PRODUCTION LOGIC
        m.Require(
            m.Equal(preStateRoot, c.GetState("stateRoot")),
            "pre-state root mismatch",
        )

        // Block number increment — PRODUCTION LOGIC
        m.Require(
            m.Equal(newBlockNum, m.Add(c.GetState("blockNumber"), runar.Uint64Literal(1))),
            "block number must increment by 1",
        )

        // Chain ID — PRODUCTION LOGIC
        m.Require(
            m.Equal(committedChainID, c.Prop("chainID")),
            "chain ID mismatch",
        )

        // Batch data hash binding — PRODUCTION LOGIC
        m.Require(
            m.Equal(m.Hash256(batchData), batchDataHash),
            "batch data does not match proof",
        )

        // hashOutputs verification — PRODUCTION LOGIC
        sighashPreimage := m.Param("sighashPreimage", runar.VarBytes)
        hashOutputs := m.ExtractBytes32(sighashPreimage, /* hashOutputsOffset */)
        expectedHashOutputs := m.SHA256d(m.Cat(
            m.SerialiseOutput(0, /* covenant script */, /* sats */),
            m.SerialiseOutput(1, m.OpReturn(batchData), 0),
            m.SerialiseOutput(2, /* prover change */, /* sats */),
        ))
        m.Require(
            m.Equal(hashOutputs, expectedHashOutputs),
            "batch data not bound to outputs",
        )

        // --- Proof authorisation — MODE-DEPENDENT ---
        switch mode {
        case "mock", "execute":
            // Dev mode: signature check instead of FRI verification
            sig := m.Param("sig", runar.Sig)
            c.Prop("devKey", runar.PubKey, devKey)
            m.RequireCheckSig(sig, c.Prop("devKey"))

        case "prove":
            // Production: full STARK FRI verification
            proof := m.Param("sp1Proof", runar.VarBytes)
            c.Prop("sp1VK", runar.VarBytes, sp1VK)
            m.RequireFRIVerification(proof, publicValues, c.Prop("sp1VK"))
        }

        // Update state — PRODUCTION LOGIC
        c.SetState("stateRoot", postStateRoot)
        c.SetState("blockNumber", newBlockNum)
        c.SetState("frozen", runar.Uint8Literal(0))
        m.RequireStateOutput()
    })

    // Governance methods — IDENTICAL to production in all modes
    // freeze(), unfreeze(), upgrade() — same as spec 12
    // ...

    return c.Build()
}
```

The key insight: **90% of the covenant logic runs identically in all modes.** State continuity, block number increment, chain ID check, batch data hash binding, hashOutputs verification, governance — all production. Only the 10-line FRI verification call is swapped for a signature check in mock/execute mode.

### `prove` mode

The full production covenant. Identical to what runs on mainnet. No dev key, no shortcuts.

---

## Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

x-bsvm-common: &bsvm-common
  image: bsvm/devnet:latest
  environment: &bsvm-env
    BSVM_PROVE_MODE: mock
    BSVM_CHAIN_ID: "31337"
    BSVM_BSV_RPC: "http://devuser:devpass@bsv-regtest:18332"
    BSVM_EXPLORER: "true"
    BSVM_LOG_LEVEL: info
    BSVM_GENESIS_DIR: /shared/genesis
    BSVM_BATCH_SIZE: "16"
    BSVM_FLUSH_DELAY: "1s"
    BSVM_DEPOSIT_CONFIRMATIONS: "1"
  depends_on:
    bsvm-init:
      condition: service_completed_successfully

services:

  # ─── BSV Regtest Node ────────────────────────────────────────
  bsv-regtest:
    image: bitcoinsv/bitcoin-sv:latest
    command: >
      bitcoind
        -regtest
        -server
        -rpcuser=devuser
        -rpcpassword=devpass
        -rpcallowip=0.0.0.0/0
        -rpcbind=0.0.0.0
        -port=18444
        -rpcport=18332
        -txindex=1
        -excessiveblocksize=4000000000
        -maxstackmemoryusageconsensus=0
    ports:
      - "18332:18332"
    volumes:
      - bsv-data:/root/.bitcoin
    healthcheck:
      test: >
        bitcoin-cli -regtest -rpcuser=devuser -rpcpassword=devpass
        getblockchaininfo
      interval: 3s
      timeout: 2s
      retries: 20

  # ─── Auto-miner (mines a block every 10s) ─────────────────────
  bsv-miner:
    image: bitcoinsv/bitcoin-sv:latest
    depends_on:
      bsv-regtest:
        condition: service_healthy
    entrypoint: /bin/sh
    command: >
      -c '
        ADDR=$$(bitcoin-cli -regtest -rpcconnect=bsv-regtest
          -rpcuser=devuser -rpcpassword=devpass getnewaddress)
        echo "Mining to $$ADDR"
        while true; do
          bitcoin-cli -regtest -rpcconnect=bsv-regtest
            -rpcuser=devuser -rpcpassword=devpass
            generatetoaddress 1 $$ADDR > /dev/null 2>&1
          sleep 10
        done
      '

  # ─── One-time initializer ─────────────────────────────────────
  bsvm-init:
    image: bsvm/devnet:latest
    depends_on:
      bsv-regtest:
        condition: service_healthy
    environment:
      BSVM_PROVE_MODE: mock
      BSVM_CHAIN_ID: "31337"
      BSVM_BSV_RPC: "http://devuser:devpass@bsv-regtest:18332"
    entrypoint: /bin/sh
    command: >
      -c '
        echo "==> Mining 150 blocks for mature coinbase..."
        bsv-evm dev mine --blocks 150

        echo "==> Initializing shard..."
        bsv-evm init \
          --chain-id 31337 \
          --prove-mode mock \
          --governance single_key \
          --gas-price 1 \
          --prefund-accounts hardhat \
          --output /shared/genesis

        echo "==> Genesis written to /shared/genesis"
        cat /shared/genesis/shard.toml
      '
    volumes:
      - shared-genesis:/shared/genesis

  # ─── Node 1: Prover (primary) ─────────────────────────────────
  node1:
    <<: *bsvm-common
    environment:
      <<: *bsvm-env
      BSVM_NODE_NAME: node1
      BSVM_RPC_PORT: "8545"
      BSVM_P2P_PORT: "9945"
      BSVM_ROLE: prover
      BSVM_COINBASE: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
      BSVM_PEERS: "node2:9945,node3:9945"
    ports:
      - "8545:8545"
      - "9945:9945"
    volumes:
      - shared-genesis:/shared/genesis:ro
      - node1-data:/data/bsvm

  # ─── Node 2: Prover (competing) ───────────────────────────────
  node2:
    <<: *bsvm-common
    environment:
      <<: *bsvm-env
      BSVM_NODE_NAME: node2
      BSVM_RPC_PORT: "8545"
      BSVM_P2P_PORT: "9945"
      BSVM_ROLE: prover
      BSVM_COINBASE: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
      BSVM_PEERS: "node1:9945,node3:9945"
    ports:
      - "8546:8545"
      - "9946:9945"
    volumes:
      - shared-genesis:/shared/genesis:ro
      - node2-data:/data/bsvm

  # ─── Node 3: Follower (read-only) ─────────────────────────────
  node3:
    <<: *bsvm-common
    environment:
      <<: *bsvm-env
      BSVM_NODE_NAME: node3
      BSVM_RPC_PORT: "8545"
      BSVM_P2P_PORT: "9945"
      BSVM_ROLE: follower
      BSVM_PEERS: "node1:9945,node2:9945"
    ports:
      - "8547:8545"
      - "9947:9945"
    volumes:
      - shared-genesis:/shared/genesis:ro
      - node3-data:/data/bsvm

volumes:
  bsv-data:
  shared-genesis:
  node1-data:
  node2-data:
  node3-data:
```

### Switching proving modes

```bash
# Default: mock mode (fast, no GPU)
docker compose up

# Execute mode: dual-EVM consistency testing
BSVM_PROVE_MODE=execute docker compose up

# Full proving: real STARK proofs (requires GPU)
docker compose -f docker-compose.yml -f docker-compose.proving.yml up
```

`docker-compose.proving.yml` override:

```yaml
services:
  node1:
    environment:
      BSVM_PROVE_MODE: prove
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
  node2:
    environment:
      BSVM_PROVE_MODE: prove
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

---

## Pre-funded Accounts

The devnet pre-funds 10 accounts with deterministic private keys, identical to Hardhat's default accounts.

```
Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (Node 1 coinbase)
  Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  Balance: 1000 wBSV

Account #1: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (Node 2 coinbase)
  Private Key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  Balance: 1000 wBSV

Account #2: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
  Private Key: 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
  Balance: 1000 wBSV

Account #3: 0x90F79bf6EB2c4f870365E785982E1f101E93b906
  Private Key: 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
  Balance: 1000 wBSV

Account #4: 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
  Private Key: 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
  Balance: 1000 wBSV

Accounts #5 through #9: (standard Hardhat keys, 1000 wBSV each)
```

---

## Startup Sequence

### Phase 1: BSV Regtest (~5 seconds)

```
bsv-regtest starts → bitcoind -regtest
health check passes
bsv-miner starts mining every 10s
```

### Phase 2: Initialisation (~10 seconds)

```
bsvm-init:
  1. Mine 150 blocks (mature coinbase)
  2. Generate deterministic dev key
  3. Fund dev wallet from coinbase
  4. Compile covenant via Rúnar (mode-appropriate)
  5. bsv-evm init:
     - Create genesis.json with pre-funded accounts
     - Initialise StateDB with genesis state
     - Compute genesis state root
     - Broadcast genesis covenant UTXO to regtest
     - Broadcast bridge covenant UTXO
     - Write shard.toml to /shared/genesis
  6. Exit
```

### Phase 3: Nodes Start (~5-10 seconds)

```
node1, node2, node3 start in parallel:
  1. Read /shared/genesis/shard.toml
  2. Load genesis state
  3. Connect to BSV regtest
  4. Connect to peers
  5. Sync from covenant chain (instant — genesis only)
  6. Start RPC + explorer
  7. node1, node2: enter prover mode
  8. node3: enter follower mode
```

### Phase 4: Ready

```
======================================================
  BSVM Devnet is running!

  Prove mode:  mock (switch with BSVM_PROVE_MODE=execute|prove)

  Node 1 (prover):   http://localhost:8545
  Node 2 (prover):   http://localhost:8546
  Node 3 (follower): http://localhost:8547

  Chain ID:    31337
  Gas Price:   1 gwei
  Block Gas:   30,000,000

  Explorer:    http://localhost:8545
  Admin:       http://localhost:8545/admin

  Pre-funded accounts (1000 wBSV each):
    #0  0xf39F...2266  (Node 1 coinbase)
    #1  0x7099...79C8  (Node 2 coinbase)
    #2  0x3C44...93BC
    ...

  MetaMask: Add network → RPC URL: http://localhost:8545
                           Chain ID: 31337
                           Symbol: wBSV

  Hardhat:  networks: { bsvm: { url: "http://localhost:8545" } }
  Foundry:  forge script --rpc-url http://localhost:8545
======================================================
```

---

## Developer Workflows

### Basic: Deploy and interact

```bash
# Terminal 1
docker compose up

# Terminal 2
cd my-solidity-project
npx hardhat run scripts/deploy.js --network bsvm

# Browser
open http://localhost:8545
```

### Multi-node: Observe gossip

```bash
# Submit tx to Node 1
cast send --rpc-url http://localhost:8545 --private-key 0xac09... \
  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC --value 1ether

# Verify it arrived at Node 2 and Node 3 via gossip
cast receipt --rpc-url http://localhost:8546 <tx-hash>
cast receipt --rpc-url http://localhost:8547 <tx-hash>
```

### Resilience: Kill and recover

```bash
# Kill Node 1
docker compose stop node1

# Node 2 takes over proving. Submit tx to Node 2:
cast send --rpc-url http://localhost:8546 ...

# Node 3 (follower) syncs from Node 2's covenant advances

# Restart Node 1 — it syncs from BSV covenant chain
docker compose start node1
```

### Race dynamics: Competing provers

```bash
# Send different txs to different nodes simultaneously
cast send --rpc-url http://localhost:8545 ... &
cast send --rpc-url http://localhost:8546 ... &
wait

# Check each explorer to see which node won the batch race
# http://localhost:8545 vs http://localhost:8546
# After race resolves, all nodes converge to the same state
```

### Dual-EVM testing (execute mode)

```bash
# Start with execute mode to test Go EVM vs Rust revm consistency
BSVM_PROVE_MODE=execute docker compose up

# Deploy a complex contract and exercise edge cases
npx hardhat test --network bsvm

# If Go EVM and Rust revm disagree, the node logs an error:
#   "CRITICAL: dual-EVM state root mismatch at block N"
```

### Full proving (prove mode)

```bash
# Start with real STARK proofs (needs GPU)
docker compose -f docker-compose.yml -f docker-compose.proving.yml up

# Everything is production-equivalent
# Proving takes 5-60 seconds per batch
# BSV covenant verifies real FRI proofs on regtest
```

### Governance: Freeze / unfreeze

```bash
# Open admin UI
open http://localhost:8545/admin

# Authenticate with BRC-100 wallet (or dev bypass header)
# Click "Freeze Shard" → all 3 nodes stop processing
# Click "Unfreeze" → all 3 nodes resume

# Or via CLI:
bsv-evm admin freeze --rpc http://localhost:8545
bsv-evm admin unfreeze --rpc http://localhost:8545
```

---

## Dev Mode Authentication Bypass

For the admin panel, BRC-100 wallet authentication can be bypassed with a dev header:

```
POST /admin/rpc
x-bsvm-dev-auth: devnet-secret-do-not-use-in-production
```

Only accepted when `BSVM_PROVE_MODE` is `mock` or `execute`. In `prove` mode, full BRC-100 authentication is required. The explorer shows a banner: "⚠️ Dev Mode — admin authentication bypassed."

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BSVM_PROVE_MODE` | `mock` | `mock`, `execute`, or `prove` |
| `BSVM_CHAIN_ID` | `31337` | L2 chain ID |
| `BSVM_BSV_RPC` | (required) | BSV RPC endpoint URL |
| `BSVM_RPC_PORT` | `8545` | HTTP RPC port |
| `BSVM_P2P_PORT` | `9945` | Peer-to-peer gossip port |
| `BSVM_ROLE` | `prover` | `prover` or `follower` |
| `BSVM_COINBASE` | (none) | L2 address for coinbase fees (provers only) |
| `BSVM_PEERS` | (none) | Comma-separated peer addresses |
| `BSVM_EXPLORER` | `true` | Serve the explorer UI |
| `BSVM_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `BSVM_NODE_NAME` | `node` | Human-readable node name |
| `BSVM_GENESIS_DIR` | `/data/genesis` | Shared genesis config path |
| `BSVM_BATCH_SIZE` | `16` | Target batch size (small for fast dev blocks) |
| `BSVM_FLUSH_DELAY` | `1s` | Batch flush timeout |
| `BSVM_GAS_PRICE` | `1` | Minimum gas price in gwei |
| `BSVM_DEPOSIT_CONFIRMATIONS` | `1` | BSV confirmations for deposits (1 in dev, 6 in prod) |

---

## NPM Convenience Wrapper

```bash
npx create-bsvm-devnet            # start devnet
npx create-bsvm-devnet stop       # stop
npx create-bsvm-devnet reset      # stop + clear all data
npx create-bsvm-devnet logs       # tail logs
npx create-bsvm-devnet status     # show node status
```

---

## Hardhat Plugin

```bash
npm install --save-dev hardhat-bsvm
```

```javascript
// hardhat.config.js
require("hardhat-bsvm");

module.exports = {
  networks: {
    bsvm:       { url: "http://localhost:8545", chainId: 31337 },
    bsvm_node2: { url: "http://localhost:8546", chainId: 31337 },
    bsvm_node3: { url: "http://localhost:8547", chainId: 31337 },
  },
};
```

Tasks:

```bash
npx hardhat bsvm:status          # devnet status
npx hardhat bsvm:accounts        # pre-funded accounts
npx hardhat bsvm:bridge-deposit  # simulate BSV deposit
npx hardhat bsvm:bridge-status   # bridge TVL
npx hardhat bsvm:freeze          # freeze shard
npx hardhat bsvm:unfreeze        # unfreeze
npx hardhat bsvm:nodes           # all nodes and status
```

---

## CI/CD Integration

```yaml
# GitHub Actions
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start BSVM devnet
        run: |
          docker compose up -d
          timeout 60 bash -c 'until curl -s http://localhost:8545/rpc \
            -X POST -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}" | \
            grep "0x7a69"; do sleep 2; done'
      - name: Run tests
        run: npx hardhat test --network bsvm
      - name: Run dual-EVM consistency check
        run: BSVM_PROVE_MODE=execute npx hardhat test --network bsvm
      - name: Stop devnet
        run: docker compose down -v
```

---

## Milestone

- **Milestone 5 (Single Node):** Basic devnet with 1 node, mock mode
- **Milestone 7 (Multi-Node):** Full 3-node cluster with gossip and competition
- **Post-Milestone 4 (Covenant):** `prove` mode with real STARK verification

## Deliverables

- [ ] `docker-compose.yml` — 3-node devnet with BSV regtest
- [ ] `docker-compose.proving.yml` — GPU override for prove mode
- [ ] Mode-parameterised covenant contract in Rúnar (mock/execute use dev key for STARK step only, all other checks production)
- [ ] SP1 guest program integration for `execute` and `prove` modes
- [ ] `bsv-evm init --prove-mode mock|execute|prove --prefund-accounts hardhat`
- [ ] `bsv-evm dev mine --blocks N` (mine regtest blocks)
- [ ] `bsv-evm admin freeze|unfreeze` CLI commands
- [ ] `Dockerfile` for devnet image
- [ ] Startup banner with connection info
- [ ] `npx create-bsvm-devnet` NPM wrapper
- [ ] `hardhat-bsvm` plugin
- [ ] CI/CD example (GitHub Actions)
- [ ] README quickstart for Hardhat, Foundry, MetaMask, and Remix
