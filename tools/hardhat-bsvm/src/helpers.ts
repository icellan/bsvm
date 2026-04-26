// helpers.ts — thin wrappers around the bsv_* JSON-RPC namespace
// exposed by the BSVM RPC server (pkg/rpc/bsv_api.go and bsv_api_ext.go).
// Returned values are deliberately untyped JSON (Record<string, any>)
// because the on-the-wire shape is defined in Go and may evolve. Callers
// can narrow as needed.

import type { HardhatRuntimeEnvironment } from "hardhat/types";

export interface BridgeDeposit {
  bsvTxId: string;
  vout: string;
  bsvBlockHeight: string;
  l2Address: string;
  satoshiAmount: string;
  l2WeiAmount: string;
  confirmed: boolean;
}

export interface BridgeWithdrawal {
  nonce: string;
  amountWei: string;
  bsvAddress: string;
  l2TxHash: string;
  claimed: boolean;
  claimBsvTxid: string;
  csvRemaining: string;
}

export interface ProvingStatus {
  mode: string;
  workers: string;
  inFlight: string;
  queueDepth: string;
  proofsStarted: string;
  proofsSucceeded: string;
  proofsFailed: string;
  averageTimeMs: string;
  pendingTxs?: string;
  batcherPaused?: boolean;
}

export interface FeeWalletBalance {
  balance: string;
  address: string;
  utxoCount?: string;
  starved?: boolean;
  floatOk?: boolean;
  minFloat?: string;
}

/**
 * BsvmHelpers attaches to `hre.bsvm` and forwards calls to the active
 * Hardhat network's JSON-RPC provider. Each helper picks the JSON-RPC
 * method that matches its name and returns the result verbatim.
 */
export interface BsvmHelpers {
  provingStatus(): Promise<ProvingStatus>;
  bridgeDeposits(
    fromBlock?: number,
    toBlock?: number,
  ): Promise<BridgeDeposit[]>;
  bridgeWithdrawals(
    fromNonce?: number,
    toNonce?: number,
  ): Promise<BridgeWithdrawal[]>;
  feeWalletBalance(): Promise<FeeWalletBalance>;
  bridgeStatus(): Promise<Record<string, unknown>>;
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * makeHelpers wires the BsvmHelpers struct against the active Hardhat
 * network provider. Uses Hardhat's EthereumProvider directly so plugin
 * users do not need to construct a separate ethers provider.
 */
export function makeHelpers(hre: HardhatRuntimeEnvironment): BsvmHelpers {
  async function call<T>(method: string, params: unknown[] = []): Promise<T> {
    const provider = hre.network.provider;
    return (await provider.request({ method, params })) as T;
  }

  return {
    call,

    async provingStatus() {
      return call<ProvingStatus>("bsv_provingStatus");
    },

    async bridgeDeposits(fromBlock = 0, toBlock = 0) {
      // Spec 15: bsv_getDeposits(fromBlock, toBlock). Both numbers; toBlock
      // 0 means "no upper bound" per the Go side.
      return call<BridgeDeposit[]>("bsv_getDeposits", [
        toHex(fromBlock),
        toHex(toBlock),
      ]);
    },

    async bridgeWithdrawals(fromNonce = 0, toNonce = 0) {
      // Spec 15: bsv_getWithdrawals(fromNonce, toNonce). Half-open range;
      // toNonce 0 fetches a default page from the RPC.
      return call<BridgeWithdrawal[]>("bsv_getWithdrawals", [
        toHex(fromNonce),
        toHex(toNonce),
      ]);
    },

    async feeWalletBalance() {
      return call<FeeWalletBalance>("bsv_feeWalletBalance");
    },

    async bridgeStatus() {
      return call<Record<string, unknown>>("bsv_bridgeStatus");
    },
  };
}

function toHex(n: number): string {
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`hardhat-bsvm: expected non-negative integer, got ${n}`);
  }
  return "0x" + Math.floor(n).toString(16);
}
