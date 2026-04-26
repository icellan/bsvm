// JSON-RPC client used by every explorer query.
//
// The design is deliberately thin — no code generation, no proxies,
// just a POST wrapper that knows about the JSON-RPC 2.0 envelope and
// throws on error. Higher-level views compose these into TanStack
// Query hooks so cancellation and cache invalidation work without
// re-inventing them here.

export type JsonRpcId = string | number;

export type JsonRpcRequest<P = unknown> = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params?: P;
};

export type JsonRpcSuccess<R> = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result: R;
};

export type JsonRpcError = {
  code: number;
  message: string;
  data?: unknown;
};

export class RpcError extends Error {
  readonly code: number;
  readonly method: string;

  constructor(method: string, err: JsonRpcError) {
    super(`${method}: ${err.message}`);
    this.code = err.code;
    this.method = method;
  }
}

export type RpcClientOptions = {
  // baseURL defaults to the document origin so a build served by the
  // node naturally talks to the same origin. The devnet Vite server
  // proxies /rpc to the node, so this stays correct in dev too.
  baseURL?: string;
  // adminHeader is a pre-formatted header map layered onto every
  // /admin/rpc call. Populated by the auth session once connected.
  adminHeader?: () => Record<string, string>;
};

let rpcCallSeq = 1;

// call drives a JSON-RPC request against the node. When `admin` is
// true the request goes to /admin/rpc with the admin header map
// attached; otherwise the public /rpc dispatcher is used.
export async function call<R>(
  method: string,
  params: unknown[] = [],
  opts: { admin?: boolean } & RpcClientOptions = {}
): Promise<R> {
  const path = opts.admin ? "/admin/rpc" : "/rpc";
  const url = (opts.baseURL ?? "") + path;

  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (opts.admin && opts.adminHeader) {
    Object.assign(headers, opts.adminHeader());
  }

  const body: JsonRpcRequest = {
    jsonrpc: "2.0",
    id: rpcCallSeq++,
    method,
    params,
  };
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${method}: HTTP ${res.status}`);
  }
  const json = (await res.json()) as
    | JsonRpcSuccess<R>
    | { jsonrpc: "2.0"; id: JsonRpcId; error: JsonRpcError };
  if ("error" in json) {
    throw new RpcError(method, json.error);
  }
  return json.result;
}

// Convenience wrappers for the public namespaces.
export const eth = {
  chainId: () => call<string>("eth_chainId"),
  blockNumber: () => call<string>("eth_blockNumber"),
  getBalance: (address: string, tag = "latest") =>
    call<string>("eth_getBalance", [address, tag]),
  getTransactionCount: (address: string, tag = "latest") =>
    call<string>("eth_getTransactionCount", [address, tag]),
  getBlockByNumber: (num: string | number, includeTxs = true) =>
    call<BlockDetail | null>("eth_getBlockByNumber", [
      typeof num === "number" ? `0x${num.toString(16)}` : num,
      includeTxs,
    ]),
  getBlockByHash: (hash: string, includeTxs = true) =>
    call<BlockDetail | null>("eth_getBlockByHash", [hash, includeTxs]),
  getTransactionByHash: (hash: string) =>
    call<TransactionDetail | null>("eth_getTransactionByHash", [hash]),
  getTransactionReceipt: (hash: string) =>
    call<TransactionReceipt | null>("eth_getTransactionReceipt", [hash]),
  getCode: (address: string, tag = "latest") =>
    call<string>("eth_getCode", [address, tag]),
  gasPrice: () => call<string>("eth_gasPrice"),
  // eth_call — read-only contract execution. Returns the hex-encoded
  // ABI-packed return value, or "0x" for a void/reverting call.
  call: (
    args: { to: string; from?: string; data?: string; value?: string },
    tag = "latest",
  ) => call<string>("eth_call", [args, tag]),
  // eth_estimateGas — best-effort gas estimate for a tx that hasn't
  // been signed yet. Used by the contract-write flow to seed a
  // sensible default before the wallet picks the final value.
  estimateGas: (args: {
    to?: string;
    from?: string;
    data?: string;
    value?: string;
  }) => call<string>("eth_estimateGas", [args]),
  // eth_sendRawTransaction — submit a wallet-signed transaction to
  // the mempool. Returns the tx hash.
  sendRawTransaction: (rawHex: string) =>
    call<string>("eth_sendRawTransaction", [rawHex]),
  // eth_getLogs — fetch logs matching the given filter. Used by the
  // contract event decoder; we constrain to a recent window to keep
  // payloads small.
  getLogs: (filter: {
    address?: string | string[];
    fromBlock?: string;
    toBlock?: string;
    topics?: (string | string[] | null)[];
  }) => call<LogEntry[]>("eth_getLogs", [filter]),
};

export const bsv = {
  shardInfo: () => call<ShardInfo>("bsv_shardInfo"),
  networkHealth: () => call<NetworkHealth>("bsv_networkHealth"),
  provingStatus: () => call<ProvingStatus>("bsv_provingStatus"),
  bridgeStatus: () => call<BridgeStatus>("bsv_bridgeStatus"),
  getDeposits: (from = "0x0", to = "0x0") =>
    call<DepositSummary[]>("bsv_getDeposits", [from, to]),
  getWithdrawals: (from = "0x0", to = "0x0") =>
    call<WithdrawalSummary[]>("bsv_getWithdrawals", [from, to]),
  getGovernanceState: () =>
    call<GovernanceState>("bsv_getGovernanceState"),
  getCovenantTip: () => call<CovenantTip>("bsv_getCovenantTip"),
  getConfirmationStatus: (blockNum: string | number) =>
    call<ConfirmationStatus>("bsv_getConfirmationStatus", [
      typeof blockNum === "number" ? `0x${blockNum.toString(16)}` : blockNum,
    ]),
  indexerStatus: () => call<IndexerStatus>("bsv_indexerStatus"),
  getPeers: () => call<PeerEntry[]>("bsv_getPeers"),
  getAddressTxs: (
    address: string,
    opts?: { fromBlock?: number; toBlock?: number; limit?: number },
  ) => {
    const params: unknown[] = [address];
    if (opts) {
      const o: Record<string, string> = {};
      if (opts.fromBlock !== undefined) o.fromBlock = `0x${opts.fromBlock.toString(16)}`;
      if (opts.toBlock !== undefined) o.toBlock = `0x${opts.toBlock.toString(16)}`;
      if (opts.limit !== undefined) o.limit = `0x${opts.limit.toString(16)}`;
      params.push(o);
    }
    return call<AddressTxEntry[]>("bsv_getAddressTxs", params);
  },
};

export type IndexerStatus = {
  enabled: boolean;
  lastBlock?: HexString;
  ingested?: HexString;
  dropped?: HexString;
};

export type PeerEntry = {
  id: string;
  addrs: string[];
  chainTip: HexString;
  lastSeen: HexString;
  score: number;
  direction: "inbound" | "outbound" | "";
};

export type AddressTxEntry = {
  txHash: HexString;
  blockNumber: HexString;
  transactionIndex: HexString;
  direction: "from" | "to" | "create";
  status: HexString;
  otherParty?: string;
};

// Admin namespace — every call routes through /admin/rpc and
// expects the adminHeader hook to be configured.
export function admin<R>(method: string, params: unknown[] = [], opts: RpcClientOptions): Promise<R> {
  return call<R>(method, params, { admin: true, ...opts });
}

// ---- Shared shapes ----------------------------------------------------

export type HexString = `0x${string}`;

export type BlockDetail = {
  number: HexString;
  hash: HexString;
  parentHash: HexString;
  timestamp: HexString;
  gasUsed: HexString;
  gasLimit: HexString;
  miner: string;
  transactions: TransactionDetail[] | HexString[];
  stateRoot: HexString;
  receiptsRoot: HexString;
};

export type TransactionDetail = {
  hash: HexString;
  blockNumber: HexString | null;
  blockHash: HexString | null;
  from: string;
  to: string | null;
  value: HexString;
  gas: HexString;
  gasPrice?: HexString;
  input: HexString;
  nonce: HexString;
  type?: HexString;
};

export type TransactionReceipt = {
  transactionHash: HexString;
  status: HexString;
  blockNumber: HexString;
  blockHash: HexString;
  from: string;
  to: string | null;
  gasUsed: HexString;
  effectiveGasPrice?: HexString;
  logs: LogEntry[];
};

export type LogEntry = {
  address: string;
  topics: HexString[];
  data: HexString;
  blockNumber: HexString;
  transactionHash: HexString;
  logIndex: HexString;
};

export type ShardInfo = {
  shardId: string;
  chainId: HexString;
  executionTip: HexString;
  provenTip: HexString;
  cachedChainLength: HexString;
  peerCount: HexString;
  genesisCovenantTxId: string;
  governance: {
    mode: string;
    frozen: boolean;
    threshold?: HexString;
    keyCount?: HexString;
  };
};

export type NetworkHealth = {
  peerCount: HexString;
  executionTip: HexString;
  provenTip: HexString;
  confirmedTip: HexString;
  finalizedTip: HexString;
  speculativeDepth: HexString;
  maxSpeculativeDepth: HexString;
  proverMode?: string;
  proverInFlight?: HexString;
  proverQueueDepth?: HexString;
  proofsSucceeded?: HexString;
  proofsFailed?: HexString;
  averageProveTimeMs?: HexString;
};

export type ProvingStatus = {
  mode: string;
  workers: HexString;
  inFlight: HexString;
  queueDepth: HexString;
  proofsStarted: HexString;
  proofsSucceeded: HexString;
  proofsFailed: HexString;
  averageTimeMs: HexString;
  pendingTxs: HexString;
  batcherPaused: boolean;
};

export type BridgeStatus = {
  totalLockedSatoshis: HexString;
  totalLockedWei: string;
  totalSupplyWei: string;
  subCovenantCount: HexString;
};

export type DepositSummary = {
  bsvTxId: string;
  vout: HexString;
  bsvBlockHeight: HexString;
  l2Address: string;
  satoshiAmount: HexString;
  l2WeiAmount: string;
  confirmed: boolean;
};

export type WithdrawalSummary = {
  nonce: HexString;
  amountWei: string;
  bsvAddress: string;
  l2TxHash: string;
  claimed: boolean;
  claimBsvTxid: string;
  csvRemaining: HexString;
};

export type GovernanceState = {
  mode: string;
  frozen: boolean;
  keys: string[];
  threshold: number;
};

export type CovenantTip = {
  bsvTxId: string;
  l2BlockNumber: HexString;
  stateRoot: HexString;
  confirmed: boolean;
  bsvBlockHeight?: HexString;
};

export type ConfirmationStatus = {
  l2BlockNumber: HexString;
  bsvTxId: string;
  confirmations: HexString;
  confirmed: boolean;
  safe: boolean;
  finalized: boolean;
};

// ---- Hex utilities ----------------------------------------------------

// hexToNumber parses an Ethereum-style 0x-prefixed hex string into a
// JS number. Returns 0 on "0x" or empty. Throws when the value
// overflows Number.MAX_SAFE_INTEGER so callers notice rather than
// silently rounding big chain values.
export function hexToNumber(hex: string | undefined | null): number {
  if (!hex) return 0;
  const trimmed = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (trimmed.length === 0) return 0;
  const n = Number.parseInt(trimmed, 16);
  if (!Number.isFinite(n)) return 0;
  if (n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`hex value overflows JS number: ${hex}`);
  }
  return n;
}

// hexToBigInt parses a hex string into a BigInt. Safe for wei
// amounts that don't fit in Number.
export function hexToBigInt(hex: string | undefined | null): bigint {
  if (!hex) return 0n;
  const trimmed = hex.startsWith("0x") ? hex : `0x${hex}`;
  return BigInt(trimmed);
}

// formatWei returns a decimal wBSV representation of a wei amount
// with up to 4 fractional digits. Input can be a hex string or a
// decimal string (bsv_bridgeStatus returns decimal).
export function formatWei(v: string): string {
  const raw = v.startsWith("0x") ? BigInt(v).toString() : v;
  if (raw === "0") return "0";
  const padded = raw.padStart(19, "0");
  const whole = padded.slice(0, -18);
  const frac = padded.slice(-18).slice(0, 4).replace(/0+$/, "");
  return frac.length ? `${whole}.${frac}` : whole;
}
