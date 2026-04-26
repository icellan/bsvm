// searchResolver — universal-search classifier used by both the
// global SearchBar and the standalone /search route.
//
// The resolver is deliberately probe-based: a regex pre-classifies
// the input into a candidate list, then a single eth_* RPC call
// confirms which one actually exists on this shard. The probes run
// in priority order, terminate on the first hit, and surface a
// progressive "stage" string so the UI can show "looking up tx..."
// while the network round-trip is in flight.
//
// Supported inputs:
//   * 0x + 64 hex  → tx hash (probe: eth_getTransactionByHash)
//   * 0x + 40 hex  → address (probe: eth_getCode → /address/<a>)
//   * decimal int  → block number, bounded by chain head
//   * 0x + ≤12 hex → block number (parsed as hex int)
//   * ENS-style    → "name.bsvm" / "name.eth" — deferred (no resolver)
//
// On a miss the resolver returns { kind: "none", hint } so the UI
// can render a helpful "no match" message without re-running the
// classifier.

import { eth, hexToNumber, RpcError } from "@/rpc/client";

export type Stage =
  | "idle"
  | "classifying"
  | "looking-up-tx"
  | "looking-up-address"
  | "looking-up-block"
  | "looking-up-ens";

export type ResolveResult =
  | { kind: "tx"; hash: string; route: string }
  | { kind: "address"; address: string; isContract: boolean; route: string }
  | { kind: "block"; number: number; route: string }
  | { kind: "ens"; name: string; route: string }
  | { kind: "none"; hint: string };

const TX_RE = /^0x[0-9a-fA-F]{64}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_INT_RE = /^0x[0-9a-fA-F]{1,12}$/; // up to 48 bits — safe for JS Number
const DEC_INT_RE = /^[0-9]+$/;
const ENS_RE = /^[a-z0-9-]+\.(bsvm|eth)$/i;

export type ResolveOpts = {
  // onStage fires every time the resolver moves to a new probe so the
  // UI can render progressive feedback. Optional — non-streaming
  // callers (e.g. the SearchBar redirect path) can ignore it.
  onStage?: (stage: Stage) => void;
  // signal lets the caller cancel an in-flight resolve when the user
  // types again. AbortController is used by the SearchBar to debounce
  // overlapping requests.
  signal?: AbortSignal;
};

// resolve runs the probe ladder for `q` and returns the first hit.
// Throws only on programmer error — RPC failures are swallowed and
// converted into "miss" results so the caller can keep typing.
export async function resolve(
  q: string,
  opts: ResolveOpts = {},
): Promise<ResolveResult> {
  const t = q.trim();
  if (!t) return { kind: "none", hint: "" };

  opts.onStage?.("classifying");

  // Tx hash — 64-hex uniquely identifies a transaction. eth_getTxByHash
  // is the cheapest probe (constant time on the indexer) so try first.
  if (TX_RE.test(t)) {
    opts.onStage?.("looking-up-tx");
    if (opts.signal?.aborted) return { kind: "none", hint: "cancelled" };
    try {
      const tx = await eth.getTransactionByHash(t);
      if (tx) {
        return { kind: "tx", hash: tx.hash, route: `/tx/${tx.hash}` };
      }
    } catch (err) {
      // Surface RPC errors (bad hex, server down) as a miss so the
      // user can keep editing without seeing an error toast.
      if (!(err instanceof RpcError)) throw err;
    }
    return {
      kind: "none",
      hint: `No transaction found for ${shorten(t)}.`,
    };
  }

  // Address — 40-hex. eth_getCode lets us label EOA vs contract for
  // a small UX win on the destination page.
  if (ADDR_RE.test(t)) {
    opts.onStage?.("looking-up-address");
    if (opts.signal?.aborted) return { kind: "none", hint: "cancelled" };
    let isContract = false;
    try {
      const code = await eth.getCode(t);
      isContract = !!code && code !== "0x";
    } catch (err) {
      if (!(err instanceof RpcError)) throw err;
    }
    return {
      kind: "address",
      address: t,
      isContract,
      route: `/address/${t}`,
    };
  }

  // ENS-style — deferred. We surface a friendly hint instead of an
  // RPC error so the user knows the explorer recognised the format
  // but doesn't have a resolver for it yet.
  if (ENS_RE.test(t)) {
    opts.onStage?.("looking-up-ens");
    return {
      kind: "none",
      hint: "ENS resolution is not available on BSVM v1. Try a block number, address, or tx hash.",
    };
  }

  // Block number — decimal or short hex. Bound the candidate by the
  // current chain head so a typo like "1234567890" doesn't kick off
  // a fetch for a block that can't possibly exist.
  if (DEC_INT_RE.test(t) || HEX_INT_RE.test(t)) {
    opts.onStage?.("looking-up-block");
    if (opts.signal?.aborted) return { kind: "none", hint: "cancelled" };
    const n = DEC_INT_RE.test(t) ? Number.parseInt(t, 10) : hexToNumber(t);
    if (!Number.isFinite(n) || n < 0) {
      return { kind: "none", hint: `${t} is not a valid block number.` };
    }
    let head = -1;
    try {
      head = hexToNumber(await eth.blockNumber());
    } catch (err) {
      if (!(err instanceof RpcError)) throw err;
    }
    if (head >= 0 && n > head) {
      return {
        kind: "none",
        hint: `Block #${n.toLocaleString()} is past the chain head (#${head.toLocaleString()}).`,
      };
    }
    try {
      const blk = await eth.getBlockByNumber(n, false);
      if (blk) {
        return { kind: "block", number: n, route: `/block/${n}` };
      }
    } catch (err) {
      if (!(err instanceof RpcError)) throw err;
    }
    return {
      kind: "none",
      hint: `No block at #${n.toLocaleString()}.`,
    };
  }

  return {
    kind: "none",
    hint: "Expected a block number, tx hash (0x + 64 hex), address (0x + 40 hex), or ENS name.",
  };
}

// stageLabel maps a Stage to a short human-readable string for the
// progressive feedback strip. Centralised so the SearchBar and the
// /search page share wording.
export function stageLabel(stage: Stage): string {
  switch (stage) {
    case "classifying":
      return "classifying input...";
    case "looking-up-tx":
      return "looking up tx...";
    case "looking-up-address":
      return "looking up address...";
    case "looking-up-block":
      return "looking up block...";
    case "looking-up-ens":
      return "resolving ENS name...";
    default:
      return "";
  }
}

function shorten(v: string): string {
  if (v.length <= 14) return v;
  return `${v.slice(0, 8)}...${v.slice(-6)}`;
}
