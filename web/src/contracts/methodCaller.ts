// methodCaller — encode + invoke contract methods using ethers v6.
//
// This module owns the bridge between the user-supplied ABI and the
// shard's JSON-RPC. Read methods (view / pure) round-trip through
// `eth_call`; write methods (nonpayable / payable) hand a populated
// transaction skeleton to the EVM wallet (window.ethereum) and
// surface the resulting tx hash.
//
// We use ethers' Interface for ABI encoding/decoding and BigInt
// coercion. The viem alternative was considered but ethers is
// already a project dep and v6 ships a tree-shakeable Interface.

import { Interface, JsonFragment } from "ethers";

import { eth } from "@/rpc/client";
import { sendEvmTransaction } from "@/auth/wallet";
import { AbiFragment } from "@/contracts/abiStore";

// classifyAbi splits the ABI into read / write functions plus events
// for the page's three main lists. Constructors / errors / fallbacks
// are intentionally hidden — the user cannot interact with them
// from the explorer.
export type ClassifiedAbi = {
  reads: AbiFragment[];
  writes: AbiFragment[];
  events: AbiFragment[];
};

export function classifyAbi(abi: AbiFragment[]): ClassifiedAbi {
  const reads: AbiFragment[] = [];
  const writes: AbiFragment[] = [];
  const events: AbiFragment[] = [];
  for (const f of abi) {
    if (f.type === "event") {
      events.push(f);
      continue;
    }
    if (f.type !== "function") continue;
    const m = f.stateMutability ?? "nonpayable";
    if (m === "view" || m === "pure") {
      reads.push(f);
    } else {
      writes.push(f);
    }
  }
  return { reads, writes, events };
}

// makeInterface wraps the ethers Interface constructor so we can
// surface a friendly error when the ABI is malformed (e.g. a stray
// fragment with an unknown type field).
export function makeInterface(abi: AbiFragment[]): Interface {
  return new Interface(abi as unknown as JsonFragment[]);
}

// coerceArg turns the raw string the user typed in the UI into a
// value ethers' encoder accepts. We handle the common cases:
//
//   * tuples / arrays — JSON literal: `[1, 2, 3]` or `["0x...", "foo"]`
//   * uint*           — decimal or 0x-prefixed hex (BigInt)
//   * int*            — signed decimal or hex (BigInt)
//   * bool            — "true" / "false" / "1" / "0"
//   * address         — pass-through
//   * bytes / string  — pass-through
//
// On any parse failure we throw with the input + parameter name so
// the caller can render an inline validation message.
export function coerceArg(type: string, raw: string, paramName?: string): unknown {
  const v = raw.trim();
  const where = paramName ? ` for "${paramName}"` : "";

  if (type.endsWith("[]") || type.startsWith("tuple")) {
    if (!v) return [];
    try {
      return JSON.parse(v);
    } catch (err) {
      throw new Error(`invalid array/tuple JSON${where}: ${(err as Error).message}`);
    }
  }
  if (type === "bool") {
    if (v === "true" || v === "1") return true;
    if (v === "false" || v === "0" || v === "") return false;
    throw new Error(`invalid bool${where}: ${raw}`);
  }
  if (type.startsWith("uint") || type.startsWith("int")) {
    if (!v) return 0n;
    try {
      return BigInt(v);
    } catch (err) {
      throw new Error(`invalid integer${where}: ${(err as Error).message}`);
    }
  }
  // address, string, bytes, bytes32 — pass through as the raw string.
  return v;
}

// encodeArgs runs coerceArg over every input of a function fragment
// and returns the array shape ethers expects.
export function encodeArgs(
  fragment: AbiFragment,
  rawValues: string[],
): unknown[] {
  const inputs = fragment.inputs ?? [];
  const out: unknown[] = [];
  for (let i = 0; i < inputs.length; i++) {
    out.push(coerceArg(inputs[i].type, rawValues[i] ?? "", inputs[i].name));
  }
  return out;
}

// callRead encodes the function call, sends an eth_call, and
// returns the decoded return values (always wrapped in an array,
// matching ethers' Result shape).
//
// Decoded values pass through `prettyValue` for display — bigint
// → decimal string, bytes → hex, otherwise JSON.stringify with
// BigInt-aware replacer.
export async function callRead(
  iface: Interface,
  fragment: AbiFragment,
  to: string,
  rawArgs: string[],
): Promise<{ raw: string; decoded: string }> {
  const args = encodeArgs(fragment, rawArgs);
  const data = iface.encodeFunctionData(fragment.name!, args);
  const raw = await eth.call({ to, data });
  if (!raw || raw === "0x") {
    return { raw, decoded: "(empty return — function may have reverted or returned void)" };
  }
  let decoded: string;
  try {
    const result = iface.decodeFunctionResult(fragment.name!, raw);
    decoded = prettyResult(result as unknown as unknown[]);
  } catch (err) {
    decoded = `(failed to decode: ${(err as Error).message})`;
  }
  return { raw, decoded };
}

// sendWrite encodes the function call and hands it to the EVM
// wallet. Returns the broadcast tx hash, which the caller can link
// to /tx/<hash>.
export async function sendWrite(opts: {
  iface: Interface;
  fragment: AbiFragment;
  to: string;
  rawArgs: string[];
  from: string;
  valueWei?: bigint;
  gasLimit?: bigint;
}): Promise<string> {
  const args = encodeArgs(opts.fragment, opts.rawArgs);
  const data = opts.iface.encodeFunctionData(opts.fragment.name!, args);
  return sendEvmTransaction({
    from: opts.from,
    to: opts.to,
    data,
    value: opts.valueWei !== undefined ? `0x${opts.valueWei.toString(16)}` : undefined,
    gas: opts.gasLimit !== undefined ? `0x${opts.gasLimit.toString(16)}` : undefined,
  });
}

// prettyResult formats an ethers Result tuple into a multi-line
// string for the read-method display panel. Single-return functions
// render as the bare value; tuple returns get one line per slot.
export function prettyResult(values: unknown[]): string {
  if (values.length === 0) return "(no return values)";
  if (values.length === 1) return prettyValue(values[0]);
  return values.map((v, i) => `[${i}] ${prettyValue(v)}`).join("\n");
}

export function prettyValue(v: unknown): string {
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return v;
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) {
    return `[${v.map(prettyValue).join(", ")}]`;
  }
  try {
    return JSON.stringify(
      v,
      (_k, val) => (typeof val === "bigint" ? val.toString() : val),
    );
  } catch {
    return String(v);
  }
}

// parseValueInput converts a "1.5" / "1500000000000000000" entry in
// the value field into a wei BigInt. Pass-through behaviour for raw
// integers; "1.5" multiplies by 1e18 (treating the entry as wBSV).
export function parseValueInput(raw: string): bigint {
  const v = raw.trim();
  if (!v) return 0n;
  if (v.startsWith("0x")) return BigInt(v);
  if (/^[0-9]+$/.test(v)) return BigInt(v);
  if (/^[0-9]+\.[0-9]+$/.test(v)) {
    const [whole, frac] = v.split(".");
    const fracPadded = (frac + "000000000000000000").slice(0, 18);
    return BigInt(whole) * 10n ** 18n + BigInt(fracPadded);
  }
  throw new Error(`invalid value: ${raw}`);
}
