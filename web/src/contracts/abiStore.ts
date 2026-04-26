// abiStore — localStorage-backed cache of contract ABIs keyed by
// address. The contract-interaction page persists whatever the user
// pastes / drops so subsequent visits load the same surface without
// re-uploading.
//
// Storage layout:
//   key   = "bsvm.abi.<lowercase-address>"
//   value = { abi: any[], savedAt: <unix-ms>, source?: string }
//
// The value is JSON-serialised; ABIs from Solidity / Foundry are
// arbitrary JSON arrays so we don't impose a stricter schema here.
// The methodCaller validates each fragment before using it.

const PREFIX = "bsvm.abi.";

export type AbiFragment = {
  type: string;
  name?: string;
  inputs?: Array<{ name?: string; type: string; indexed?: boolean }>;
  outputs?: Array<{ name?: string; type: string }>;
  stateMutability?: "pure" | "view" | "nonpayable" | "payable";
  anonymous?: boolean;
};

export type StoredAbi = {
  abi: AbiFragment[];
  savedAt: number;
  source?: string;
};

// normaliseAddress lowercases the 0x-prefixed hex so the storage key
// is stable regardless of the casing used in the URL.
function normaliseAddress(address: string): string {
  return address.toLowerCase();
}

export function loadAbi(address: string): StoredAbi | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(PREFIX + normaliseAddress(address));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredAbi;
    if (!Array.isArray(parsed.abi)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveAbi(address: string, abi: AbiFragment[], source?: string): void {
  if (typeof localStorage === "undefined") return;
  const value: StoredAbi = { abi, savedAt: Date.now(), source };
  localStorage.setItem(PREFIX + normaliseAddress(address), JSON.stringify(value));
}

export function clearAbi(address: string): void {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem(PREFIX + normaliseAddress(address));
}

// parseAbiInput accepts either a raw JSON ABI array or a Hardhat /
// Foundry artifact wrapping it under `.abi`. Returns the normalised
// fragment list or throws with a useful message when the input
// can't be coerced.
export function parseAbiInput(text: string): AbiFragment[] {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("ABI is empty");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    throw new Error(`invalid JSON: ${(err as Error).message}`);
  }
  // Hardhat / Foundry artifact: { abi: [...] }
  if (
    parsed &&
    typeof parsed === "object" &&
    !Array.isArray(parsed) &&
    "abi" in parsed &&
    Array.isArray((parsed as { abi: unknown }).abi)
  ) {
    parsed = (parsed as { abi: unknown[] }).abi;
  }
  if (!Array.isArray(parsed)) {
    throw new Error("expected an ABI array or a { abi: [...] } artifact");
  }
  // Light validation — every fragment must at least have `type`.
  // The deeper shape (inputs/outputs) is validated lazily by ethers
  // when the user actually invokes a method.
  for (const f of parsed) {
    if (!f || typeof f !== "object" || typeof (f as { type?: unknown }).type !== "string") {
      throw new Error("invalid ABI fragment — missing `type`");
    }
  }
  return parsed as AbiFragment[];
}

// fragmentSignature builds a canonical "name(type1,type2)" string
// for a function or event fragment. Used as a stable map key in the
// methodCaller / eventDecoder tables.
export function fragmentSignature(f: AbiFragment): string {
  const inputs = (f.inputs ?? []).map((i) => i.type).join(",");
  return `${f.name ?? ""}(${inputs})`;
}
