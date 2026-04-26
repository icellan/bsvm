// BRC-100 wallet bridge.
//
// The explorer reaches a running BRC-100 wallet (BSV Desktop,
// Metanet Desktop, or any wallet that implements the browser-side
// window.bsv provider contract exported by @bsv/wallet-toolbox). A
// real integration defers to those providers; this module exposes
// the thin adapter surface the rest of the app consumes.
//
// When no wallet is present the functions here throw a helpful error
// the admin-panel UI catches and renders as "install a BRC-100
// wallet to continue."

declare global {
  interface Window {
    bsv?: BrowserBsvProvider;
    ethereum?: EvmProvider;
  }
}

// EvmProvider is the EIP-1193 surface exposed by MetaMask, Rabby,
// and any wallet that speaks the standard. The contract-interaction
// page uses it for write methods (eth_sendTransaction). The wallet
// is expected to handle nonce, gas, and chain selection — we only
// hand it the call arguments. BRC-100 wallets like Metanet Desktop
// don't currently expose this surface, so the UI degrades to a
// "no EVM wallet available" hint when window.ethereum is absent.
export type EvmProvider = {
  isMetaMask?: boolean;
  request: <T = unknown>(args: {
    method: string;
    params?: unknown[];
  }) => Promise<T>;
};

// The `window.bsv` interface as defined by BRC-100 wallet toolbox.
// We only use a tiny slice of it — requestIdentity + signMessage.
// Full wallet features (actions, certificates) are out of scope for
// the admin panel.
export type BrowserBsvProvider = {
  isBsvWallet?: true;
  // Returns the compressed secp256k1 identity key hex.
  requestIdentityKey: () => Promise<string>;
  // Signs a SHA-256 digest over the given message bytes.
  signMessage: (args: {
    message: Uint8Array;
    protocolID: [number, string];
    keyID: string;
  }) => Promise<{ signature: Uint8Array }>;
};

export class WalletUnavailableError extends Error {
  constructor() {
    super(
      "No BRC-100 wallet detected. Install Metanet Desktop or BSV Desktop and reload."
    );
  }
}

export function getProvider(): BrowserBsvProvider {
  const provider = typeof window !== "undefined" ? window.bsv : undefined;
  if (!provider) throw new WalletUnavailableError();
  return provider;
}

export async function requestIdentityKey(): Promise<string> {
  return getProvider().requestIdentityKey();
}

// signMessage asks the wallet to sign the given byte payload under
// the `auth message signature` protocol ID (matches BRC-31 / BRC-3).
// Returns a hex-encoded DER signature the server can verify with
// ec.ParseDERSignature + sig.Verify.
export async function signMessage(payload: Uint8Array): Promise<string> {
  const provider = getProvider();
  const { signature } = await provider.signMessage({
    message: payload,
    protocolID: [2, "auth message signature"],
    keyID: "1",
  });
  return bytesToHex(signature);
}

// Low-level hex helpers — intentionally self-contained so this file
// doesn't pull in a whole crypto library for two small conversions.

export function bytesToHex(bytes: Uint8Array): string {
  const chars: string[] = [];
  for (const b of bytes) chars.push(b.toString(16).padStart(2, "0"));
  return chars.join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const trimmed = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Cast needed since TS 5.7 tightened BufferSource to forbid
  // SharedArrayBuffer backing — our data is always a plain
  // Uint8Array so the cast is safe.
  const buf = await crypto.subtle.digest(
    "SHA-256",
    data as unknown as ArrayBuffer
  );
  return new Uint8Array(buf);
}

export function randomNonce(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

// ---- EVM wallet bridge (contract write methods) ----------------------
//
// The contract-interaction page on the explorer needs an Ethereum-
// compatible signer for state-changing calls. We use the EIP-1193
// `window.ethereum` provider when present (MetaMask, Rabby, etc.).
// The BRC-100 wallet (window.bsv) is reserved for admin / governance
// signatures and cannot sign EVM transactions on its own.

export class EvmWalletUnavailableError extends Error {
  constructor() {
    super(
      "No EVM wallet detected. Install MetaMask (or any EIP-1193 wallet) to send transactions.",
    );
  }
}

export function getEvmProvider(): EvmProvider {
  const provider = typeof window !== "undefined" ? window.ethereum : undefined;
  if (!provider) throw new EvmWalletUnavailableError();
  return provider;
}

export function hasEvmProvider(): boolean {
  return typeof window !== "undefined" && !!window.ethereum;
}

// requestEvmAccounts asks the wallet to expose at least one account.
// Returns the user-selected from-address (lowercased hex). The wallet
// may show a connect prompt the first time this is invoked.
export async function requestEvmAccounts(): Promise<string> {
  const provider = getEvmProvider();
  const accounts = await provider.request<string[]>({
    method: "eth_requestAccounts",
  });
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error("wallet returned no accounts");
  }
  return accounts[0].toLowerCase();
}

// sendEvmTransaction hands an unsigned tx skeleton to the EVM wallet
// for signing + broadcast. The wallet returns the resulting tx hash.
// We deliberately let the wallet pick nonce / gas / fees; callers may
// override gas / value via the args.
export async function sendEvmTransaction(args: {
  from: string;
  to?: string;
  data?: string;
  value?: string;
  gas?: string;
}): Promise<string> {
  const provider = getEvmProvider();
  return provider.request<string>({
    method: "eth_sendTransaction",
    params: [args],
  });
}
