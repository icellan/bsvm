import { create } from "zustand";
import { persist } from "zustand/middleware";

// SessionState tracks the operator's active admin session. Wallets
// open a BRC-103 handshake once; after that, subsequent requests
// carry the x-bsv-auth-* headers derived from the wallet and the
// stored server/client nonce pair.
//
// For operators who run against mock / execute devnets, the
// devAuthSecret path skips the handshake entirely.

export type BrcSessionState = {
  kind: "brc100";
  identityKey: string; // hex compressed secp256k1 pubkey
  serverIdentityKey: string; // hex
  serverNonce: string; // base64 — rotates after every request
  clientNonce: string; // base64
};

export type DevSessionState = {
  kind: "devAuth";
  secret: string;
};

export type AdminSession = BrcSessionState | DevSessionState | null;

export type SessionStore = {
  session: AdminSession;
  setSession: (s: AdminSession) => void;
  updateServerNonce: (nonce: string) => void;
  clear: () => void;
};

export const useSession = create<SessionStore>()(
  persist(
    (set) => ({
      session: null,
      setSession: (s) => set({ session: s }),
      updateServerNonce: (nonce) =>
        set((state) =>
          state.session && state.session.kind === "brc100"
            ? { session: { ...state.session, serverNonce: nonce } }
            : state
        ),
      clear: () => set({ session: null }),
    }),
    {
      name: "bsvm-admin-session",
      // sessionStorage: admin session dies when the tab closes.
      storage: {
        getItem: (name) => {
          const raw = sessionStorage.getItem(name);
          return raw ? JSON.parse(raw) : null;
        },
        setItem: (name, value) => {
          sessionStorage.setItem(name, JSON.stringify(value));
        },
        removeItem: (name) => sessionStorage.removeItem(name),
      },
    }
  )
);
