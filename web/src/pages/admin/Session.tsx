import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import { useSession } from "@/state/session";
import { handshake } from "@/auth/session";
import { WalletUnavailableError } from "@/auth/wallet";
import { Button } from "@/components/ui";

// Admin sign-in — 440 px centered card, handshake-flow numbered list
// below, dev-auth fallback for devnet. Gate for all /admin/* routes:
// redirects here when no session exists.
export default function AdminSession() {
  const session = useSession((s) => s.session);
  const setSession = useSession((s) => s.setSession);
  const nav = useNavigate();
  const loc = useLocation();
  const [err, setErr] = useState("");
  const [pending, setPending] = useState(false);

  const returnTo = (loc.state as { returnTo?: string } | null)?.returnTo ?? "/admin";

  useEffect(() => {
    if (session) nav(returnTo, { replace: true });
  }, [session, nav, returnTo]);

  async function connectWallet() {
    setErr("");
    setPending(true);
    try {
      await handshake();
    } catch (e) {
      if (e instanceof WalletUnavailableError) setErr(e.message);
      else setErr(String(e));
    } finally {
      setPending(false);
    }
  }

  function useDevAuth() {
    const secret = prompt("Enter the admin dev-auth secret (BSVM_ADMIN_DEV_SECRET).") ?? "";
    if (!secret) return;
    setSession({ kind: "devAuth", secret });
  }

  return (
    <div
      className="flex justify-center"
      style={{ paddingTop: 60, paddingBottom: 40 }}
    >
      <div
        style={{
          maxWidth: 440,
          width: "100%",
          border: "1px solid var(--ts-line)",
          borderRadius: 8,
          padding: 28,
          background: "var(--ts-bg-1)",
        }}
      >
        <div
          className="mono"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-text-3)",
          }}
        >
          Admin · sign in
        </div>
        <h1
          className="mt-2"
          style={{ fontSize: 22, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Connect a{" "}
          <span style={{ color: "var(--ts-accent)" }}>governance</span> wallet
        </h1>
        <p
          className="mt-3"
          style={{ fontSize: 13, color: "var(--ts-text-2)", lineHeight: 1.55 }}
        >
          Connect a BRC-100 wallet (BSV Desktop, Metanet Desktop) whose
          identity key is in the shard's governance set. Admin RPC calls are
          signed per request via BRC-104.
        </p>

        <div className="flex flex-col mt-5" style={{ gap: 8 }}>
          <Button variant="primary" onClick={connectWallet} disabled={pending}>
            {pending ? "Connecting…" : "Connect BRC-100 wallet"}
          </Button>
          <Button onClick={useDevAuth}>
            Use dev-auth secret (devnet only)
          </Button>
        </div>

        {err ? (
          <p
            className="mono mt-3"
            style={{ fontSize: 11, color: "var(--ts-bad)" }}
          >
            {err}
          </p>
        ) : null}

        <div
          className="mono mt-6"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-text-3)",
          }}
        >
          Handshake flow
        </div>
        <ol
          style={{
            marginTop: 8,
            paddingLeft: 22,
            fontSize: 12,
            color: "var(--ts-text-2)",
            lineHeight: 1.7,
          }}
        >
          <li>Wallet exposes identity key (BRC-100)</li>
          <li>Server verifies key is in governance set</li>
          <li>Server issues session nonce</li>
          <li>Every admin RPC call is signed (BRC-104)</li>
        </ol>

        <p
          className="mt-6"
          style={{ fontSize: 11, color: "var(--ts-text-3)" }}
        >
          <Link to="/" style={{ color: "var(--ts-accent)" }}>
            ← back to explorer
          </Link>
        </p>
      </div>
    </div>
  );
}
