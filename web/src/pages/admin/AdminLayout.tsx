import { Link, NavLink as RRNavLink, Outlet } from "react-router-dom";

import { useSession } from "@/state/session";
import { handshake } from "@/auth/session";
import { WalletUnavailableError } from "@/auth/wallet";
import { useState } from "react";

// AdminLayout wraps the admin pages with a sidebar + session gate.
// The gate is intentionally client-side: even with a leaked URL a
// request to /admin/rpc still fails at the server unless the browser
// holds a live session.
export default function AdminLayout() {
  const session = useSession((s) => s.session);
  const clear = useSession((s) => s.clear);
  const setSession = useSession((s) => s.setSession);
  const [error, setError] = useState<string>("");

  async function connectWallet() {
    setError("");
    try {
      await handshake();
    } catch (err) {
      if (err instanceof WalletUnavailableError) {
        setError(err.message);
      } else {
        setError(String(err));
      }
    }
  }

  function useDevAuth() {
    const secret =
      prompt("Enter the admin dev-auth secret (BSVM_ADMIN_DEV_SECRET).") ?? "";
    if (!secret) return;
    setSession({ kind: "devAuth", secret });
  }

  if (!session) {
    return (
      <div className="mx-auto max-w-md panel p-6">
        <h1 className="text-lg font-bold">Admin sign-in</h1>
        <p className="mt-2 text-sm text-muted">
          Connect a BRC-100 wallet (BSV Desktop, Metanet Desktop) whose
          identity key is in the shard's governance set.
        </p>
        <div className="mt-4 flex flex-col gap-2">
          <button
            onClick={connectWallet}
            className="rounded-md border border-accent/60 bg-accent/10 px-3 py-2 text-sm font-semibold text-accent hover:bg-accent/20"
          >
            Connect wallet
          </button>
          <button
            onClick={useDevAuth}
            className="rounded-md border border-border bg-panel px-3 py-2 text-xs text-muted hover:text-fg"
          >
            Use dev-auth secret (devnet only)
          </button>
        </div>
        {error ? (
          <p className="mt-3 text-xs text-danger">{error}</p>
        ) : null}
        <p className="mt-4 text-xs text-muted">
          <Link to="/">← back to explorer</Link>
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 md:flex-row">
      <aside className="w-full flex-none md:w-56">
        <div className="panel p-3 text-sm">
          <p className="text-xs uppercase tracking-wider text-muted">Signed in</p>
          <p className="mt-1 font-mono text-xs text-fg">
            {session.kind === "brc100" ? `${session.identityKey.slice(0, 12)}…` : "dev-auth"}
          </p>
          <button
            onClick={clear}
            className="mt-3 w-full rounded-md border border-border px-2 py-1 text-xs text-muted hover:text-danger"
          >
            Sign out
          </button>
        </div>
        <nav className="mt-3 flex flex-col gap-1 text-sm">
          <SideLink to="/admin" label="Dashboard" end />
          <SideLink to="/admin/governance" label="Governance" />
          <SideLink to="/admin/config" label="Config" />
          <SideLink to="/admin/prover" label="Prover" />
          <SideLink to="/admin/logs" label="Logs" />
        </nav>
      </aside>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}

function SideLink(props: { to: string; label: string; end?: boolean }) {
  return (
    <RRNavLink
      to={props.to}
      end={props.end}
      className={({ isActive }) =>
        `rounded-md px-3 py-2 ${isActive ? "bg-accent/10 text-accent" : "text-muted hover:bg-border/30 hover:text-fg"}`
      }
    >
      {props.label}
    </RRNavLink>
  );
}
