import { Link, Outlet, useNavigate } from "react-router-dom";
import { FormEvent, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";

export default function Layout() {
  const { data: shardInfo } = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
  });

  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  function onSearch(e: FormEvent) {
    e.preventDefault();
    const trimmed = query.trim();
    if (!trimmed) return;
    setQuery("");
    navigate(`/search?q=${encodeURIComponent(trimmed)}`);
  }

  const frozen = shardInfo?.governance.frozen;

  return (
    <div className="flex min-h-full flex-col">
      {frozen ? (
        <div className="bg-danger/20 px-6 py-2 text-center text-sm font-bold text-danger">
          SHARD IS FROZEN — no new transactions will be accepted
        </div>
      ) : null}
      <header className="border-b border-border bg-panel/60 px-6 py-4">
        <div className="flex flex-wrap items-center gap-6">
          <Link to="/" className="font-mono text-lg font-bold text-fg">
            BSVM
          </Link>
          <nav className="flex gap-4 text-sm text-muted">
            <NavLink to="/" label="Dashboard" />
            <NavLink to="/bridge" label="Bridge" />
            <NavLink to="/network" label="Network" />
            <NavLink to="/admin" label="Admin" />
          </nav>
          <form
            className="ml-auto flex grow items-center sm:grow-0"
            onSubmit={onSearch}
          >
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="block / tx / address"
              className="w-full rounded-l-md border border-border bg-bg px-3 py-1.5 font-mono text-sm placeholder:text-muted focus:border-accent focus:outline-none sm:w-80"
            />
            <button
              type="submit"
              className="rounded-r-md border border-l-0 border-border bg-bg px-3 py-1.5 font-mono text-xs text-muted hover:text-fg"
            >
              Go
            </button>
          </form>
        </div>
        {shardInfo ? (
          <div className="mt-3 flex flex-wrap gap-4 font-mono text-xs text-muted">
            <span>
              chain{" "}
              <span className="text-fg">{hexToNumber(shardInfo.chainId)}</span>
            </span>
            <span>
              execution tip{" "}
              <span className="text-fg">
                {hexToNumber(shardInfo.executionTip)}
              </span>
            </span>
            <span>
              proven{" "}
              <span className="text-fg">
                {hexToNumber(shardInfo.provenTip)}
              </span>
            </span>
            <span>
              governance{" "}
              <span className="text-fg">{shardInfo.governance.mode}</span>
            </span>
          </div>
        ) : null}
      </header>
      <main className="flex-1 px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}

function NavLink(props: { to: string; label: string }) {
  return (
    <Link
      to={props.to}
      className="rounded px-2 py-1 text-muted hover:bg-border/40 hover:text-fg"
    >
      {props.label}
    </Link>
  );
}
