import { FormEvent, ReactElement, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import Pill from "@/components/ui/Pill";
import { useTheme } from "@/state/theme";

// Chrome is the mission-control top bar: brand + nav + search + right
// cluster (chain/peer/quorum pills + theme toggle). Sticky at the top
// of the viewport; 48 px min-height. Media queries hide the search +
// pills at narrow widths so the nav stays reachable.
export default function Chrome(): ReactElement {
  const { data: shard } = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
    refetchInterval: 3_000,
  });
  const { data: health } = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
    refetchInterval: 2_000,
  });

  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  function onSearch(e: FormEvent) {
    e.preventDefault();
    const t = query.trim();
    if (!t) return;
    setQuery("");
    navigate(`/search?q=${encodeURIComponent(t)}`);
  }

  const { theme, toggle } = useTheme();

  const chainHex = shard?.chainId ?? "0x0";
  const chainDec = hexToNumber(chainHex);
  const peers = health ? hexToNumber(health.peerCount) : 0;
  const gov = shard?.governance;
  const quorum =
    gov && gov.threshold !== undefined && gov.keyCount !== undefined
      ? `${hexToNumber(gov.threshold)}/${hexToNumber(gov.keyCount)}`
      : gov?.mode ?? "—";

  return (
    <header
      className="sticky top-0 z-20 w-full"
      style={{
        minHeight: 48,
        background: "var(--ts-bg-1)",
        borderBottom: "1px solid var(--ts-line)",
        backdropFilter: "blur(4px)",
      }}
    >
      <div
        className="flex items-center gap-5"
        style={{ padding: "8px 20px", minHeight: 48 }}
      >
        <Link
          to="/"
          className="flex items-center gap-2 shrink-0"
          style={{ color: "var(--ts-text)" }}
        >
          <span
            aria-hidden
            style={{
              width: 10,
              height: 10,
              background: "var(--ts-accent)",
              boxShadow: "0 0 10px var(--ts-accent)",
              display: "inline-block",
            }}
          />
          <span
            className="mono"
            style={{
              fontSize: 13,
              fontWeight: 600,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
            }}
          >
            BSVM
          </span>
        </Link>

        <nav
          className="flex items-center gap-1 overflow-x-auto scrollbar-none"
          style={{ minWidth: 0 }}
        >
          <ChromeLink to="/" end label="Overview" />
          <ChromeLink to="/bridge" label="Bridge" />
          <ChromeLink to="/network" label="Network" />
          <ChromeLink to="/admin" label="Admin" matchPrefix="/admin" />
        </nav>

        <form
          onSubmit={onSearch}
          className="ml-auto chrome-search flex items-center gap-2"
          style={{ minWidth: 0 }}
        >
          <div
            className="flex items-center gap-2"
            style={{
              background: "var(--ts-bg-2)",
              border: "1px solid var(--ts-line-2)",
              borderRadius: 4,
              padding: "4px 8px",
              minWidth: 280,
            }}
          >
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="block · tx · address"
              className="mono"
              style={{
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--ts-text)",
                fontSize: 11,
                flex: 1,
                minWidth: 0,
              }}
            />
            <kbd
              className="mono"
              style={{
                fontSize: 10,
                padding: "1px 5px",
                color: "var(--ts-text-3)",
                border: "1px solid var(--ts-line-2)",
                borderRadius: 3,
              }}
            >
              /
            </kbd>
          </div>
        </form>

        <div className="chrome-pills flex items-center gap-2">
          <Pill tone="neutral">
            <span style={{ color: "var(--ts-text-3)" }}>chain</span>
            <span style={{ color: "var(--ts-text)" }} className="mono">
              {chainDec || "—"}
            </span>
          </Pill>
          <Pill tone={peers > 0 ? "ok" : "warn"} dot>
            <span style={{ color: "var(--ts-text-3)" }}>peers</span>
            <span style={{ color: "var(--ts-text)" }} className="mono">
              {peers}
            </span>
          </Pill>
          <Pill tone="info">
            <span style={{ color: "var(--ts-text-3)" }}>quorum</span>
            <span style={{ color: "var(--ts-text)" }} className="mono">
              {quorum}
            </span>
          </Pill>
        </div>

        <button
          onClick={toggle}
          className="mono"
          title="Toggle theme"
          aria-label="Toggle theme"
          style={{
            background: "var(--ts-bg-2)",
            border: "1px solid var(--ts-line-2)",
            color: "var(--ts-text-2)",
            borderRadius: 4,
            padding: "4px 10px",
            fontSize: 11,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          {theme === "dark" ? "◐ Mission" : "◑ Light"}
        </button>
      </div>

      <style>{`
        @media (max-width: 1100px) {
          header .chrome-search { display: none; }
        }
        @media (max-width: 820px) {
          header .chrome-pills { display: none; }
        }
      `}</style>
    </header>
  );
}

function ChromeLink(props: {
  to: string;
  label: string;
  end?: boolean;
  matchPrefix?: string;
}) {
  return (
    <NavLink
      to={props.to}
      end={props.end}
      className={({ isActive }) => {
        const prefixActive =
          !isActive &&
          !!props.matchPrefix &&
          typeof window !== "undefined" &&
          window.location.pathname.startsWith(props.matchPrefix);
        return (
          "chrome-nav-link " + (isActive || prefixActive ? "is-active" : "")
        );
      }}
      style={({ isActive }) => {
        const prefixActive =
          !isActive &&
          !!props.matchPrefix &&
          typeof window !== "undefined" &&
          window.location.pathname.startsWith(props.matchPrefix);
        const on = isActive || prefixActive;
        return {
          padding: "6px 10px",
          fontSize: 12,
          borderRadius: 4,
          color: on ? "var(--ts-text)" : "var(--ts-text-3)",
          background: on ? "var(--ts-bg-2)" : "transparent",
          whiteSpace: "nowrap",
          letterSpacing: "0.02em",
        };
      }}
    >
      {props.label}
    </NavLink>
  );
}
