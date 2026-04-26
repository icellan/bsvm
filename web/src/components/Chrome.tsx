import { ReactElement } from "react";
import { Link, NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import Pill from "@/components/ui/Pill";
import SearchBar from "@/components/SearchBar";
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

  const { theme, toggle } = useTheme();

  const chainHex = shard?.chainId ?? "0x0";
  const chainDec = hexToNumber(chainHex);
  const peers = health ? hexToNumber(health.peerCount) : 0;
  const gov = shard?.governance;
  // For multisig shards show the M-of-N threshold; otherwise show the
  // governance mode name (none / single_key). Label the pill as "gov"
  // so "gov none" reads as "no governance keys", not as "no quorum".
  const govLabel =
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

        <div className="ml-auto chrome-search" style={{ minWidth: 0 }}>
          <SearchBar variant="compact" />
        </div>

        <div className="chrome-pills flex items-center gap-2">
          <Pill tone="neutral">
            <span style={{ color: "var(--ts-text-3)" }}>chain</span>
            <span style={{ color: "var(--ts-text)" }} className="mono">
              {chainDec || "—"}
            </span>
          </Pill>
          <Link
            to="/network"
            title="Open Network page"
            style={{ textDecoration: "none" }}
          >
            <Pill tone={peers > 0 ? "ok" : "warn"} dot>
              <span style={{ color: "var(--ts-text-3)" }}>peers</span>
              <span style={{ color: "var(--ts-text)" }} className="mono">
                {peers}
              </span>
            </Pill>
          </Link>
          <Pill tone="info">
            <span
              style={{ color: "var(--ts-text-3)" }}
              title="Governance mode (or M/N threshold for multisig)"
            >
              gov
            </span>
            <span style={{ color: "var(--ts-text)" }} className="mono">
              {govLabel}
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
