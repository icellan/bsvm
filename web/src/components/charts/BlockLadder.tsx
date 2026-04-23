import { ReactElement } from "react";
import { Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";

import { eth, hexToNumber } from "@/rpc/client";
import Tier, { tierFor } from "@/components/ui/Tier";
import Bar from "@/components/ui/Bar";

type Props = {
  executionTip: number;
  provenTip: number;
  finalizedTip: number;
  rows?: number;
  frozen?: boolean;
};

// BlockLadder renders the "recent blocks" table from the dashboard:
// one row per block in a fixed 5-column grid (number, hash + age,
// gas-fill bar, tx count, tier chip). Each cell is clickable and
// routes to the block detail page.
export default function BlockLadder({
  executionTip,
  provenTip,
  finalizedTip,
  rows = 14,
  frozen = false,
}: Props): ReactElement {
  const count = Math.max(0, Math.min(rows, executionTip + 1));
  const numbers = Array.from({ length: count }, (_, i) => executionTip - i);

  const results = useQueries({
    queries: numbers.map((n) => ({
      queryKey: ["eth_getBlockByNumber", n, true],
      queryFn: () => eth.getBlockByNumber(n, true),
      staleTime: 10_000,
    })),
  });

  if (count === 0) {
    return (
      <div
        className="mono"
        style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
      >
        No blocks yet.
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      {numbers.map((n, i) => {
        const { data } = results[i];
        const txs = Array.isArray(data?.transactions) ? data!.transactions.length : 0;
        const gasUsed = data ? hexToNumber(data.gasUsed) : 0;
        const gasLimit = data ? hexToNumber(data.gasLimit) : 1;
        const pct = gasLimit > 0 ? (gasUsed / gasLimit) * 100 : 0;
        const hash = data?.hash ?? "";
        const ts = data ? hexToNumber(data.timestamp) : 0;
        const age = ts ? relativeAge(ts) : "—";
        const t = tierFor(n, { proven: provenTip, finalized: finalizedTip, frozen });
        return (
          <Link
            key={n}
            to={`/block/${n}`}
            className="grid items-center ladder-row"
            style={{
              gridTemplateColumns: "70px 1fr 140px 64px 110px",
              gap: 12,
              padding: "8px 14px",
              borderTop: i === 0 ? "none" : "1px solid var(--ts-line)",
              color: "var(--ts-text-2)",
              textDecoration: "none",
            }}
          >
            <span
              className="mono"
              style={{ fontSize: 11, color: "var(--ts-text)" }}
            >
              #{n.toLocaleString()}
            </span>
            <span className="min-w-0 truncate">
              <span
                className="mono truncate"
                style={{ fontSize: 11, color: "var(--ts-text-2)" }}
              >
                {hash ? `${hash.slice(0, 14)}…${hash.slice(-6)}` : "—"}
              </span>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  color: "var(--ts-text-4)",
                  marginLeft: 8,
                }}
              >
                {age}
                {data?.miner ? ` · ${data.miner.slice(0, 8)}…` : ""}
              </span>
            </span>
            <div className="flex items-center gap-2">
              <Bar
                value={Math.max(0, Math.min(100, pct))}
                max={100}
                tone={pct > 95 ? "warn" : "accent"}
                height={5}
              />
              <span
                className="mono"
                style={{ fontSize: 10, color: "var(--ts-text-3)" }}
              >
                {pct.toFixed(0)}%
              </span>
            </div>
            <span
              className="mono"
              style={{ fontSize: 11, color: "var(--ts-text-2)" }}
            >
              {txs} tx
            </span>
            <span>
              <Tier tier={t} />
            </span>
          </Link>
        );
      })}
      <style>{`
        .ladder-row:hover {
          background: var(--ts-bg-2);
          color: var(--ts-text);
        }
      `}</style>
    </div>
  );
}

function relativeAge(unixSec: number): string {
  const diff = Math.max(0, Math.floor(Date.now() / 1000 - unixSec));
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  return `${Math.floor(diff / 3600)}h`;
}
