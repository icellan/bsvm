import { ReactElement, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { bsv, eth, hexToNumber } from "@/rpc/client";
import StatusDot from "@/components/ui/StatusDot";

const BUILD_HASH = typeof __BUILD_HASH__ !== "undefined" ? __BUILD_HASH__ : "dev";

// StatusBar is the persistent 28 px footer with live ticker
// counters (exec/proven/final tips), gas + mempool, uptime, build
// hash, and keyboard-hint chips. Live dot pulses while a background
// refetch is in flight.
export default function StatusBar(): ReactElement {
  const [loadedAt] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const blockNumber = useQuery({
    queryKey: ["eth_blockNumber"],
    queryFn: eth.blockNumber,
    refetchInterval: 1_000,
  });
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
    refetchInterval: 2_000,
  });
  const gas = useQuery({
    queryKey: ["eth_gasPrice"],
    queryFn: eth.gasPrice,
    refetchInterval: 4_000,
  });
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
    refetchInterval: 4_000,
  });

  const exec = health.data ? hexToNumber(health.data.executionTip) : blockNumber.data ? hexToNumber(blockNumber.data) : 0;
  const prov = health.data ? hexToNumber(health.data.provenTip) : 0;
  const fin = health.data ? hexToNumber(health.data.finalizedTip) : 0;
  const gasGwei = gas.data ? (hexToNumber(gas.data) / 1e9).toFixed(2) : "—";
  const mempool = proving.data ? hexToNumber(proving.data.pendingTxs) : 0;

  const live = blockNumber.isSuccess && !blockNumber.isError;
  const uptime = formatUptime(now - loadedAt);

  return (
    <footer
      className="fixed bottom-0 left-0 right-0 z-30 mono"
      style={{
        height: 28,
        background: "var(--ts-bg-1)",
        borderTop: "1px solid var(--ts-line)",
        fontSize: 11,
        color: "var(--ts-text-3)",
        padding: "0 14px",
      }}
    >
      <div className="h-full flex items-center gap-5 whitespace-nowrap overflow-hidden">
        <span className="flex items-center gap-1.5">
          <StatusDot tone={live ? "ok" : "bad"} pulse={live} size={7} />
          <span>{live ? "live" : "offline"}</span>
        </span>
        <Field label="exec" value={exec.toLocaleString()} />
        <Field label="proven" value={prov.toLocaleString()} tone="info" />
        <Field label="final" value={fin.toLocaleString()} tone="ok" />
        <span className="flex-1" />
        <Field label="gas" value={`${gasGwei} gwei`} />
        <Field label="mempool" value={mempool.toString()} />
        <Field label="uptime" value={uptime} />
        <Field label="build" value={BUILD_HASH} />
        <span className="flex items-center gap-1">
          <Kbd>?</Kbd>
          <span>help</span>
        </span>
        <span className="flex items-center gap-1">
          <Kbd>/</Kbd>
          <span>search</span>
        </span>
        <span className="flex items-center gap-1">
          <Kbd>⌘K</Kbd>
          <span>cmd</span>
        </span>
      </div>
    </footer>
  );
}

function Field({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "ok" | "info" | "warn";
}) {
  const color =
    tone === "ok"
      ? "var(--ts-ok)"
      : tone === "info"
      ? "var(--ts-info)"
      : tone === "warn"
      ? "var(--ts-warn)"
      : "var(--ts-text)";
  return (
    <span className="flex items-center gap-1.5">
      <span style={{ color: "var(--ts-text-4)" }}>{label}</span>
      <span style={{ color }}>{value}</span>
    </span>
  );
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd
      style={{
        fontSize: 10,
        padding: "1px 5px",
        color: "var(--ts-text-3)",
        border: "1px solid var(--ts-line-2)",
        borderRadius: 3,
      }}
    >
      {children}
    </kbd>
  );
}

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}
