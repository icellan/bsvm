import { useQuery } from "@tanstack/react-query";

import { adminRPC } from "@/pages/admin/rpc";
import { bsv, hexToNumber } from "@/rpc/client";
import { Panel, KPI, KV, Bar } from "@/components/ui";

type AdminConfig = {
  chainId: number;
  minGasPriceWei: string;
  maxBatchSize: number;
  maxBatchFlushMs: number;
  maxSpeculativeDepth: number;
  proveMode: string;
  restartRequired: boolean;
};

type BridgeHealth = {
  mismatch: boolean;
  totalLocked: string;
  totalSupply: string;
  lastScanned: number;
  note?: string;
};

// Admin Dashboard — operator-facing KPIs, a runtime-config pre, bridge
// reconciliation KV, and an audit-log placeholder panel.
export default function AdminDashboard() {
  const config = useQuery({
    queryKey: ["admin_getConfig"],
    queryFn: () => adminRPC<AdminConfig>("admin_getConfig"),
    refetchInterval: 30_000,
  });
  const bridge = useQuery({
    queryKey: ["admin_bridgeHealth"],
    queryFn: () => adminRPC<BridgeHealth>("admin_bridgeHealth"),
    refetchInterval: 15_000,
  });
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
    refetchInterval: 3_000,
  });

  const avgMs = proving.data ? hexToNumber(proving.data.averageTimeMs) : 0;

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div>
        <div
          className="mono"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-text-3)",
          }}
        >
          Admin · dashboard
        </div>
        <h1
          className="mt-1"
          style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Shard control
        </h1>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <KPI label="Pending proposals" value="0" />
        <KPI
          label="Avg proof"
          value={(avgMs / 1000).toFixed(1)}
          unit="s"
          valueTone="warn"
        />
        <KPI
          label="Bridge delta"
          value={bridge.data ? (bridge.data.mismatch ? "mismatch" : "in sync") : "—"}
          valueTone={bridge.data?.mismatch ? "bad" : "ok"}
        />
        <KPI label="Uptime" value="—" unit="hrs" />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel title="Runtime config" kicker="admin_getConfig" statusDot="ok">
          {config.data ? (
            <pre
              className="mono"
              style={{
                fontSize: 11,
                padding: 10,
                background: "var(--ts-bg)",
                border: "1px solid var(--ts-line)",
                borderRadius: 4,
                maxHeight: 260,
                overflow: "auto",
                margin: 0,
                color: "var(--ts-text-2)",
                lineHeight: 1.55,
              }}
            >
              {colorJson(config.data)}
            </pre>
          ) : config.error ? (
            <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)" }}>
              {String(config.error)}
            </div>
          ) : (
            <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>Loading…</div>
          )}
        </Panel>

        <Panel title="Bridge reconciliation" kicker="admin_bridgeHealth" statusDot={bridge.data?.mismatch ? "bad" : "ok"}>
          {bridge.data ? (
            <>
              <KV
                items={[
                  { label: "total locked", value: bridge.data.totalLocked, mono: true },
                  { label: "total supply", value: bridge.data.totalSupply, mono: true },
                  { label: "mismatch", value: bridge.data.mismatch ? "yes" : "no", mono: true },
                  { label: "last scanned", value: String(bridge.data.lastScanned), mono: true },
                ]}
                columns={2}
              />
              <div style={{ marginTop: 12 }}>
                <Bar value={100} max={100} tone={bridge.data.mismatch ? "bad" : "ok"} />
                <div
                  className="mono"
                  style={{ fontSize: 10, color: "var(--ts-text-4)", marginTop: 4 }}
                >
                  {bridge.data.note ?? "reserve in sync · 1:1 peg"}
                </div>
              </div>
            </>
          ) : bridge.error ? (
            <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)" }}>
              {String(bridge.error)}
            </div>
          ) : (
            <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>Loading…</div>
          )}
        </Panel>
      </div>

      <Panel title="Recent actions" kicker="Audit trail">
        <div
          className="mono"
          style={{ fontSize: 11, color: "var(--ts-text-3)", padding: "4px 0" }}
        >
          No actions recorded.{" "}
          <span style={{ color: "var(--ts-text-4)" }}>
            (Audit RPC pending — tracked as a spec-15 follow-up.)
          </span>
        </div>
      </Panel>
    </div>
  );
}

function colorJson(v: unknown): React.ReactNode {
  const s = JSON.stringify(v, null, 2);
  const parts: React.ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:\s*)?|(-?\d+\.?\d*(?:[eE][+-]?\d+)?)|(true|false|null)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(s)) !== null) {
    if (m.index > last) parts.push(s.slice(last, m.index));
    if (m[1]) {
      if (m[2]) {
        parts.push(
          <span key={key++} style={{ color: "var(--ts-info)" }}>
            {m[1]}
          </span>
        );
        parts.push(m[2]);
      } else {
        parts.push(
          <span key={key++} style={{ color: "var(--ts-ok)" }}>
            {m[1]}
          </span>
        );
      }
    } else if (m[3]) {
      parts.push(
        <span key={key++} style={{ color: "var(--ts-warn)" }}>
          {m[3]}
        </span>
      );
    } else if (m[4]) {
      parts.push(
        <span key={key++} style={{ color: "var(--ts-accent)" }}>
          {m[4]}
        </span>
      );
    }
    last = re.lastIndex;
  }
  if (last < s.length) parts.push(s.slice(last));
  return parts;
}
