import { useQuery } from "@tanstack/react-query";

import { adminRPC } from "@/pages/admin/rpc";
import { Panel, Chip } from "@/components/ui";

type AdminConfig = {
  chainId: number;
  minGasPriceWei: string;
  maxBatchSize: number;
  maxBatchFlushMs: number;
  maxSpeculativeDepth: number;
  proveMode: string;
  restartRequired: boolean;
};

type Row = {
  key: string;
  value: string;
  scope: "hot" | "restart";
  description: string;
};

// Admin Config — runtime configuration table with hot / restart
// scope chips. Hot fields apply live; restart fields need a node
// reboot. Source of truth is `admin_getConfig`.
export default function AdminConfig() {
  const config = useQuery({
    queryKey: ["admin_getConfig"],
    queryFn: () => adminRPC<AdminConfig>("admin_getConfig"),
    refetchInterval: 30_000,
  });

  const rows: Row[] = config.data
    ? [
        {
          key: "chainId",
          value: String(config.data.chainId),
          scope: "restart",
          description: "EVM chain id bound into every tx signature.",
        },
        {
          key: "proveMode",
          value: config.data.proveMode || "—",
          scope: "hot",
          description: "live | paused | ondemand.",
        },
        {
          key: "minGasPriceWei",
          value: config.data.minGasPriceWei,
          scope: "hot",
          description: "Minimum gas price admitted into the mempool.",
        },
        {
          key: "maxBatchSize",
          value: String(config.data.maxBatchSize),
          scope: "hot",
          description: "Max txs per batch before forced flush.",
        },
        {
          key: "maxBatchFlushMs",
          value: String(config.data.maxBatchFlushMs),
          scope: "hot",
          description: "Max batch idle time before forced flush.",
        },
        {
          key: "maxSpeculativeDepth",
          value: String(config.data.maxSpeculativeDepth),
          scope: "restart",
          description: "Max unproven blocks before batcher pause.",
        },
      ]
    : [];

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
          Admin · config
        </div>
        <h1
          className="mt-1"
          style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Runtime configuration
        </h1>
      </div>

      <Panel
        title="Runtime keys"
        kicker="admin_getConfig · live"
        padded={false}
      >
        {config.isLoading ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
          >
            Loading…
          </div>
        ) : rows.length === 0 ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-bad)", padding: 14 }}
          >
            Failed to load: {String(config.error)}
          </div>
        ) : (
          <table
            className="w-full text-left"
            style={{ borderCollapse: "collapse" }}
          >
            <thead>
              <tr>
                {["key", "value", "scope", "description"].map((h) => (
                  <th
                    key={h}
                    className="mono"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      color: "var(--ts-text-3)",
                      fontWeight: 500,
                      padding: "10px 14px",
                      borderBottom: "1px solid var(--ts-line)",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.key}
                  style={{ borderTop: "1px solid var(--ts-line)" }}
                >
                  <td
                    className="mono"
                    style={{
                      padding: "8px 14px",
                      fontSize: 11,
                      color: "var(--ts-accent)",
                    }}
                  >
                    {r.key}
                  </td>
                  <td
                    className="mono"
                    style={{
                      padding: "8px 14px",
                      fontSize: 11,
                      color: "var(--ts-text)",
                    }}
                  >
                    {r.value}
                  </td>
                  <td style={{ padding: "8px 14px" }}>
                    <Chip tone={r.scope === "hot" ? "ok" : "warn"}>
                      {r.scope}
                    </Chip>
                  </td>
                  <td
                    style={{
                      padding: "8px 14px",
                      fontSize: 11,
                      color: "var(--ts-text-3)",
                    }}
                  >
                    {r.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {config.data?.restartRequired ? (
        <Panel title="Pending change" kicker="Restart required" statusDot="warn">
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-warn)" }}
          >
            A configuration change is pending that requires a node restart.
            Live reload is tracked as a follow-up.
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
