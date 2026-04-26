import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, eth, hexToNumber, formatWei } from "@/rpc/client";
import Copy from "@/components/Copy";
import { Panel, KPI, Chip, Segmented } from "@/components/ui";

type Filter = "all" | "from" | "to" | "create";

// Address — account detail. Balance + nonce KPIs, contract code when
// applicable, and an indexer-backed tx history with a direction
// filter.
export default function Address() {
  const { address } = useParams<{ address: string }>();
  const [filter, setFilter] = useState<Filter>("all");

  const balance = useQuery({
    queryKey: ["eth_getBalance", address],
    queryFn: () => eth.getBalance(address!),
    enabled: !!address,
    refetchInterval: 5_000,
  });
  const nonce = useQuery({
    queryKey: ["eth_getTransactionCount", address],
    queryFn: () => eth.getTransactionCount(address!),
    enabled: !!address,
    refetchInterval: 5_000,
  });
  const code = useQuery({
    queryKey: ["eth_getCode", address],
    queryFn: () => eth.getCode(address!),
    enabled: !!address,
  });

  const indexerStatus = useQuery({
    queryKey: ["bsv_indexerStatus"],
    queryFn: () => bsv.indexerStatus(),
    staleTime: 60_000,
  });
  const txs = useQuery({
    queryKey: ["bsv_getAddressTxs", address],
    queryFn: () => bsv.getAddressTxs(address!, { limit: 100 }),
    enabled: !!address && indexerStatus.data?.enabled === true,
    refetchInterval: 5_000,
  });

  const isContract = !!code.data && code.data !== "0x";
  const filtered = useMemo(
    () =>
      (txs.data ?? []).filter((t) =>
        filter === "all" ? true : t.direction === filter
      ),
    [txs.data, filter]
  );

  const countIn = (txs.data ?? []).filter((t) => t.direction === "to").length;
  const countCreate = (txs.data ?? []).filter(
    (t) => t.direction === "create"
  ).length;

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
          Account · {isContract ? "contract" : "EOA"}
        </div>
        <h1
          className="mt-1 mono truncate"
          style={{ fontSize: 18, fontWeight: 500 }}
          title={address}
        >
          {address}
        </h1>
        <div className="mt-2 flex gap-3 items-center">
          <Copy value={address ?? ""} label="copy address" />
          {isContract ? <Chip tone="info" dot>contract</Chip> : <Chip tone="neutral" dot>eoa</Chip>}
          {isContract && address ? (
            <Link
              to={`/address/${address}/interact`}
              className="mono"
              style={{
                fontSize: 11,
                color: "var(--ts-accent)",
                padding: "3px 8px",
                border:
                  "1px solid color-mix(in srgb, var(--ts-accent) 40%, transparent)",
                borderRadius: 4,
                textDecoration: "none",
              }}
              title="Open the read/write/event interaction panel"
            >
              interact →
            </Link>
          ) : null}
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <KPI
          label="Balance"
          value={balance.data ? formatWei(balance.data) : "0"}
          unit="wBSV"
          valueTone="accent"
        />
        <KPI
          label="Nonce"
          value={nonce.data ? hexToNumber(nonce.data).toLocaleString() : "0"}
        />
        <KPI
          label="Received"
          value={
            indexerStatus.data?.enabled ? countIn.toLocaleString() : "—"
          }
          unit="txs"
        />
        <KPI
          label="Contracts created"
          value={
            indexerStatus.data?.enabled ? countCreate.toLocaleString() : "—"
          }
        />
      </div>

      {isContract ? (
        <Panel title="Bytecode" kicker={`${((code.data?.length ?? 2) - 2) / 2} bytes`}>
          <pre
            className="mono"
            style={{
              fontSize: 11,
              padding: 10,
              background: "var(--ts-bg)",
              border: "1px solid var(--ts-line)",
              borderRadius: 4,
              maxHeight: 240,
              overflow: "auto",
              color: "var(--ts-text-3)",
              margin: 0,
              wordBreak: "break-all",
              whiteSpace: "pre-wrap",
            }}
          >
            {code.data}
          </pre>
        </Panel>
      ) : null}

      <Panel
        title="Transactions"
        kicker={
          indexerStatus.data?.enabled
            ? `indexer up · last ${(txs.data ?? []).length} entries`
            : "indexer disabled"
        }
        meta={
          indexerStatus.data?.enabled ? (
            <Segmented<Filter>
              size="sm"
              value={filter}
              onChange={setFilter}
              options={[
                { value: "all", label: "All" },
                { value: "from", label: "Sent" },
                { value: "to", label: "Received" },
                { value: "create", label: "Create" },
              ]}
            />
          ) : undefined
        }
        padded={false}
      >
        {indexerStatus.data && !indexerStatus.data.enabled ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
          >
            Indexer disabled on this node. Set{" "}
            <code style={{ color: "var(--ts-accent)" }}>
              BSVM_INDEXER_ENABLED=true
            </code>{" "}
            or flip <code>indexer.enabled</code> in the node TOML to populate
            this view.
          </div>
        ) : txs.isLoading ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}>Loading…</div>
        ) : txs.error ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)", padding: 14 }}>
            Failed to load: {(txs.error as Error).message}
          </div>
        ) : filtered.length === 0 ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
          >
            No transactions.{" "}
            <span style={{ color: "var(--ts-text-4)" }}>
              (Indexer only covers blocks emitted since it came up.)
            </span>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table
              className="w-full text-left"
              style={{ borderCollapse: "collapse" }}
            >
              <thead>
                <tr>
                  {["block", "tx hash", "direction", "counterparty", "status"].map((h, i) => (
                    <th
                      key={i}
                      className="mono"
                      style={{
                        fontSize: 10,
                        letterSpacing: "0.08em",
                        textTransform: "uppercase",
                        color: "var(--ts-text-3)",
                        fontWeight: 500,
                        padding: "8px 14px",
                        borderBottom: "1px solid var(--ts-line)",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((t) => {
                  const dirTone =
                    t.direction === "from"
                      ? ("warn" as const)
                      : t.direction === "to"
                      ? ("ok" as const)
                      : ("info" as const);
                  return (
                    <tr
                      key={t.txHash}
                      style={{ borderTop: "1px solid var(--ts-line)" }}
                      className="row-hover"
                    >
                      <td style={{ padding: "6px 14px" }}>
                        <Link
                          to={`/block/${hexToNumber(t.blockNumber)}`}
                          className="mono"
                          style={{ fontSize: 11, color: "var(--ts-accent)" }}
                        >
                          #{hexToNumber(t.blockNumber).toLocaleString()}
                        </Link>
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        <Link
                          to={`/tx/${t.txHash}`}
                          className="mono"
                          style={{ fontSize: 11, color: "var(--ts-accent)" }}
                        >
                          {t.txHash.slice(0, 10)}…{t.txHash.slice(-6)}
                        </Link>
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        <Chip tone={dirTone}>{t.direction}</Chip>
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        {t.otherParty ? (
                          <Link
                            to={`/address/${t.otherParty}`}
                            className="mono"
                            style={{ fontSize: 11, color: "var(--ts-text-2)" }}
                          >
                            {t.otherParty.slice(0, 8)}…{t.otherParty.slice(-4)}
                          </Link>
                        ) : (
                          <span style={{ color: "var(--ts-text-4)" }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        {hexToNumber(t.status) === 1 ? (
                          <Chip tone="ok" dot>ok</Chip>
                        ) : (
                          <Chip tone="bad" dot>fail</Chip>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <style>{`
              tr.row-hover:hover { background: var(--ts-bg-2); color: var(--ts-text); }
            `}</style>
          </div>
        )}
      </Panel>
    </div>
  );
}
