import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, eth, hexToNumber } from "@/rpc/client";
import Copy, { shorten } from "@/components/Copy";
import { Panel, KV, Tier, tierFor, Chip } from "@/components/ui";
import Timeline, { Step } from "@/components/ui/Timeline";

// Transaction — single-tx detail. Envelope KV + confirmation
// pipeline timeline + raw input + logs table.
export default function Transaction() {
  const { hash } = useParams<{ hash: string }>();

  const tx = useQuery({
    queryKey: ["tx", hash],
    queryFn: () => eth.getTransactionByHash(hash!),
  });
  const receipt = useQuery({
    queryKey: ["receipt", hash],
    queryFn: () => eth.getTransactionReceipt(hash!),
    enabled: !!hash,
  });
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
    refetchInterval: 3_000,
  });
  const shard = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
    refetchInterval: 5_000,
  });

  if (tx.isLoading) return <LoadingRow label="Loading transaction…" />;
  if (!tx.data) return <LoadingRow label="Transaction not found." />;

  const status =
    receipt.data?.status === "0x1"
      ? "success"
      : receipt.data?.status === "0x0"
      ? "failed"
      : "pending";

  const blockNum = tx.data.blockNumber ? hexToNumber(tx.data.blockNumber) : 0;
  const prov = health.data ? hexToNumber(health.data.provenTip) : 0;
  const fin = health.data ? hexToNumber(health.data.finalizedTip) : 0;
  const frozen = !!shard.data?.governance.frozen;
  const tier = blockNum
    ? tierFor(blockNum, { proven: prov, finalized: fin, frozen })
    : "speculative";

  const pipeline: Step[] = [
    {
      label: "Broadcast",
      state: "ok",
    },
    {
      label: "Included",
      state: blockNum > 0 ? "ok" : "progress",
      detail: blockNum > 0 ? `block #${blockNum.toLocaleString()}` : "awaiting block",
    },
    {
      label: "Assembled into batch",
      state: blockNum > 0 ? "ok" : "pending",
    },
    {
      label: "Proof generated",
      state: tier === "proven" || tier === "finalized" ? "ok" : blockNum > 0 ? "progress" : "pending",
    },
    {
      label: "Covenant advanced",
      state: tier === "finalized" ? "ok" : tier === "proven" ? "progress" : "pending",
    },
    {
      label: "BSV finalized",
      state: tier === "finalized" ? "ok" : "pending",
      detail: tier === "finalized" ? "6+ confirmations" : "waiting for 6 BSV confs",
    },
  ];

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
          Transaction · status{" "}
          <span
            style={{
              color:
                status === "success"
                  ? "var(--ts-ok)"
                  : status === "failed"
                  ? "var(--ts-bad)"
                  : "var(--ts-warn)",
            }}
          >
            {status}
          </span>
        </div>
        <h1
          className="mt-1 mono truncate"
          style={{ fontSize: 18, fontWeight: 500, color: "var(--ts-text)" }}
          title={tx.data.hash}
        >
          {tx.data.hash}
        </h1>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel title="Envelope" kicker="Tx fields">
          <KV
            items={[
              {
                label: "block",
                value: tx.data.blockNumber ? (
                  <span className="flex items-center gap-2">
                    <Link to={`/block/${blockNum}`} className="mono" style={{ color: "var(--ts-accent)" }}>
                      #{blockNum.toLocaleString()}
                    </Link>
                    <Tier tier={tier} />
                  </span>
                ) : (
                  <Chip tone="warn" dot>pending</Chip>
                ),
                mono: true,
              },
              {
                label: "nonce",
                value: hexToNumber(tx.data.nonce).toString(),
                mono: true,
              },
              {
                label: "from",
                value: (
                  <Link to={`/address/${tx.data.from}`} className="mono" style={{ color: "var(--ts-accent)" }}>
                    <Copy value={tx.data.from} label={shorten(tx.data.from)} />
                  </Link>
                ),
                mono: true,
              },
              {
                label: "to",
                value: tx.data.to ? (
                  <Link to={`/address/${tx.data.to}`} className="mono" style={{ color: "var(--ts-accent)" }}>
                    <Copy value={tx.data.to} label={shorten(tx.data.to)} />
                  </Link>
                ) : (
                  <Chip tone="accent">contract create</Chip>
                ),
                mono: true,
              },
              {
                label: "value",
                value: `${hexToNumber(tx.data.value).toLocaleString()} wei`,
                mono: true,
              },
              {
                label: "gas",
                value: hexToNumber(tx.data.gas).toLocaleString(),
                mono: true,
              },
              {
                label: "gas price",
                value: tx.data.gasPrice
                  ? `${hexToNumber(tx.data.gasPrice).toLocaleString()} wei`
                  : "—",
                mono: true,
              },
              {
                label: "gas used",
                value: receipt.data
                  ? hexToNumber(receipt.data.gasUsed).toLocaleString()
                  : "—",
                mono: true,
              },
            ]}
            columns={2}
          />
        </Panel>

        <Panel title="Confirmation pipeline" kicker="Proof stages">
          <Timeline steps={pipeline} />
        </Panel>
      </div>

      {tx.data.input && tx.data.input !== "0x" ? (
        <Panel title="Input data" kicker={`${(tx.data.input.length - 2) / 2} bytes`}>
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
              color: "var(--ts-text-2)",
              margin: 0,
              wordBreak: "break-all",
              whiteSpace: "pre-wrap",
            }}
          >
            <span style={{ color: "var(--ts-text-4)" }}>
              {"// selector " + tx.data.input.slice(0, 10)}
              {"\n"}
            </span>
            <span style={{ color: "var(--ts-accent)" }}>
              {tx.data.input.slice(0, 10)}
            </span>
            <span>{tx.data.input.slice(10)}</span>
          </pre>
        </Panel>
      ) : null}

      {receipt.data && receipt.data.logs.length > 0 ? (
        <Panel title="Event logs" kicker={`${receipt.data.logs.length} entries`} padded={false}>
          <table
            className="w-full text-left"
            style={{ borderCollapse: "collapse" }}
          >
            <thead>
              <tr>
                {["#", "address", "topic[0]", "data"].map((h, i) => (
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
              {receipt.data.logs.map((log, i) => (
                <tr
                  key={i}
                  style={{ borderTop: "1px solid var(--ts-line)" }}
                >
                  <td className="mono" style={{ padding: "6px 14px", fontSize: 11, color: "var(--ts-text-3)" }}>{i}</td>
                  <td style={{ padding: "6px 14px" }}>
                    <Link to={`/address/${log.address}`} className="mono" style={{ fontSize: 11, color: "var(--ts-accent)" }}>
                      {shorten(log.address)}
                    </Link>
                  </td>
                  <td className="mono" style={{ padding: "6px 14px", fontSize: 11, color: "var(--ts-text-2)" }}>
                    {log.topics[0] ? shorten(log.topics[0]) : "—"}
                  </td>
                  <td className="mono truncate" style={{ padding: "6px 14px", fontSize: 11, color: "var(--ts-text-3)", maxWidth: 400 }}>
                    {log.data}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </div>
  );
}

function LoadingRow({ label }: { label: string }) {
  return (
    <div
      className="mono"
      style={{ fontSize: 12, color: "var(--ts-text-3)", padding: 14 }}
    >
      {label}
    </div>
  );
}
