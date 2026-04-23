import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, eth, hexToNumber } from "@/rpc/client";
import Copy, { shorten } from "@/components/Copy";
import { Panel, KV, Chip, Bar, Button, Tier, tierFor } from "@/components/ui";

// Block — single-block detail. Header KV grid, gas + tx stats + proof
// trajectory strip, full transactions table.
export default function Block() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const isHash = id?.startsWith("0x") && id.length === 66;
  const blockNum = isHash ? null : Number(id);

  const block = useQuery({
    queryKey: ["block", id],
    queryFn: () =>
      isHash ? eth.getBlockByHash(id!) : eth.getBlockByNumber(blockNum ?? 0),
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
  const confirm = useQuery({
    queryKey: ["bsv_getConfirmationStatus", blockNum ?? -1],
    queryFn: () => bsv.getConfirmationStatus(blockNum ?? 0),
    enabled: !isHash && blockNum !== null,
    refetchInterval: 5_000,
  });

  if (block.isLoading)
    return <LoadingRow label="Loading block…" />;
  if (!block.data) return <LoadingRow label="Block not found." />;

  const n = hexToNumber(block.data.number);
  const prov = health.data ? hexToNumber(health.data.provenTip) : 0;
  const fin = health.data ? hexToNumber(health.data.finalizedTip) : 0;
  const frozen = !!shard.data?.governance.frozen;
  const t = tierFor(n, { proven: prov, finalized: fin, frozen });
  const txs = Array.isArray(block.data.transactions)
    ? block.data.transactions
    : [];
  const gasUsed = hexToNumber(block.data.gasUsed);
  const gasLimit = hexToNumber(block.data.gasLimit);
  const gasPct = gasLimit > 0 ? (gasUsed / gasLimit) * 100 : 0;

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="flex items-end justify-between flex-wrap gap-3">
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
            Block · detail
          </div>
          <h1
            className="mt-1 mono"
            style={{ fontSize: 26, fontWeight: 500 }}
          >
            <span style={{ color: "var(--ts-accent)" }}>
              #{n.toLocaleString()}
            </span>
            <span style={{ marginLeft: 10, display: "inline-block" }}>
              <Tier tier={t} />
            </span>
          </h1>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => nav(`/block/${n - 1}`)} disabled={n <= 0}>
            ← prev
          </Button>
          <Button onClick={() => nav(`/block/${n + 1}`)}>next →</Button>
          <Button variant="accent-ghost">Raw JSON</Button>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel title="Header" kicker="Canonical envelope">
          <KV
            items={[
              {
                label: "hash",
                value: <Copy value={block.data.hash} label={shorten(block.data.hash)} />,
                mono: true,
                wide: true,
              },
              {
                label: "parent",
                value: (
                  <Link to={`/block/${n - 1}`} style={{ color: "var(--ts-accent)" }}>
                    <Copy value={block.data.parentHash} label={shorten(block.data.parentHash)} />
                  </Link>
                ),
                mono: true,
                wide: true,
              },
              {
                label: "coinbase",
                value: (
                  <Link to={`/address/${block.data.miner}`} style={{ color: "var(--ts-accent)" }}>
                    {shorten(block.data.miner)}
                  </Link>
                ),
                mono: true,
              },
              {
                label: "timestamp",
                // L2 timestamps are deterministic: parentTs + interval (see
                // pkg/overlay/process.go). On a freshly genesis'd shard the
                // first few blocks land in 1970 because the genesis block
                // starts at t=0 — that's correct, not a bug. Show both the
                // raw unix seconds and the ISO form so operators see the
                // convention.
                value: (() => {
                  const ts = hexToNumber(block.data.timestamp);
                  const iso = new Date(ts * 1000).toISOString().replace("T", " ").replace(".000Z", "Z");
                  return `${iso}  (t=${ts}s)`;
                })(),
                mono: true,
                wide: true,
              },
              {
                label: "state root",
                value: <Copy value={block.data.stateRoot} label={shorten(block.data.stateRoot)} />,
                mono: true,
                wide: true,
              },
              {
                label: "receipts root",
                value: <Copy value={block.data.receiptsRoot} label={shorten(block.data.receiptsRoot)} />,
                mono: true,
                wide: true,
              },
            ]}
            columns={2}
          />
        </Panel>

        <Panel title="Stats" kicker="Execution metrics">
          <KV
            items={[
              { label: "txns", value: txs.length.toLocaleString(), mono: true },
              { label: "gas used", value: gasUsed.toLocaleString(), mono: true },
              { label: "gas limit", value: gasLimit.toLocaleString(), mono: true },
              { label: "fill", value: `${gasPct.toFixed(1)}%`, mono: true },
            ]}
            columns={4}
          />
          <div style={{ marginTop: 10 }}>
            <div
              className="mono"
              style={{
                fontSize: 10,
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: "var(--ts-text-3)",
                marginBottom: 4,
              }}
            >
              gas fill
            </div>
            <Bar value={gasPct} max={100} tone={gasPct > 95 ? "warn" : "accent"} />
          </div>
          <div style={{ marginTop: 16 }}>
            <div
              className="mono"
              style={{
                fontSize: 10,
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: "var(--ts-text-3)",
                marginBottom: 6,
              }}
            >
              lifecycle
            </div>
            <LifecycleStrip tier={t} confirm={confirm.data} />
          </div>
        </Panel>
      </div>

      <Panel title="BSV settlement" kicker="Covenant advance">
        <BsvSettlement data={confirm.data} loading={confirm.isLoading} />
      </Panel>

      <Panel title="Transactions" kicker={`${txs.length} in block`} padded={false}>
        {txs.length === 0 ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
          >
            No transactions.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table
              className="w-full text-left"
              style={{ borderCollapse: "collapse" }}
            >
              <thead>
                <tr>
                  {["#", "hash", "from", "to", "value", "type"].map((h, i) => (
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
                {txs.map((tx, i) => {
                  if (typeof tx === "string") {
                    return (
                      <tr key={tx}>
                        <td className="mono" style={{ padding: "6px 14px", color: "var(--ts-text-3)" }}>{i}</td>
                        <td style={{ padding: "6px 14px" }} colSpan={5}>
                          <Link to={`/tx/${tx}`} className="mono" style={{ color: "var(--ts-accent)" }}>
                            {shorten(tx)}
                          </Link>
                        </td>
                      </tr>
                    );
                  }
                  return (
                    <tr
                      key={tx.hash}
                      className="row-hover"
                      style={{ borderTop: "1px solid var(--ts-line)" }}
                    >
                      <td className="mono" style={{ padding: "6px 14px", color: "var(--ts-text-3)", fontSize: 11 }}>{i}</td>
                      <td style={{ padding: "6px 14px" }}>
                        <Link to={`/tx/${tx.hash}`} className="mono" style={{ fontSize: 11, color: "var(--ts-accent)" }}>
                          {shorten(tx.hash)}
                        </Link>
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        <Link to={`/address/${tx.from}`} className="mono" style={{ fontSize: 11, color: "var(--ts-text-2)" }}>
                          {shorten(tx.from)}
                        </Link>
                      </td>
                      <td style={{ padding: "6px 14px" }}>
                        {tx.to ? (
                          <Link to={`/address/${tx.to}`} className="mono" style={{ fontSize: 11, color: "var(--ts-text-2)" }}>
                            {shorten(tx.to)}
                          </Link>
                        ) : (
                          <Chip tone="accent">create</Chip>
                        )}
                      </td>
                      <td className="mono" style={{ padding: "6px 14px", fontSize: 11, color: "var(--ts-text-2)" }}>
                        {hexToNumber(tx.value).toLocaleString()}
                      </td>
                      <td className="mono" style={{ padding: "6px 14px", fontSize: 11, color: "var(--ts-text-3)" }}>
                        {tx.type ? `0x${hexToNumber(tx.type).toString(16)}` : "0x0"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <style>{`
              tr.row-hover:hover { background: var(--ts-bg-2); }
            `}</style>
          </div>
        )}
      </Panel>
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

type ConfirmData = {
  l2BlockNumber: string;
  bsvTxId: string;
  confirmations: string;
  confirmed: boolean;
  safe: boolean;
  finalized: boolean;
};

// BsvSettlement panel: shows which BSV covenant-advance tx settled
// this L2 block, with confirmation / safe / finalized flags. Empty
// bsvTxId means the advance hasn't been broadcast yet (or the node
// never observed its confirmation — e.g. this is a peer-replayed
// block on a follower node).
function BsvSettlement({
  data,
  loading,
}: {
  data: ConfirmData | undefined;
  loading: boolean;
}) {
  if (loading)
    return (
      <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
        Loading…
      </div>
    );
  if (!data)
    return (
      <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
        No settlement data.
      </div>
    );
  const confs = hexToNumber(data.confirmations);
  const noAdvance = !data.bsvTxId;

  return (
    <KV
      items={[
        {
          label: "bsv txid",
          value: noAdvance ? (
            <span style={{ color: "var(--ts-text-3)" }}>—</span>
          ) : (
            <Copy value={data.bsvTxId} label={shorten("0x" + data.bsvTxId)} />
          ),
          mono: true,
          wide: true,
        },
        {
          label: "confirmations",
          value: (
            <span style={{ color: confs >= 6 ? "var(--ts-ok)" : confs > 0 ? "var(--ts-info)" : "var(--ts-text-3)" }}>
              {noAdvance ? "—" : confs}
            </span>
          ),
          mono: true,
        },
        {
          label: "status",
          value: (
            <div className="flex gap-1" style={{ flexWrap: "wrap" }}>
              <Chip tone={data.confirmed ? "ok" : "neutral"}>
                {data.confirmed ? "confirmed" : "pending"}
              </Chip>
              <Chip tone={data.safe ? "ok" : "neutral"}>
                {data.safe ? "safe" : "speculative"}
              </Chip>
              <Chip tone={data.finalized ? "ok" : "neutral"}>
                {data.finalized ? "finalized" : "not-final"}
              </Chip>
            </div>
          ),
        },
      ]}
      columns={2}
    />
  );
}

// LifecycleStrip: 4-step lifecycle indicator (assembled → proof-ok →
// covenant → confirmed). Replaces the purely-cosmetic ProofTrajectory
// mockup. Stage is derived from the confirmation RPC + the block's
// tier; a stage is "active" when the block has reached it.
function LifecycleStrip({
  tier,
  confirm,
}: {
  tier: string;
  confirm: ConfirmData | undefined;
}) {
  const hasBsv = !!confirm?.bsvTxId;
  const isConfirmed = !!confirm?.confirmed;
  const isFinalized = !!confirm?.finalized;

  const stages = [
    { key: "assembled", label: "assembled", active: true },
    { key: "proof-ok", label: "proof-ok", active: tier !== "speculative" || hasBsv },
    { key: "covenant", label: "on-chain", active: hasBsv },
    { key: "confirmed", label: isFinalized ? "finalized" : "confirmed", active: isConfirmed },
  ];

  return (
    <div className="flex gap-1" style={{ width: "100%" }}>
      {stages.map((s) => (
        <div key={s.key} style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              height: 8,
              borderRadius: 2,
              background: s.active ? "var(--ts-accent)" : "var(--ts-bg-2)",
              border: `1px solid ${s.active ? "var(--ts-accent)" : "var(--ts-line)"}`,
            }}
          />
          <div
            className="mono"
            style={{
              marginTop: 4,
              fontSize: 10,
              color: s.active ? "var(--ts-text-2)" : "var(--ts-text-3)",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
            }}
          >
            {s.label}
          </div>
        </div>
      ))}
    </div>
  );
}
