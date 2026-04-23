import { useQuery } from "@tanstack/react-query";

import { bsv, formatWei, hexToNumber } from "@/rpc/client";
import { Panel, Chip, Bar, KPI } from "@/components/ui";
import BridgeFlow from "@/components/charts/BridgeFlow";

// Bridge — BSV ↔ wBSV reserve dashboard. Headline flow component
// plus deposit / withdrawal tables driven by the existing bsv_*
// queries.
export default function Bridge() {
  const status = useQuery({
    queryKey: ["bsv_bridgeStatus"],
    queryFn: bsv.bridgeStatus,
    refetchInterval: 5_000,
  });
  const deposits = useQuery({
    queryKey: ["bsv_getDeposits"],
    queryFn: () => bsv.getDeposits(),
    refetchInterval: 8_000,
  });
  const withdrawals = useQuery({
    queryKey: ["bsv_getWithdrawals"],
    queryFn: () => bsv.getWithdrawals(),
    refetchInterval: 8_000,
  });

  const locked = status.data ? formatWei(status.data.totalLockedWei) : "0";
  const supply = status.data ? formatWei(status.data.totalSupplyWei) : "0";
  const subCovs = status.data ? hexToNumber(status.data.subCovenantCount) : 0;
  const deps = deposits.data ?? [];
  const wds = withdrawals.data ?? [];

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <PageHeader kicker="Bridge · live" title="BSV ↔ wBSV" />

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <KPI label="BSV locked" value={locked} unit="wBSV" valueTone="accent" />
        <KPI label="wBSV supply" value={supply} unit="wBSV" />
        <KPI label="Sub-covenants" value={subCovs.toLocaleString()} />
        <KPI
          label="Peg delta"
          value="0.0000"
          unit="wBSV"
          valueTone="ok"
          delta={{ value: "in sync", tone: "ok" }}
        />
      </div>

      <BridgeFlow bsvLocked={locked} wbsvSupply={supply} subCovenants={subCovs} />

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel title="Recent deposits" kicker={`${deps.length} total`}>
          {deps.length === 0 ? (
            <EmptyRow label="No deposits yet" />
          ) : (
            <Table
              head={["bsv tx", "l2 recipient", "amount", "status"]}
              rows={deps.slice(0, 12).map((d) => [
                <span key="a" className="mono" style={{ fontSize: 11 }}>
                  {d.bsvTxId.slice(0, 10)}…:{hexToNumber(d.vout)}
                </span>,
                <span key="b" className="mono" style={{ fontSize: 11 }}>
                  {d.l2Address.slice(0, 8)}…{d.l2Address.slice(-4)}
                </span>,
                <span key="c" className="mono" style={{ fontSize: 11 }}>
                  {formatWei(d.l2WeiAmount)} wBSV
                </span>,
                d.confirmed ? (
                  <Chip key="d" tone="ok" dot>
                    confirmed
                  </Chip>
                ) : (
                  <Chip key="d" tone="warn" dot>
                    pending
                  </Chip>
                ),
              ])}
            />
          )}
        </Panel>

        <Panel title="Recent withdrawals" kicker={`${wds.length} total`}>
          {wds.length === 0 ? (
            <EmptyRow label="No withdrawals yet" />
          ) : (
            <Table
              head={["nonce", "bsv address", "amount", "claim status"]}
              rows={wds.slice(0, 12).map((w) => {
                const csv = hexToNumber(w.csvRemaining);
                return [
                  <span key="a" className="mono" style={{ fontSize: 11 }}>
                    #{hexToNumber(w.nonce)}
                  </span>,
                  <span key="b" className="mono" style={{ fontSize: 11 }}>
                    {w.bsvAddress.slice(0, 8)}…{w.bsvAddress.slice(-4)}
                  </span>,
                  <span key="c" className="mono" style={{ fontSize: 11 }}>
                    {formatWei(w.amountWei)} wBSV
                  </span>,
                  w.claimed ? (
                    <Chip key="d" tone="ok" dot>
                      claimed
                    </Chip>
                  ) : csv > 0 ? (
                    <div
                      key="d"
                      className="flex items-center gap-2"
                      style={{ minWidth: 120 }}
                    >
                      <Bar value={100 - Math.min(100, csv)} max={100} tone="warn" />
                      <span
                        className="mono"
                        style={{ fontSize: 10, color: "var(--ts-text-3)" }}
                      >
                        {csv}b
                      </span>
                    </div>
                  ) : (
                    <Chip key="d" tone="accent" dot>
                      claimable
                    </Chip>
                  ),
                ];
              })}
            />
          )}
        </Panel>
      </div>
    </div>
  );
}

function PageHeader({ kicker, title }: { kicker: string; title: string }) {
  return (
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
        {kicker}
      </div>
      <h1
        className="mt-1"
        style={{ fontSize: 26, fontWeight: 500, letterSpacing: "-0.01em" }}
      >
        {title}
      </h1>
    </div>
  );
}

function Table({
  head,
  rows,
}: {
  head: string[];
  rows: React.ReactNode[][];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left" style={{ borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {head.map((h, i) => (
              <th
                key={i}
                className="mono"
                style={{
                  fontSize: 10,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "var(--ts-text-3)",
                  fontWeight: 500,
                  padding: "6px 8px",
                  borderBottom: "1px solid var(--ts-line)",
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr
              key={i}
              className="table-row"
              style={{ borderBottom: "1px solid var(--ts-line)" }}
            >
              {r.map((c, ci) => (
                <td key={ci} style={{ padding: "6px 8px" }}>
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <style>{`
        tr.table-row:hover { background: var(--ts-bg-2); color: var(--ts-text); }
      `}</style>
    </div>
  );
}

function EmptyRow({ label }: { label: string }) {
  return (
    <div
      className="mono"
      style={{ fontSize: 11, color: "var(--ts-text-3)", padding: "8px 4px" }}
    >
      {label}.
    </div>
  );
}
