import { useQuery } from "@tanstack/react-query";

import { bsv, formatWei, hexToNumber } from "@/rpc/client";
import Panel from "@/components/Panel";

export default function Bridge() {
  const status = useQuery({
    queryKey: ["bsv_bridgeStatus"],
    queryFn: bsv.bridgeStatus,
  });
  const deposits = useQuery({
    queryKey: ["bsv_getDeposits"],
    queryFn: () => bsv.getDeposits(),
  });
  const withdrawals = useQuery({
    queryKey: ["bsv_getWithdrawals"],
    queryFn: () => bsv.getWithdrawals(),
  });

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-4">
      <Panel title="Bridge status">
        {status.data ? (
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
            <Row label="Locked" value={`${formatWei(status.data.totalLockedWei)} wBSV`} />
            <Row label="Supply" value={`${formatWei(status.data.totalSupplyWei)} wBSV`} />
            <Row
              label="Sub-covenants"
              value={String(hexToNumber(status.data.subCovenantCount))}
            />
          </dl>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>

      <Panel title={`Recent deposits (${deposits.data?.length ?? 0})`}>
        {(!deposits.data || deposits.data.length === 0) ? (
          <p className="text-sm text-muted">No deposits yet.</p>
        ) : (
          <ul className="divide-y divide-border/50 text-sm">
            {deposits.data.map((d) => (
              <li key={`${d.bsvTxId}-${d.vout}`} className="py-2 font-mono">
                <div className="text-muted">
                  {d.confirmed ? "✓" : "…"} {d.bsvTxId.slice(0, 12)}… → {d.l2Address}
                </div>
                <div>
                  {hexToNumber(d.satoshiAmount).toLocaleString()} sats ({formatWei(d.l2WeiAmount)} wBSV)
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title={`Recent withdrawals (${withdrawals.data?.length ?? 0})`}>
        {(!withdrawals.data || withdrawals.data.length === 0) ? (
          <p className="text-sm text-muted">No withdrawals yet.</p>
        ) : (
          <ul className="divide-y divide-border/50 text-sm">
            {withdrawals.data.map((w) => (
              <li key={String(w.nonce)} className="py-2 font-mono">
                <div className="text-muted">
                  nonce {hexToNumber(w.nonce)} → {w.bsvAddress}
                </div>
                <div>
                  {formatWei(w.amountWei)} wBSV · {w.claimed ? "claimed" : "pending"}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function Row(props: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">{props.label}</dt>
      <dd className="mt-1 font-mono">{props.value}</dd>
    </div>
  );
}
