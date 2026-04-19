import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { bsv, eth, hexToNumber } from "@/rpc/client";
import Copy, { shorten } from "@/components/Copy";
import Panel from "@/components/Panel";
import ConfirmationBadge, { tierForBlock } from "@/components/ConfirmationBadge";

export default function Block() {
  const { id } = useParams<{ id: string }>();
  const isHash = id?.startsWith("0x") && id.length === 66;
  const blockNum = isHash ? null : Number(id);
  const block = useQuery({
    queryKey: ["block", id],
    queryFn: () =>
      isHash
        ? eth.getBlockByHash(id!)
        : eth.getBlockByNumber(blockNum ?? 0),
  });
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
  });

  if (block.isLoading) return <p className="text-muted">Loading block…</p>;
  if (!block.data) return <p className="text-muted">Block not found.</p>;

  const blockNumber = hexToNumber(block.data.number);
  const provenTip = hexToNumber(health.data?.provenTip);
  const finalizedTip = hexToNumber(health.data?.finalizedTip);
  const txs = Array.isArray(block.data.transactions) ? block.data.transactions : [];

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <Panel
        title={`Block #${blockNumber}`}
        subtitle={
          <ConfirmationBadge
            tier={tierForBlock(blockNumber, { provenTip, finalizedTip })}
          />
        }
      >
        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <Row label="Block hash" value={block.data.hash} copyable />
          <Row label="Parent" value={block.data.parentHash} copyable />
          <Row label="Coinbase" value={block.data.miner} copyable />
          <Row
            label="Timestamp"
            value={new Date(hexToNumber(block.data.timestamp) * 1000).toISOString()}
          />
          <Row
            label="Gas used / limit"
            value={`${hexToNumber(block.data.gasUsed).toLocaleString()} / ${hexToNumber(block.data.gasLimit).toLocaleString()}`}
          />
          <Row label="State root" value={block.data.stateRoot} copyable />
        </dl>
      </Panel>

      <Panel title={`Transactions (${txs.length})`}>
        {txs.length === 0 ? (
          <p className="text-sm text-muted">No transactions.</p>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <thead className="bg-border/30 text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-3 py-2 text-left">Hash</th>
                  <th className="px-3 py-2 text-left">From</th>
                  <th className="px-3 py-2 text-left">To</th>
                  <th className="px-3 py-2 text-left">Value</th>
                </tr>
              </thead>
              <tbody>
                {txs.map((tx) => {
                  if (typeof tx === "string") {
                    return (
                      <tr key={tx} className="border-t border-border/50">
                        <td className="px-3 py-2">
                          <Link to={`/tx/${tx}`}>{shorten(tx)}</Link>
                        </td>
                      </tr>
                    );
                  }
                  return (
                    <tr key={tx.hash} className="border-t border-border/50 hover:bg-border/20">
                      <td className="px-3 py-2 font-mono">
                        <Link to={`/tx/${tx.hash}`}>{shorten(tx.hash)}</Link>
                      </td>
                      <td className="px-3 py-2 font-mono text-muted">
                        <Link to={`/address/${tx.from}`}>{shorten(tx.from)}</Link>
                      </td>
                      <td className="px-3 py-2 font-mono text-muted">
                        {tx.to ? (
                          <Link to={`/address/${tx.to}`}>{shorten(tx.to)}</Link>
                        ) : (
                          <span className="italic">contract create</span>
                        )}
                      </td>
                      <td className="px-3 py-2 font-mono text-muted">
                        {hexToNumber(tx.value).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function Row(props: {
  label: string;
  value: string;
  copyable?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">
        {props.label}
      </dt>
      <dd className="mt-1 break-all font-mono text-sm">
        {props.copyable ? <Copy value={props.value} label={shorten(props.value)} /> : props.value}
      </dd>
    </div>
  );
}
