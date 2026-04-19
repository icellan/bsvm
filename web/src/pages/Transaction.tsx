import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { eth, hexToNumber } from "@/rpc/client";
import Copy, { shorten } from "@/components/Copy";
import Panel from "@/components/Panel";

export default function Transaction() {
  const { hash } = useParams<{ hash: string }>();

  const tx = useQuery({
    queryKey: ["tx", hash],
    queryFn: () => eth.getTransactionByHash(hash!),
  });
  const receipt = useQuery({
    queryKey: ["receipt", hash],
    queryFn: () => eth.getTransactionReceipt(hash!),
  });

  if (tx.isLoading) return <p className="text-muted">Loading transaction…</p>;
  if (!tx.data) return <p className="text-muted">Transaction not found.</p>;

  const status =
    receipt.data?.status === "0x1"
      ? "success"
      : receipt.data?.status === "0x0"
        ? "failed"
        : "pending";

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <Panel title="Transaction" subtitle={status}>
        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <Row label="Hash" value={tx.data.hash} copyable />
          <Row
            label="Block"
            value={tx.data.blockNumber ? String(hexToNumber(tx.data.blockNumber)) : "pending"}
            link={tx.data.blockNumber ? `/block/${hexToNumber(tx.data.blockNumber)}` : undefined}
          />
          <Row label="From" value={tx.data.from} copyable link={`/address/${tx.data.from}`} />
          <Row
            label="To"
            value={tx.data.to ?? "contract create"}
            copyable={!!tx.data.to}
            link={tx.data.to ? `/address/${tx.data.to}` : undefined}
          />
          <Row
            label="Value"
            value={`${hexToNumber(tx.data.value).toLocaleString()} wei`}
          />
          <Row
            label="Gas used"
            value={
              receipt.data
                ? hexToNumber(receipt.data.gasUsed).toLocaleString()
                : "—"
            }
          />
          <Row label="Nonce" value={String(hexToNumber(tx.data.nonce))} />
        </dl>
      </Panel>

      {tx.data.input && tx.data.input !== "0x" ? (
        <Panel title="Input data">
          <pre className="overflow-x-auto rounded-md bg-bg p-3 font-mono text-xs text-muted">
            {tx.data.input}
          </pre>
        </Panel>
      ) : null}

      {receipt.data && receipt.data.logs.length > 0 ? (
        <Panel title={`Logs (${receipt.data.logs.length})`}>
          <ul className="divide-y divide-border/50">
            {receipt.data.logs.map((log, i) => (
              <li key={i} className="py-2 font-mono text-xs">
                <div className="text-muted">
                  {log.address} · topic[0]{" "}
                  <Copy value={log.topics[0] ?? ""} label={shorten(log.topics[0] ?? "")} />
                </div>
                <div className="mt-1 break-all text-fg">{log.data}</div>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  );
}

function Row(props: {
  label: string;
  value: string;
  copyable?: boolean;
  link?: string;
}) {
  const body = props.link ? (
    <Link to={props.link} className="font-mono text-sm">
      {props.copyable ? <Copy value={props.value} label={shorten(props.value)} /> : props.value}
    </Link>
  ) : props.copyable ? (
    <Copy value={props.value} label={shorten(props.value)} />
  ) : (
    props.value
  );
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">{props.label}</dt>
      <dd className="mt-1 break-all text-sm">{body}</dd>
    </div>
  );
}
