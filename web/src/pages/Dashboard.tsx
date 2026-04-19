import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { bsv, eth, hexToNumber, formatWei } from "@/rpc/client";
import ConfirmationBadge, { tierForBlock } from "@/components/ConfirmationBadge";
import Copy, { shorten } from "@/components/Copy";
import Panel from "@/components/Panel";

// The dashboard is the explorer's landing page. Three panels:
// shard identity, live statistics, recent blocks. Designed to fit
// on one vertical scroll even on a laptop screen.
export default function Dashboard() {
  const shardInfo = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
  });
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
  });
  const bridge = useQuery({
    queryKey: ["bsv_bridgeStatus"],
    queryFn: bsv.bridgeStatus,
  });

  const executionTip = hexToNumber(health.data?.executionTip);
  const provenTip = hexToNumber(health.data?.provenTip);
  const finalizedTip = hexToNumber(health.data?.finalizedTip);

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <Panel title="Shard identity">
        {shardInfo.data ? (
          <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <Row label="Chain ID" value={String(hexToNumber(shardInfo.data.chainId))} mono />
            <Row
              label="Genesis covenant"
              value={shardInfo.data.genesisCovenantTxId}
              copyable
            />
            <Row
              label="Governance"
              value={shardInfo.data.governance.mode}
            />
            <Row
              label="Frozen"
              value={shardInfo.data.governance.frozen ? "yes" : "no"}
            />
          </dl>
        ) : (
          <p className="text-sm text-muted">Loading…</p>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Panel title="Execution tip">
          <p className="font-mono text-2xl">{executionTip}</p>
        </Panel>
        <Panel title="Proven tip">
          <p className="font-mono text-2xl">{provenTip}</p>
          <p className="mt-1 font-mono text-xs text-muted">
            {executionTip - provenTip} blocks behind
          </p>
        </Panel>
        <Panel title="Finalized tip">
          <p className="font-mono text-2xl">{finalizedTip}</p>
          <p className="mt-1 font-mono text-xs text-muted">
            6+ BSV confirmations
          </p>
        </Panel>
      </div>

      <Panel title="Bridge status">
        {bridge.data ? (
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <Row
              label="Locked"
              value={`${formatWei(bridge.data.totalLockedWei)} wBSV`}
            />
            <Row
              label="Supply"
              value={`${formatWei(bridge.data.totalSupplyWei)} wBSV`}
            />
            <Row
              label="Sub-covenants"
              value={String(hexToNumber(bridge.data.subCovenantCount))}
            />
          </dl>
        ) : (
          <p className="text-sm text-muted">Loading…</p>
        )}
      </Panel>

      <RecentBlocks
        executionTip={executionTip}
        provenTip={provenTip}
        finalizedTip={finalizedTip}
      />
    </div>
  );
}

function Row(props: {
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">
        {props.label}
      </dt>
      <dd
        className={`mt-1 ${props.mono ? "font-mono" : ""}`}
      >
        {props.copyable ? (
          <Copy value={props.value} label={shorten(props.value)} />
        ) : (
          props.value
        )}
      </dd>
    </div>
  );
}

function RecentBlocks(props: {
  executionTip: number;
  provenTip: number;
  finalizedTip: number;
}) {
  const count = Math.min(10, props.executionTip + 1);
  const startBlock = Math.max(0, props.executionTip - count + 1);
  const blockNumbers = Array.from({ length: count }, (_, i) => props.executionTip - i).filter(
    (n) => n >= startBlock
  );

  return (
    <Panel
      title="Recent blocks"
      subtitle={
        blockNumbers.length > 0 ? `showing ${blockNumbers.length}` : ""
      }
    >
      {blockNumbers.length === 0 ? (
        <p className="text-sm text-muted">No blocks yet.</p>
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-border/30 text-xs uppercase tracking-wider text-muted">
              <tr>
                <th className="px-3 py-2 text-left">Block</th>
                <th className="px-3 py-2 text-left">Txns</th>
                <th className="px-3 py-2 text-left">Gas used</th>
                <th className="px-3 py-2 text-left">Coinbase</th>
                <th className="px-3 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {blockNumbers.map((n) => (
                <BlockRow
                  key={n}
                  number={n}
                  provenTip={props.provenTip}
                  finalizedTip={props.finalizedTip}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function BlockRow(props: {
  number: number;
  provenTip: number;
  finalizedTip: number;
}) {
  const { data } = useQuery({
    queryKey: ["eth_getBlockByNumber", props.number],
    queryFn: () => eth.getBlockByNumber(props.number),
    staleTime: 10_000,
  });
  const txCount = Array.isArray(data?.transactions)
    ? data!.transactions.length
    : 0;
  return (
    <tr className="border-t border-border/50 hover:bg-border/20">
      <td className="px-3 py-2 font-mono">
        <Link to={`/block/${props.number}`}>{props.number}</Link>
      </td>
      <td className="px-3 py-2 font-mono">{txCount}</td>
      <td className="px-3 py-2 font-mono text-muted">
        {data ? hexToNumber(data.gasUsed).toLocaleString() : "—"}
      </td>
      <td className="px-3 py-2 font-mono text-muted">
        {data ? (
          <Link to={`/address/${data.miner}`}>{shorten(data.miner)}</Link>
        ) : (
          "—"
        )}
      </td>
      <td className="px-3 py-2">
        <ConfirmationBadge
          tier={tierForBlock(props.number, {
            provenTip: props.provenTip,
            finalizedTip: props.finalizedTip,
          })}
        />
      </td>
    </tr>
  );
}
