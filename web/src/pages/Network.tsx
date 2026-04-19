import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import Panel from "@/components/Panel";

export default function Network() {
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
  });
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
  });

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-4">
      <Panel title="Chain tips">
        {health.data ? (
          <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <Stat label="Execution" value={hexToNumber(health.data.executionTip)} />
            <Stat label="Proven" value={hexToNumber(health.data.provenTip)} />
            <Stat label="Confirmed" value={hexToNumber(health.data.confirmedTip)} />
            <Stat label="Finalized" value={hexToNumber(health.data.finalizedTip)} />
          </div>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>

      <Panel title="Speculative depth">
        {health.data ? (
          <p className="font-mono text-2xl">
            {hexToNumber(health.data.speculativeDepth)} /{" "}
            {hexToNumber(health.data.maxSpeculativeDepth)}
          </p>
        ) : null}
      </Panel>

      <Panel title="Prover">
        {proving.data ? (
          <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <Stat label="Mode" value={proving.data.mode} mono />
            <Stat label="Workers" value={hexToNumber(proving.data.workers)} />
            <Stat label="In flight" value={hexToNumber(proving.data.inFlight)} />
            <Stat label="Queue" value={hexToNumber(proving.data.queueDepth)} />
            <Stat label="Succeeded" value={hexToNumber(proving.data.proofsSucceeded)} />
            <Stat label="Failed" value={hexToNumber(proving.data.proofsFailed)} />
            <Stat label="Avg ms" value={hexToNumber(proving.data.averageTimeMs)} />
            <Stat label="Pending txs" value={hexToNumber(proving.data.pendingTxs)} />
          </div>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>
    </div>
  );
}

function Stat(props: { label: string; value: number | string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">{props.label}</dt>
      <dd className={`mt-1 ${props.mono ? "font-mono" : "font-mono"}`}>{props.value}</dd>
    </div>
  );
}
