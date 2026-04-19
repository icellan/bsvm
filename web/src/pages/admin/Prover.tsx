import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import { adminRPC } from "@/pages/admin/rpc";
import Panel from "@/components/Panel";

export default function AdminProver() {
  const qc = useQueryClient();
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
  });

  const pause = useMutation({
    mutationFn: () => adminRPC<{ success: boolean }>("admin_pauseProving"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["bsv_provingStatus"] }),
  });
  const resume = useMutation({
    mutationFn: () => adminRPC<{ success: boolean }>("admin_resumeProving"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["bsv_provingStatus"] }),
  });
  const flush = useMutation({
    mutationFn: () => adminRPC<{ success: boolean; batchSize: number }>("admin_forceFlushBatch"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["bsv_provingStatus"] }),
  });

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Prover status">
        {proving.data ? (
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <Row label="Mode" value={proving.data.mode} />
            <Row label="Workers" value={String(hexToNumber(proving.data.workers))} />
            <Row label="In flight" value={String(hexToNumber(proving.data.inFlight))} />
            <Row label="Queue" value={String(hexToNumber(proving.data.queueDepth))} />
            <Row
              label="Succeeded"
              value={String(hexToNumber(proving.data.proofsSucceeded))}
            />
            <Row
              label="Failed"
              value={String(hexToNumber(proving.data.proofsFailed))}
            />
            <Row
              label="Avg ms"
              value={String(hexToNumber(proving.data.averageTimeMs))}
            />
            <Row
              label="Pending txs"
              value={String(hexToNumber(proving.data.pendingTxs))}
            />
          </dl>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>

      <Panel title="Actions">
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => pause.mutate()}
            disabled={pause.isPending}
            className="rounded-md border border-warning/60 bg-warning/10 px-3 py-1.5 text-xs font-semibold text-warning hover:bg-warning/20"
          >
            Pause proving
          </button>
          <button
            onClick={() => resume.mutate()}
            disabled={resume.isPending}
            className="rounded-md border border-accent/60 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20"
          >
            Resume proving
          </button>
          <button
            onClick={() => flush.mutate()}
            disabled={flush.isPending}
            className="rounded-md border border-border bg-bg px-3 py-1.5 text-xs text-fg hover:bg-border/20"
          >
            Force flush batch
          </button>
        </div>
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
