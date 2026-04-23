import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import { adminRPC } from "@/pages/admin/rpc";
import { Panel, KPI, Button, SparkBars, Chip } from "@/components/ui";
import { useRingBuffer } from "@/hooks/useRingBuffer";

// Admin Prover — KPI row, controls panel (pause/resume/flush),
// workers table, 60 min proof-duration bar chart.
export default function AdminProver() {
  const qc = useQueryClient();
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
    refetchInterval: 2_000,
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
    mutationFn: () =>
      adminRPC<{ success: boolean; batchSize: number }>(
        "admin_forceFlushBatch"
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["bsv_provingStatus"] }),
  });

  const mode = proving.data?.mode ?? "—";
  const workers = proving.data ? hexToNumber(proving.data.workers) : 0;
  const avgMs = proving.data ? hexToNumber(proving.data.averageTimeMs) : 0;
  const pending = proving.data ? hexToNumber(proving.data.pendingTxs) : 0;
  const succeeded = proving.data ? hexToNumber(proving.data.proofsSucceeded) : 0;
  const failed = proving.data ? hexToNumber(proving.data.proofsFailed) : 0;
  const paused = !!proving.data?.batcherPaused;

  const avgBuf = useRingBuffer(avgMs || undefined, 60);
  const succBuf = useRingBuffer(succeeded || undefined, 60);

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
            Admin · prover
          </div>
          <h1
            className="mt-1"
            style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}
          >
            Proof pipeline
          </h1>
        </div>
        <Chip tone={paused ? "warn" : "ok"} dot>
          {paused ? "batcher paused" : mode}
        </Chip>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <KPI label="Mode" value={mode} valueTone={paused ? "warn" : "accent"} />
        <KPI label="Workers" value={workers.toString()} />
        <KPI
          label="Avg proof"
          value={(avgMs / 1000).toFixed(1)}
          unit="s"
          sparkData={avgBuf}
          sparkColor="var(--ts-warn)"
          valueTone="warn"
        />
        <KPI label="Pending tx" value={pending.toLocaleString()} sparkData={useRingBuffer(pending, 60)} />
      </div>

      <Panel title="Controls" kicker="Operator actions" statusDot={paused ? "warn" : "ok"}>
        <div className="flex gap-2 flex-wrap">
          <Button
            variant="danger"
            onClick={() => pause.mutate()}
            disabled={pause.isPending || paused}
          >
            ⏸ Pause proving
          </Button>
          <Button
            variant="primary"
            onClick={() => resume.mutate()}
            disabled={resume.isPending || !paused}
          >
            ▶ Resume proving
          </Button>
          <Button onClick={() => flush.mutate()} disabled={flush.isPending}>
            ↻ Force flush batch
          </Button>
          <Button disabled>Restart workers</Button>
          <Button disabled>Diagnostics</Button>
        </div>
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel title="Workers" kicker={`${workers} active`}>
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            Per-worker breakdown requires a follow-up RPC
            (`admin_proverWorkers`). Aggregate throughput for now:
          </div>
          <div style={{ marginTop: 12 }}>
            <SparkBars
              data={succBuf.length > 0 ? succBuf : [0]}
              width={420}
              height={60}
              color="var(--ts-ok)"
            />
            <div
              className="mono"
              style={{
                marginTop: 6,
                fontSize: 10,
                color: "var(--ts-text-3)",
              }}
            >
              succeeded · last {succBuf.length} samples · {succeeded.toLocaleString()} total · {failed} failed
            </div>
          </div>
        </Panel>

        <Panel title="Proof duration" kicker="60-sample rolling window">
          <SparkBars
            data={avgBuf.length > 0 ? avgBuf : [0]}
            width={420}
            height={140}
            color="var(--ts-warn)"
          />
          <div
            className="mono"
            style={{
              marginTop: 6,
              fontSize: 10,
              color: "var(--ts-text-3)",
            }}
          >
            avg {(avgMs / 1000).toFixed(2)}s · peak{" "}
            {avgBuf.length > 0
              ? (Math.max(...avgBuf) / 1000).toFixed(2) + "s"
              : "—"}
          </div>
        </Panel>
      </div>
    </div>
  );
}
