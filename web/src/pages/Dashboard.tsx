import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber, formatWei } from "@/rpc/client";
import {
  Panel,
  KPI,
  Chip,
  Bar,
  SparkBars,
  KV,
} from "@/components/ui";
import ThroughputChart from "@/components/charts/ThroughputChart";
import DepthViz from "@/components/charts/DepthViz";
import BlockLadder from "@/components/charts/BlockLadder";
import { useRingBuffer } from "@/hooks/useRingBuffer";

// Dashboard — shard-level operator overview. 6 KPI cards over a
// throughput chart + speculative depth viz + alerts panel, then a
// 14-row recent-block ladder on the left and a prover/bridge/
// governance right rail. All data is pulled from bsv_* + eth_* RPC
// with short (2–4 s) refetch intervals; sparklines are client-side
// ring buffers.
export default function Dashboard() {
  const shard = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
    refetchInterval: 4_000,
  });
  const health = useQuery({
    queryKey: ["bsv_networkHealth"],
    queryFn: bsv.networkHealth,
    refetchInterval: 2_000,
  });
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
    refetchInterval: 3_000,
  });
  const bridge = useQuery({
    queryKey: ["bsv_bridgeStatus"],
    queryFn: bsv.bridgeStatus,
    refetchInterval: 5_000,
  });
  const gov = useQuery({
    queryKey: ["bsv_getGovernanceState"],
    queryFn: bsv.getGovernanceState,
    refetchInterval: 5_000,
  });

  const exec = health.data ? hexToNumber(health.data.executionTip) : 0;
  const prov = health.data ? hexToNumber(health.data.provenTip) : 0;
  const fin = health.data ? hexToNumber(health.data.finalizedTip) : 0;
  // Compute speculativeDepth client-side: exec - prov is the honest
  // number of blocks not yet proven on BSV. The RPC's speculativeDepth
  // field is measured against an internal proven counter which, in
  // mock mode, never advances — yielding misleading 0 values.
  const specDepth = Math.max(0, exec - prov);
  const maxSpec = health.data ? hexToNumber(health.data.maxSpeculativeDepth) : 64;
  const avgProofMs = proving.data ? hexToNumber(proving.data.averageTimeMs) : 0;
  const pending = proving.data ? hexToNumber(proving.data.pendingTxs) : 0;
  const frozen = !!shard.data?.governance.frozen;
  const proveMode = proving.data?.mode ?? "—";
  const isMock = proveMode === "mock";

  const execBuf = useRingBuffer(exec || undefined, 60);
  const provBuf = useRingBuffer(prov || undefined, 60);
  const finBuf = useRingBuffer(fin || undefined, 60);
  const proofBuf = useRingBuffer(avgProofMs || undefined, 60);
  const pendingBuf = useRingBuffer(pending, 60);
  const specBuf = useRingBuffer(specDepth, 60);

  const chainLabel = shard.data ? `Shard #${shard.data.chainId}` : "Shard";

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <PageHeader
        kicker="Overview · live"
        title={chainLabel}
        chips={
          shard.data
            ? [
                { label: `chain ${hexToNumber(shard.data.chainId)}`, tone: "neutral" as const },
                { label: shard.data.governance.mode, tone: "info" as const },
                { label: `prove ${proveMode}`, tone: isMock ? "warn" as const : "ok" as const },
                frozen
                  ? { label: "frozen", tone: "bad" as const }
                  : { label: "unfrozen", tone: "ok" as const },
              ]
            : []
        }
      />

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
          gap: 10,
        }}
      >
        <KPI
          label="Exec tip"
          value={exec.toLocaleString()}
          sparkData={execBuf}
          valueTone="accent"
        />
        <KPI
          label="Proven"
          value={prov.toLocaleString()}
          delta={{ value: `−${exec - prov}`, tone: exec - prov > 10 ? "warn" : "neutral" }}
          sparkData={provBuf}
          sparkColor="var(--ts-info)"
          valueTone="info"
        />
        <KPI
          label="Finalized"
          value={fin.toLocaleString()}
          sparkData={finBuf}
          sparkColor="var(--ts-ok)"
          valueTone="ok"
        />
        <KPI
          label="Avg proof"
          value={(avgProofMs / 1000).toFixed(1)}
          unit="s"
          sparkData={proofBuf}
          sparkColor="var(--ts-warn)"
        />
        <KPI
          label="Mempool"
          value={pending.toLocaleString()}
          sparkData={pendingBuf}
        />
        <KPI
          label="Spec depth"
          value={specDepth.toLocaleString()}
          unit={`/ ${maxSpec}`}
          sparkData={specBuf}
          sparkColor={specDepth > maxSpec * 0.75 ? "var(--ts-bad)" : "var(--ts-accent)"}
          valueTone={specDepth > maxSpec * 0.75 ? "bad" : specDepth > maxSpec * 0.5 ? "warn" : "default"}
        />
      </div>

      <div
        className="grid"
        style={{ gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}
      >
        <Panel title="Throughput" kicker="Exec vs proven · 60s" statusDot="ok">
          <ThroughputChart exec={execBuf} proven={provBuf} />
          <div
            className="grid mono"
            style={{
              gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
              marginTop: 12,
              paddingTop: 10,
              borderTop: "1px solid var(--ts-line)",
              gap: 14,
            }}
          >
            <StatBlock label="current" value={exec.toLocaleString()} />
            <StatBlock label="peak" value={Math.max(exec, ...execBuf).toLocaleString()} />
            <StatBlock
              label="avg"
              value={
                execBuf.length > 0
                  ? Math.round(execBuf.reduce((a, b) => a + b, 0) / execBuf.length).toLocaleString()
                  : "—"
              }
            />
            <StatBlock label="errors" value="0" tone="ok" />
          </div>
        </Panel>

        <Panel title="Speculative depth" kicker="64 blocks">
          <DepthViz
            executionTip={exec}
            provenTip={prov}
            finalizedTip={fin}
            maxDepth={64}
            frozen={frozen}
          />
          <div className="flex flex-wrap gap-2" style={{ marginTop: 10 }}>
            <Chip tone="ok" dot>
              finalized
            </Chip>
            <Chip tone="info" dot>
              proven
            </Chip>
            <Chip tone="neutral" dot>
              speculative
            </Chip>
            {frozen ? (
              <Chip tone="bad" dot>
                frozen
              </Chip>
            ) : null}
          </div>
        </Panel>

        <Panel
          title="Active alerts"
          kicker="System health"
          statusDot={frozen ? "bad" : isMock ? "warn" : "ok"}
        >
          <div className="flex flex-col gap-2">
            {frozen ? (
              <AlertRow
                tone="bad"
                title="Shard frozen"
                body="Governance halt active. No new covenant advances accepted."
              />
            ) : null}
            {isMock ? (
              <AlertRow
                tone="warn"
                title="Prover in mock mode"
                body="No SP1 proofs generated and no BSV covenant-advance transactions submitted. Set BSVM_PROVE_MODE=execute or prove for real settlement."
              />
            ) : null}
            {!frozen && !isMock && specDepth > maxSpec * 0.75 ? (
              <AlertRow
                tone="warn"
                title="Speculative depth high"
                body={`${specDepth}/${maxSpec} unproven blocks. Prover may be saturated.`}
              />
            ) : null}
            {!frozen && !isMock && specDepth <= maxSpec * 0.75 ? (
              <div
                className="mono"
                style={{ fontSize: 11, color: "var(--ts-text-3)", padding: "8px 0" }}
              >
                No active alerts.
              </div>
            ) : null}
          </div>
        </Panel>
      </div>

      <div
        className="grid"
        style={{ gridTemplateColumns: "3fr 1fr", gap: 10 }}
      >
        <Panel title="Recent blocks" kicker="Latest 14" padded={false}>
          <BlockLadder
            executionTip={exec}
            provenTip={prov}
            finalizedTip={fin}
            rows={14}
            frozen={frozen}
          />
        </Panel>

        <div className="flex flex-col" style={{ gap: 10 }}>
          <Panel title="Prover" kicker="Batch pipeline" statusDot={proving.data?.batcherPaused ? "warn" : "ok"}>
            <KV
              items={[
                { label: "mode", value: proving.data?.mode ?? "—", mono: true },
                { label: "workers", value: proving.data ? hexToNumber(proving.data.workers).toString() : "—", mono: true },
                { label: "in flight", value: proving.data ? hexToNumber(proving.data.inFlight).toString() : "—", mono: true },
                { label: "queue", value: proving.data ? hexToNumber(proving.data.queueDepth).toString() : "—", mono: true },
              ]}
              columns={2}
            />
            <div style={{ marginTop: 10 }}>
              <SparkBars data={proofBuf.length > 0 ? proofBuf : [0]} width={260} height={40} color="var(--ts-warn)" />
              <div
                className="mono"
                style={{ fontSize: 10, color: "var(--ts-text-4)", marginTop: 4 }}
              >
                avg {(avgProofMs / 1000).toFixed(1)}s · last {proofBuf.length} samples
              </div>
            </div>
          </Panel>

          <Panel title="Bridge reserve" kicker="wBSV supply · satoshi locked">
            <KV
              items={[
                {
                  label: "locked",
                  value: bridge.data ? `${formatWei(bridge.data.totalLockedWei)} wBSV` : "—",
                  mono: true,
                },
                {
                  label: "supply",
                  value: bridge.data ? `${formatWei(bridge.data.totalSupplyWei)} wBSV` : "—",
                  mono: true,
                },
              ]}
              columns={1}
            />
            <div style={{ marginTop: 10 }}>
              <Bar value={100} max={100} tone="ok" />
              <div
                className="mono"
                style={{ fontSize: 10, color: "var(--ts-text-4)", marginTop: 4 }}
              >
                1:1 reserve · {bridge.data ? hexToNumber(bridge.data.subCovenantCount) : 0} sub-covenants
              </div>
            </div>
          </Panel>

          <Panel title="Governance" kicker={shard.data?.governance.mode ?? "—"} statusDot={frozen ? "bad" : "ok"}>
            <div className="flex flex-wrap gap-1" style={{ marginBottom: 10 }}>
              {(gov.data?.keys ?? []).slice(0, 8).map((k, i) => (
                <span
                  key={k}
                  title={k}
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: 999,
                    background: i < (gov.data?.threshold ?? 0) ? "var(--ts-accent)" : "var(--ts-line-2)",
                    display: "inline-block",
                  }}
                />
              ))}
            </div>
            <KV
              items={[
                { label: "threshold", value: `${gov.data?.threshold ?? "—"} / ${gov.data?.keys.length ?? "—"}`, mono: true },
                { label: "pending", value: "0", mono: true },
              ]}
              columns={2}
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}

function PageHeader({
  kicker,
  title,
  chips,
}: {
  kicker: string;
  title: string;
  chips?: { label: string; tone: "ok" | "warn" | "bad" | "info" | "accent" | "neutral" }[];
}) {
  return (
    <div className="flex items-end justify-between flex-wrap gap-3">
      <div className="min-w-0">
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
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: "-0.01em",
            color: "var(--ts-text)",
          }}
        >
          {title.includes("#") ? (
            <>
              {title.split("#")[0]}
              <span style={{ color: "var(--ts-accent)" }} className="mono">
                #{title.split("#")[1]}
              </span>
            </>
          ) : (
            title
          )}
        </h1>
        {chips && chips.length > 0 ? (
          <div className="flex gap-2 mt-2 flex-wrap">
            {chips.map((c, i) => (
              <Chip key={i} tone={c.tone} dot>
                {c.label}
              </Chip>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function StatBlock({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "ok" | "warn" | "bad";
}) {
  const color =
    tone === "ok"
      ? "var(--ts-ok)"
      : tone === "warn"
      ? "var(--ts-warn)"
      : tone === "bad"
      ? "var(--ts-bad)"
      : "var(--ts-text)";
  return (
    <div>
      <div
        style={{
          fontSize: 10,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: "var(--ts-text-3)",
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 16, color }}>{value}</div>
    </div>
  );
}

function AlertRow({
  tone,
  title,
  body,
}: {
  tone: "ok" | "warn" | "bad" | "info";
  title: string;
  body: string;
}) {
  const color =
    tone === "ok"
      ? "var(--ts-ok)"
      : tone === "warn"
      ? "var(--ts-warn)"
      : tone === "bad"
      ? "var(--ts-bad)"
      : "var(--ts-info)";
  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        paddingLeft: 10,
        paddingTop: 4,
        paddingBottom: 4,
      }}
    >
      <div style={{ fontSize: 12, color: "var(--ts-text)" }}>{title}</div>
      <div style={{ fontSize: 11, color: "var(--ts-text-3)" }}>{body}</div>
    </div>
  );
}
