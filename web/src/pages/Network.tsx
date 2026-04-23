import { useQuery } from "@tanstack/react-query";

import { bsv, hexToNumber } from "@/rpc/client";
import { Panel, KPI, SparkBars, KV, Chip, StatusDot } from "@/components/ui";
import { useRingBuffer } from "@/hooks/useRingBuffer";

// Network — chain-tip overview + prover throughput + speculative
// depth history. Single source of truth for node/cluster health.
export default function Network() {
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
  const peersQuery = useQuery({
    queryKey: ["bsv_getPeers"],
    queryFn: bsv.getPeers,
    refetchInterval: 3_000,
  });

  const exec = health.data ? hexToNumber(health.data.executionTip) : 0;
  const prov = health.data ? hexToNumber(health.data.provenTip) : 0;
  const conf = health.data ? hexToNumber(health.data.confirmedTip) : 0;
  const fin = health.data ? hexToNumber(health.data.finalizedTip) : 0;
  // Use the honest exec - prov depth rather than the RPC field which
  // reports 0 in mock mode regardless of the tip gap.
  const spec = Math.max(0, exec - prov);
  const maxSpec = health.data ? hexToNumber(health.data.maxSpeculativeDepth) : 64;
  const avgProofMs = proving.data ? hexToNumber(proving.data.averageTimeMs) : 0;

  const execBuf = useRingBuffer(exec, 60);
  const provBuf = useRingBuffer(prov, 60);
  const confBuf = useRingBuffer(conf, 60);
  const finBuf = useRingBuffer(fin, 60);
  const specBuf = useRingBuffer(spec, 60);
  const proofBuf = useRingBuffer(avgProofMs, 60);

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
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
          Network · live
        </div>
        <h1
          className="mt-1"
          style={{ fontSize: 26, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Cluster health
        </h1>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <KPI label="Execution" value={exec.toLocaleString()} sparkData={execBuf} valueTone="accent" />
        <KPI label="Proven" value={prov.toLocaleString()} sparkData={provBuf} sparkColor="var(--ts-info)" valueTone="info" />
        <KPI label="Confirmed" value={conf.toLocaleString()} sparkData={confBuf} sparkColor="var(--ts-ok)" />
        <KPI label="Finalized" value={fin.toLocaleString()} sparkData={finBuf} sparkColor="var(--ts-ok)" valueTone="ok" />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Panel
          title="Peers"
          kicker={`${peersQuery.data?.length ?? 0} connected`}
          statusDot={(peersQuery.data?.length ?? 0) > 0 ? "ok" : "warn"}
        >
          {!peersQuery.data || peersQuery.data.length === 0 ? (
            <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
              No peers connected.{" "}
              <span style={{ color: "var(--ts-text-4)" }}>
                Check BSVM_PEERS bootstrap list and libp2p listen addresses.
              </span>
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="w-full text-left" style={{ borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["peer", "tip", "direction", "last seen", "score", "status"].map((h) => (
                      <th
                        key={h}
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
                  {peersQuery.data.map((p) => {
                    const lastSeen = Number(BigInt(p.lastSeen));
                    const since = Math.max(0, Math.floor(Date.now() / 1000 - lastSeen));
                    const fresh = since < 30;
                    const scoreTone: "ok" | "warn" | "bad" =
                      p.score >= 0 ? "ok" : p.score > -50 ? "warn" : "bad";
                    return (
                      <tr
                        key={p.id}
                        style={{ borderTop: "1px solid var(--ts-line)" }}
                      >
                        <td
                          className="mono"
                          title={p.id}
                          style={{
                            padding: "6px 8px",
                            fontSize: 11,
                            color: "var(--ts-text)",
                          }}
                        >
                          {p.id.slice(0, 8)}…{p.id.slice(-6)}
                        </td>
                        <td
                          className="mono"
                          style={{
                            padding: "6px 8px",
                            fontSize: 11,
                            color: "var(--ts-text-2)",
                          }}
                        >
                          #{hexToNumber(p.chainTip).toLocaleString()}
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <Chip
                            tone={
                              p.direction === "outbound"
                                ? "info"
                                : p.direction === "inbound"
                                ? "accent"
                                : "neutral"
                            }
                          >
                            {p.direction || "—"}
                          </Chip>
                        </td>
                        <td
                          className="mono"
                          style={{
                            padding: "6px 8px",
                            fontSize: 11,
                            color: "var(--ts-text-3)",
                          }}
                        >
                          {lastSeen === 0 ? "—" : relAge(since)}
                        </td>
                        <td
                          className="mono"
                          style={{
                            padding: "6px 8px",
                            fontSize: 11,
                            color:
                              scoreTone === "ok"
                                ? "var(--ts-text-2)"
                                : scoreTone === "warn"
                                ? "var(--ts-warn)"
                                : "var(--ts-bad)",
                          }}
                        >
                          {p.score >= 0 ? `+${p.score}` : p.score}
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <StatusDot
                            tone={fresh ? "ok" : "warn"}
                            pulse={fresh}
                            size={7}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Prover throughput" kicker={`${proving.data?.mode ?? "—"} · ${hexToNumber(proving.data?.workers ?? "0x0")} workers`}>
          <SparkBars data={proofBuf.length > 0 ? proofBuf : [0]} width={360} height={60} color="var(--ts-warn)" />
          <div style={{ marginTop: 10 }}>
            <KV
              items={[
                { label: "avg time", value: `${(avgProofMs / 1000).toFixed(2)}s`, mono: true },
                { label: "in flight", value: hexToNumber(proving.data?.inFlight ?? "0x0").toString(), mono: true },
                { label: "queue", value: hexToNumber(proving.data?.queueDepth ?? "0x0").toString(), mono: true },
                { label: "pending tx", value: hexToNumber(proving.data?.pendingTxs ?? "0x0").toString(), mono: true },
                { label: "succeeded", value: hexToNumber(proving.data?.proofsSucceeded ?? "0x0").toLocaleString(), mono: true },
                { label: "failed", value: hexToNumber(proving.data?.proofsFailed ?? "0x0").toString(), mono: true },
              ]}
              columns={3}
            />
          </div>
        </Panel>
      </div>

      <Panel title="Speculative depth" kicker={`60s · cap = ${maxSpec}`} statusDot={spec > maxSpec * 0.75 ? "bad" : spec > maxSpec * 0.5 ? "warn" : "ok"}>
        <SpecDepthChart buf={specBuf} cap={maxSpec} />
        <div className="mt-3 flex items-baseline gap-6 mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
          <span>
            current <span style={{ color: "var(--ts-text)" }}>{spec}</span>
          </span>
          <span>
            peak{" "}
            <span style={{ color: "var(--ts-text)" }}>
              {specBuf.length > 0 ? Math.max(...specBuf) : spec}
            </span>
          </span>
          <span>
            cap <span style={{ color: "var(--ts-bad)" }}>{maxSpec}</span>
          </span>
        </div>
      </Panel>
    </div>
  );
}

function relAge(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h`;
}

function SpecDepthChart({ buf, cap }: { buf: number[]; cap: number }) {
  const w = 900;
  const h = 160;
  const max = Math.max(cap, ...buf, 1);
  const padY = 10;
  const innerH = h - padY * 2;
  const points = (buf.length >= 2 ? buf : [0, 0])
    .map((v, i, arr) => {
      const x = (i / Math.max(1, arr.length - 1)) * w;
      const y = padY + (1 - v / max) * innerH;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
  const capY = padY + (1 - cap / max) * innerH;

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      style={{ width: "100%", height: 160 }}
    >
      <line x1={0} x2={w} y1={capY} y2={capY} stroke="var(--ts-bad)" strokeWidth={1} strokeDasharray="4 6" />
      <polyline
        points={points}
        fill="none"
        stroke="var(--ts-accent)"
        strokeWidth={1.5}
      />
    </svg>
  );
}
