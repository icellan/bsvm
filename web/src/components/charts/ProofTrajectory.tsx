import { ReactElement } from "react";

type Props = {
  tier: "speculative" | "proven" | "finalized" | "frozen";
  cells?: number;
};

// ProofTrajectory renders the per-block proof-stage strip shown on
// the Block detail page. Four stages — assembled → proof-ok →
// covenant → confirmed — rendered as 40 cells colored by how far
// the block has progressed through the pipeline.
export default function ProofTrajectory({
  tier,
  cells = 40,
}: Props): ReactElement {
  // Reached stage: speculative=1 (assembled); proven=2 (proof-ok);
  // covenant-seen is tracked by `finalized` here because confirmed
  // tip is BSV-confirmed; frozen forces 0.
  const reached =
    tier === "frozen"
      ? 0
      : tier === "finalized"
      ? 4
      : tier === "proven"
      ? 2
      : 1;

  const per = Math.floor(cells / 4);
  const stages: { label: string; tone: string; filled: boolean }[] = [
    { label: "assembled", tone: "var(--ts-accent)", filled: reached >= 1 },
    { label: "proof-ok", tone: "var(--ts-info)", filled: reached >= 2 },
    { label: "covenant", tone: "var(--ts-accent)", filled: reached >= 3 },
    { label: "confirmed", tone: "var(--ts-ok)", filled: reached >= 4 },
  ];

  return (
    <div style={{ width: "100%" }}>
      <div
        className="flex"
        style={{ gap: 1, height: 14, background: "var(--ts-bg-3)", padding: 1, borderRadius: 2 }}
      >
        {stages.map((s, si) => (
          <div key={si} className="flex" style={{ flex: 1, gap: 1 }}>
            {Array.from({ length: per }).map((_, i) => (
              <div
                key={i}
                style={{
                  flex: 1,
                  background: s.filled ? s.tone : "var(--ts-bg-3)",
                  opacity: s.filled ? 0.85 : 0.3,
                  borderRadius: 1,
                }}
              />
            ))}
          </div>
        ))}
      </div>
      <div
        className="grid mono"
        style={{
          gridTemplateColumns: "repeat(4, 1fr)",
          marginTop: 6,
          fontSize: 10,
          color: "var(--ts-text-4)",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
        }}
      >
        {stages.map((s, i) => (
          <span
            key={i}
            style={{
              color: s.filled ? "var(--ts-text-2)" : "var(--ts-text-4)",
            }}
          >
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}
