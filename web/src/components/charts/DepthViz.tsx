import { ReactElement } from "react";

type Props = {
  executionTip: number;
  provenTip: number;
  finalizedTip: number;
  maxDepth?: number;
  frozen?: boolean;
};

// DepthViz shows the `maxDepth` most recent blocks as a row of cells
// colored by their confirmation tier (finalized / proven /
// speculative). Cell heights vary slightly to emphasise depth.
export default function DepthViz({
  executionTip,
  provenTip,
  finalizedTip,
  maxDepth = 64,
  frozen = false,
}: Props): ReactElement {
  const blocks: { number: number; tier: "speculative" | "proven" | "finalized" | "frozen" }[] = [];
  const n = Math.min(maxDepth, Math.max(0, executionTip + 1));
  for (let i = 0; i < maxDepth; i++) {
    const num = executionTip - (maxDepth - 1 - i);
    let tier: "speculative" | "proven" | "finalized" | "frozen";
    if (frozen) tier = "frozen";
    else if (num <= finalizedTip) tier = "finalized";
    else if (num <= provenTip) tier = "proven";
    else tier = "speculative";
    blocks.push({ number: num, tier });
  }

  const color = (t: string) =>
    t === "finalized"
      ? "var(--ts-ok)"
      : t === "proven"
      ? "var(--ts-info)"
      : t === "frozen"
      ? "var(--ts-bad)"
      : "var(--ts-text-4)";

  return (
    <div
      className="flex items-end"
      style={{
        height: 110,
        gap: 2,
        padding: "0 2px",
      }}
      aria-label={`Speculative depth: ${executionTip - provenTip} unproven blocks`}
    >
      {blocks.map((b, i) => (
        <div
          key={i}
          title={`#${b.number} · ${b.tier}`}
          style={{
            flex: 1,
            minWidth: 3,
            height: "72%",
            background: color(b.tier),
            opacity: i < maxDepth - n ? 0.15 : 0.92,
            borderRadius: 1,
          }}
        />
      ))}
    </div>
  );
}
