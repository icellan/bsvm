import { ReactElement } from "react";

type Props = {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  gap?: number;
  className?: string;
  responsive?: boolean;
};

// SparkBars renders a deterministic bar chart for short series
// (worker activity, per-minute proof counts, etc). Responsive by
// default — fills the parent width via viewBox scaling.
export default function SparkBars({
  data,
  width = 180,
  height = 50,
  color = "var(--ts-accent)",
  gap = 2,
  className = "",
  responsive = true,
}: Props): ReactElement {
  const n = Math.max(1, data.length);
  const max = Math.max(1, ...data);
  const barW = (width - gap * (n - 1)) / n;

  return (
    <svg
      {...(responsive
        ? { width: "100%", preserveAspectRatio: "none" as const }
        : { width, preserveAspectRatio: "xMidYMid meet" as const })}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className={className}
      style={{ display: "block", maxWidth: "100%" }}
      aria-hidden="true"
    >
      {data.map((v, i) => {
        const h = Math.max(1, (v / max) * (height - 2));
        const x = i * (barW + gap);
        const y = height - h;
        return (
          <rect
            key={i}
            x={x}
            y={y}
            width={barW}
            height={h}
            fill={color}
            opacity={0.85}
            rx={1}
          />
        );
      })}
    </svg>
  );
}
