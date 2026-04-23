import { ReactElement } from "react";

type Props = {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  fillOpacity?: number;
  strokeWidth?: number;
  className?: string;
  responsive?: boolean;
};

// Sparkline renders a simple SVG polyline over a numeric series.
// With `responsive` (default), the SVG stretches to fill its parent
// via viewBox + preserveAspectRatio, so narrow KPI cards don't get
// overflowed by a fixed-px SVG.
export default function Sparkline({
  data,
  width = 220,
  height = 24,
  color = "var(--ts-accent)",
  fillOpacity = 0.12,
  strokeWidth = 1.3,
  className = "",
  responsive = true,
}: Props): ReactElement {
  const n = data.length;
  const hasPoints = n >= 2;
  const min = hasPoints ? Math.min(...data) : 0;
  const max = hasPoints ? Math.max(...data) : 1;
  const range = max - min || 1;
  const padY = 2;
  const innerH = height - 2 * padY;

  const points: string[] = [];
  if (hasPoints) {
    for (let i = 0; i < n; i++) {
      const x = (i / (n - 1)) * width;
      const y = padY + (1 - (data[i] - min) / range) * innerH;
      points.push(`${x.toFixed(2)},${y.toFixed(2)}`);
    }
  } else {
    points.push(`0,${(height / 2).toFixed(2)}`);
    points.push(`${width},${(height / 2).toFixed(2)}`);
  }

  const line = points.join(" ");
  const fill = `0,${height} ${line} ${width},${height}`;

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
      <polyline points={fill} fill={color} fillOpacity={fillOpacity} stroke="none" />
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
