import { ReactElement } from "react";

type Props = {
  exec: number[];
  proven: number[];
  width?: number;
  height?: number;
};

// ThroughputChart renders the dual-series exec/proven tip-history
// plot for the dashboard: a solid accent line with 12 % fill for
// exec, a dashed info line for proven, dashed horizontal grid at
// 25 / 50 / 75 %, and "−60s…now" x-axis labels in the bottom strip.
export default function ThroughputChart({
  exec,
  proven,
  width = 900,
  height = 200,
}: Props): ReactElement {
  const series = exec.length >= 2 ? exec : [0, 0];
  const provSeries = proven.length >= 2 ? proven : [0, 0];
  const all = [...series, ...provSeries];
  const min = Math.min(...all);
  const max = Math.max(...all);
  const range = max - min || 1;
  const padY = 18;
  const innerH = height - padY * 2;

  const toPoints = (arr: number[]) =>
    arr
      .map((v, i) => {
        const x = (i / Math.max(1, arr.length - 1)) * width;
        const y = padY + (1 - (v - min) / range) * innerH;
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(" ");

  const execLine = toPoints(series);
  const provLine = toPoints(provSeries);
  const execFill = `0,${height - padY} ${execLine} ${width},${height - padY}`;

  const gridRows = [0.25, 0.5, 0.75];

  return (
    <div style={{ width: "100%" }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        style={{ width: "100%", height: "auto", display: "block" }}
      >
        {gridRows.map((r, i) => {
          const y = padY + r * innerH;
          return (
            <line
              key={i}
              x1={0}
              x2={width}
              y1={y}
              y2={y}
              stroke="var(--ts-line)"
              strokeWidth={0.8}
              strokeDasharray="3 4"
            />
          );
        })}
        <polyline points={execFill} fill="var(--ts-accent)" fillOpacity={0.12} stroke="none" />
        <polyline
          points={execLine}
          fill="none"
          stroke="var(--ts-accent)"
          strokeWidth={1.6}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        <polyline
          points={provLine}
          fill="none"
          stroke="var(--ts-info)"
          strokeWidth={1.4}
          strokeLinejoin="round"
          strokeLinecap="round"
          strokeDasharray="5 4"
        />
      </svg>
      <div
        className="mono flex justify-between"
        style={{
          fontSize: 10,
          color: "var(--ts-text-4)",
          letterSpacing: "0.08em",
          marginTop: 4,
          padding: "0 2px",
        }}
      >
        <span>−60s</span>
        <span>−45s</span>
        <span>−30s</span>
        <span>−15s</span>
        <span>now</span>
      </div>
    </div>
  );
}
