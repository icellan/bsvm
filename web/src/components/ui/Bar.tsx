import { ReactElement } from "react";
import type { Tone } from "./StatusDot";

type Props = {
  value: number;
  max?: number;
  tone?: Tone;
  height?: number;
  className?: string;
};

const TONE_COLOR: Record<Tone, string> = {
  ok: "var(--ts-ok)",
  warn: "var(--ts-warn)",
  bad: "var(--ts-bad)",
  info: "var(--ts-info)",
  accent: "var(--ts-accent)",
  neutral: "var(--ts-text-3)",
  idle: "var(--ts-text-4)",
};

// Bar renders a thin rounded progress/fill bar used in gas-used,
// claim-window, reserve-utilisation, proposal-progress contexts.
export default function Bar({
  value,
  max = 100,
  tone = "accent",
  height = 6,
  className = "",
}: Props): ReactElement {
  const pct = max <= 0 ? 0 : Math.max(0, Math.min(1, value / max));
  return (
    <div
      className={className}
      style={{
        width: "100%",
        height,
        background: "var(--ts-bg-3)",
        borderRadius: height,
        overflow: "hidden",
      }}
      role="progressbar"
      aria-valuenow={Math.round(pct * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        style={{
          width: `${pct * 100}%`,
          height: "100%",
          background: TONE_COLOR[tone],
          borderRadius: height,
          transition: "width 240ms ease",
        }}
      />
    </div>
  );
}
