import { ReactElement, ReactNode } from "react";
import Sparkline from "./Sparkline";
import type { Tone } from "./StatusDot";

type Props = {
  label: ReactNode;
  value: ReactNode;
  unit?: ReactNode;
  delta?: { value: string; tone?: Tone };
  sparkData?: number[];
  sparkColor?: string;
  sparkFill?: number;
  valueTone?: Tone | "default";
  className?: string;
};

const TONE_COLOR: Record<Tone | "default", string> = {
  ok: "var(--ts-ok)",
  warn: "var(--ts-warn)",
  bad: "var(--ts-bad)",
  info: "var(--ts-info)",
  accent: "var(--ts-accent)",
  neutral: "var(--ts-text)",
  idle: "var(--ts-text-4)",
  default: "var(--ts-text)",
};

// KPI is the headline metric card used on every dashboard-like screen.
// 10px uppercase kicker, optional delta line, 30px mono value, optional
// small unit in text-3, 22px-tall sparkline anchored at the bottom.
export default function KPI({
  label,
  value,
  unit,
  delta,
  sparkData,
  sparkColor,
  sparkFill = 0.12,
  valueTone = "default",
  className = "",
}: Props): ReactElement {
  return (
    <div
      className={`flex flex-col gap-1 ${className}`}
      style={{
        background: "var(--ts-bg-1)",
        border: "1px solid var(--ts-line)",
        borderRadius: 6,
        padding: 14,
        minHeight: 108,
      }}
    >
      <div className="flex items-baseline justify-between gap-2">
        <div
          className="mono"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-text-3)",
          }}
        >
          {label}
        </div>
        {delta ? (
          <span
            className="mono"
            style={{
              fontSize: 10,
              color: delta.tone ? TONE_COLOR[delta.tone] : "var(--ts-text-3)",
            }}
          >
            {delta.value}
          </span>
        ) : null}
      </div>
      <div className="flex items-baseline gap-2 min-w-0">
        <span
          className="mono truncate"
          style={{
            fontSize: 30,
            fontWeight: 500,
            letterSpacing: "-0.02em",
            color: TONE_COLOR[valueTone],
            lineHeight: 1.1,
          }}
        >
          {value}
        </span>
        {unit ? (
          <span
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            {unit}
          </span>
        ) : null}
      </div>
      <div style={{ marginTop: "auto", paddingTop: 6, height: 22, width: "100%", overflow: "hidden" }}>
        {sparkData && sparkData.length > 0 ? (
          <Sparkline
            data={sparkData}
            height={22}
            color={sparkColor ?? TONE_COLOR[valueTone]}
            fillOpacity={sparkFill}
          />
        ) : (
          <div style={{ height: 22 }} />
        )}
      </div>
    </div>
  );
}
