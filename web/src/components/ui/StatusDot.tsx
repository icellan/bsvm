import { ReactElement } from "react";

export type Tone = "ok" | "warn" | "bad" | "info" | "accent" | "neutral" | "idle";

const TONE_COLOR: Record<Tone, string> = {
  ok: "var(--ts-ok)",
  warn: "var(--ts-warn)",
  bad: "var(--ts-bad)",
  info: "var(--ts-info)",
  accent: "var(--ts-accent)",
  neutral: "var(--ts-text-3)",
  idle: "var(--ts-text-4)",
};

type Props = {
  tone?: Tone;
  size?: number;
  pulse?: boolean | "fast" | "urgent";
  glow?: boolean;
  className?: string;
};

export default function StatusDot({
  tone = "neutral",
  size = 8,
  pulse = false,
  glow = true,
  className = "",
}: Props): ReactElement {
  const color = TONE_COLOR[tone];
  const pulseClass =
    pulse === "fast"
      ? "ts-pulse-fast"
      : pulse === "urgent"
      ? "ts-pulse-urgent"
      : pulse
      ? "ts-pulse"
      : "";
  return (
    <span
      aria-hidden="true"
      className={`${pulseClass} ${className}`.trim()}
      style={{
        display: "inline-block",
        width: size,
        height: size,
        borderRadius: "50%",
        background: color,
        color,
        boxShadow: glow ? "0 0 6px currentColor" : "none",
        flex: "0 0 auto",
      }}
    />
  );
}
