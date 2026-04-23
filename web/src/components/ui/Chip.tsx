import { PropsWithChildren, ReactElement } from "react";
import StatusDot, { Tone } from "./StatusDot";

type Props = PropsWithChildren<{
  tone?: Tone;
  dot?: boolean;
  className?: string;
  uppercase?: boolean;
}>;

const TONE_BORDER: Record<Tone, string> = {
  ok: "color-mix(in srgb, var(--ts-ok) 40%, transparent)",
  warn: "color-mix(in srgb, var(--ts-warn) 40%, transparent)",
  bad: "color-mix(in srgb, var(--ts-bad) 40%, transparent)",
  info: "color-mix(in srgb, var(--ts-info) 40%, transparent)",
  accent: "color-mix(in srgb, var(--ts-accent) 40%, transparent)",
  neutral: "var(--ts-line-2)",
  idle: "var(--ts-line-2)",
};

const TONE_TEXT: Record<Tone, string> = {
  ok: "var(--ts-ok)",
  warn: "var(--ts-warn)",
  bad: "var(--ts-bad)",
  info: "var(--ts-info)",
  accent: "var(--ts-accent)",
  neutral: "var(--ts-text-3)",
  idle: "var(--ts-text-4)",
};

// Chip is the standard small status pill used across tables, headers,
// and alert strips. 10px mono, 3px radius, 1px border.
export default function Chip({
  tone = "neutral",
  dot = false,
  uppercase = true,
  className = "",
  children,
}: Props): ReactElement {
  return (
    <span
      className={`mono inline-flex items-center gap-1.5 px-2 py-[2px] ${className}`}
      style={{
        border: `1px solid ${TONE_BORDER[tone]}`,
        color: TONE_TEXT[tone],
        borderRadius: 3,
        fontSize: 10,
        letterSpacing: uppercase ? "0.08em" : undefined,
        textTransform: uppercase ? "uppercase" : undefined,
        lineHeight: 1.4,
      }}
    >
      {dot ? <StatusDot tone={tone} size={6} glow={false} /> : null}
      {children}
    </span>
  );
}
