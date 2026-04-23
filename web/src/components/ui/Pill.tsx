import { PropsWithChildren, ReactElement } from "react";
import StatusDot, { Tone } from "./StatusDot";

type Props = PropsWithChildren<{
  tone?: Tone;
  dot?: boolean;
  className?: string;
}>;

// Pill is the rounded status badge used in the top chrome
// (peer / quorum / chain indicators). 11px mono, border, rounded.
export default function Pill({
  tone = "neutral",
  dot = false,
  className = "",
  children,
}: Props): ReactElement {
  return (
    <span
      className={`mono inline-flex items-center gap-1.5 px-2.5 py-1 ${className}`}
      style={{
        border: "1px solid var(--ts-line-2)",
        color: tone === "neutral" ? "var(--ts-text-2)" : undefined,
        borderRadius: 999,
        fontSize: 11,
        lineHeight: 1.2,
      }}
    >
      {dot ? <StatusDot tone={tone} size={7} pulse /> : null}
      {children}
    </span>
  );
}
