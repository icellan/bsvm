import { useState } from "react";

// Copy renders a short hex / address with a click-to-copy affordance.
// Used throughout the explorer so every table row carries the same
// interaction for grabbing a hash.
export default function Copy(props: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function onClick(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(props.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      /* Clipboard denied — ignore. */
    }
  }

  const display = props.label ?? shorten(props.value);

  return (
    <button
      onClick={onClick}
      title={props.value}
      className="mono"
      style={{
        background: "transparent",
        border: "none",
        padding: 0,
        cursor: "pointer",
        color: "inherit",
        fontSize: "inherit",
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
      }}
    >
      <span>{display}</span>
      <span style={{ fontSize: 10, color: copied ? "var(--ts-ok)" : "var(--ts-text-4)" }}>
        {copied ? "✓" : "⎘"}
      </span>
    </button>
  );
}

export function shorten(v: string): string {
  if (!v) return "";
  if (v.length <= 12) return v;
  return `${v.slice(0, 6)}…${v.slice(-4)}`;
}
