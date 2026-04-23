import { useState } from "react";

// Copy renders a hex / address with a click-to-copy affordance.
// Used throughout the explorer so every table row carries the same
// interaction for grabbing a hash.
//
// When `responsive` is true and no explicit `label` is given, the
// component renders two variants — the full value and a shortened
// form — and CSS media queries hide the one that doesn't belong for
// the current viewport. Desktop shows the full hash; ≤720 px shows
// the shortened form. Copy always writes the full value.
export default function Copy(props: {
  value: string;
  label?: string;
  responsive?: boolean;
}) {
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

  const explicit = props.label !== undefined;

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
        maxWidth: "100%",
      }}
    >
      {explicit || !props.responsive ? (
        <span>{props.label ?? shorten(props.value)}</span>
      ) : (
        <>
          <span className="copy-full">{props.value}</span>
          <span className="copy-short">{shorten(props.value)}</span>
        </>
      )}
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
