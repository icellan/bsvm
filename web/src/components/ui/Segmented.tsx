import { ReactElement } from "react";

type Option<T extends string> = { value: T; label: string };

type Props<T extends string> = {
  options: Option<T>[];
  value: T;
  onChange: (v: T) => void;
  className?: string;
  size?: "sm" | "md";
};

// Segmented is a labeled button group with a single active option.
// Used for log level filter, address tx direction filter, etc.
export default function Segmented<T extends string>({
  options,
  value,
  onChange,
  className = "",
  size = "md",
}: Props<T>): ReactElement {
  return (
    <div
      role="tablist"
      className={`inline-flex ${className}`}
      style={{
        background: "var(--ts-bg-2)",
        border: "1px solid var(--ts-line)",
        borderRadius: 4,
        padding: 2,
      }}
    >
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            role="tab"
            aria-selected={on}
            onClick={() => onChange(o.value)}
            className="mono"
            style={{
              fontSize: size === "sm" ? 10 : 11,
              padding: size === "sm" ? "3px 8px" : "4px 10px",
              borderRadius: 3,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              border: "none",
              background: on ? "var(--ts-accent)" : "transparent",
              color: on ? "var(--ts-accent-ink)" : "var(--ts-text-2)",
              cursor: "pointer",
              fontWeight: on ? 600 : 500,
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
