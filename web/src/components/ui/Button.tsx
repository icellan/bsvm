import { ButtonHTMLAttributes, ReactElement } from "react";

type Variant = "primary" | "ghost" | "danger" | "accent-ghost";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "md";
};

// Button — mission-control styled button. 11px mono, modest padding,
// hover lifts the bg one level (bg-2 → bg-3). Primary is the
// chartreuse accent; danger is red outline; ghost is transparent.
export default function Button({
  variant = "ghost",
  size = "md",
  className = "",
  style,
  ...rest
}: Props): ReactElement {
  const base: React.CSSProperties = {
    fontFamily:
      '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
    fontSize: 11,
    fontWeight: variant === "primary" ? 600 : 500,
    padding: size === "sm" ? "4px 8px" : "6px 12px",
    borderRadius: 4,
    cursor: "pointer",
    transition: "filter 120ms ease, background 120ms ease",
    whiteSpace: "nowrap",
    letterSpacing: "0.02em",
  };

  const variantStyle: React.CSSProperties = (() => {
    switch (variant) {
      case "primary":
        return {
          background: "var(--ts-accent)",
          color: "var(--ts-accent-ink)",
          border: "1px solid var(--ts-accent)",
        };
      case "danger":
        return {
          background: "transparent",
          color: "var(--ts-bad)",
          border:
            "1px solid color-mix(in srgb, var(--ts-bad) 50%, transparent)",
        };
      case "accent-ghost":
        return {
          background: "transparent",
          color: "var(--ts-accent)",
          border:
            "1px solid color-mix(in srgb, var(--ts-accent) 40%, transparent)",
        };
      case "ghost":
      default:
        return {
          background: "var(--ts-bg-2)",
          color: "var(--ts-text-2)",
          border: "1px solid var(--ts-line-2)",
        };
    }
  })();

  return (
    <button
      {...rest}
      className={`${className} hover:brightness-110`}
      style={{ ...base, ...variantStyle, ...style }}
    />
  );
}
