import { ReactElement, ReactNode } from "react";

export type KVItem = {
  label: ReactNode;
  value: ReactNode;
  mono?: boolean;
  wide?: boolean;
};

type Props = {
  items: KVItem[];
  columns?: 1 | 2 | 3 | 4;
  className?: string;
};

// KV is the flat label/value grid used across panel bodies. Label is
// 10px uppercase mono; value is 12px, mono when the value is hex.
export default function KV({
  items,
  columns = 2,
  className = "",
}: Props): ReactElement {
  return (
    <dl
      className={className}
      style={{
        display: "grid",
        gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
        rowGap: 12,
        columnGap: 24,
      }}
    >
      {items.map((it, i) => (
        <div
          key={i}
          style={{ gridColumn: it.wide ? `span ${columns}` : undefined }}
        >
          <dt
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "var(--ts-text-3)",
              marginBottom: 4,
            }}
          >
            {it.label}
          </dt>
          <dd
            className={it.mono ? "mono" : undefined}
            style={{
              fontSize: 12,
              color: "var(--ts-text)",
              wordBreak: "break-all",
            }}
          >
            {it.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
