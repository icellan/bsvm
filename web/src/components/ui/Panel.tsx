import { PropsWithChildren, ReactElement, ReactNode } from "react";
import StatusDot, { Tone } from "./StatusDot";

type Props = PropsWithChildren<{
  title?: ReactNode;
  kicker?: ReactNode;
  meta?: ReactNode;
  statusDot?: Tone;
  className?: string;
  bodyClassName?: string;
  padded?: boolean;
}>;

// Panel is the core card shell: 1px border, no shadow, optional
// header with title/meta row. All panels share this chrome so
// restyles land in one place.
export default function Panel({
  title,
  kicker,
  meta,
  statusDot,
  className = "",
  bodyClassName = "",
  padded = true,
  children,
}: Props): ReactElement {
  return (
    <section
      className={`flex flex-col ${className}`}
      style={{
        background: "var(--ts-bg-1)",
        border: "1px solid var(--ts-line)",
        borderRadius: 6,
      }}
    >
      {title || kicker || meta ? (
        <header
          className="flex items-center justify-between"
          style={{
            padding: "10px 14px 8px",
            borderBottom: "1px solid var(--ts-line)",
          }}
        >
          <div className="flex items-center gap-2 min-w-0">
            {statusDot ? <StatusDot tone={statusDot} size={7} /> : null}
            <div className="min-w-0">
              {kicker ? (
                <div
                  className="mono"
                  style={{
                    fontSize: 10,
                    letterSpacing: "0.14em",
                    textTransform: "uppercase",
                    color: "var(--ts-text-3)",
                  }}
                >
                  {kicker}
                </div>
              ) : null}
              {title ? (
                <h2
                  className="truncate"
                  style={{
                    fontSize: 12,
                    fontWeight: 500,
                    color: "var(--ts-text)",
                  }}
                >
                  {title}
                </h2>
              ) : null}
            </div>
          </div>
          {meta ? (
            <div
              className="mono whitespace-nowrap"
              style={{ fontSize: 11, color: "var(--ts-text-3)" }}
            >
              {meta}
            </div>
          ) : null}
        </header>
      ) : null}
      <div className={bodyClassName} style={padded ? { padding: 14 } : undefined}>
        {children}
      </div>
    </section>
  );
}
