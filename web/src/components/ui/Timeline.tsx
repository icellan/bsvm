import { ReactElement } from "react";

export type StepState = "ok" | "progress" | "pending";

export type Step = {
  label: string;
  state: StepState;
  timestamp?: string;
  detail?: string;
};

// Timeline renders the confirmation-pipeline strip: a stack of rows
// with a 12×12 state box + label + mono timestamp.
export default function Timeline({ steps }: { steps: Step[] }): ReactElement {
  return (
    <ol className="flex flex-col" style={{ gap: 10 }}>
      {steps.map((s, i) => (
        <li key={i} className="flex items-center gap-3">
          <span
            className={s.state === "progress" ? "ts-pulse-fast" : ""}
            style={{
              width: 12,
              height: 12,
              flex: "0 0 auto",
              borderRadius: 2,
              background:
                s.state === "ok"
                  ? "var(--ts-ok)"
                  : s.state === "progress"
                  ? "var(--ts-accent)"
                  : "transparent",
              border:
                s.state === "pending"
                  ? "1px solid var(--ts-line-2)"
                  : "1px solid transparent",
              boxShadow:
                s.state === "ok"
                  ? "0 0 6px color-mix(in srgb, var(--ts-ok) 70%, transparent)"
                  : s.state === "progress"
                  ? "0 0 6px color-mix(in srgb, var(--ts-accent) 70%, transparent)"
                  : "none",
            }}
          />
          <div className="flex-1 min-w-0">
            <div
              style={{
                fontSize: 12,
                color:
                  s.state === "pending" ? "var(--ts-text-3)" : "var(--ts-text)",
              }}
            >
              {s.label}
            </div>
            {s.detail ? (
              <div
                className="mono truncate"
                style={{ fontSize: 10, color: "var(--ts-text-3)" }}
              >
                {s.detail}
              </div>
            ) : null}
          </div>
          {s.timestamp ? (
            <div
              className="mono whitespace-nowrap"
              style={{ fontSize: 10, color: "var(--ts-text-4)" }}
            >
              {s.timestamp}
            </div>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
