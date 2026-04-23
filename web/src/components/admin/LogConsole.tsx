import { ReactElement, useEffect, useRef, useState } from "react";
import { Segmented, Button, Chip } from "@/components/ui";

export type LogRecord = {
  time: string;
  level: "INFO" | "WARN" | "ERROR" | "DEBUG" | string;
  message: string;
  attrs?: Record<string, string>;
};

type Props = {
  records: LogRecord[];
  onClear?: () => void;
  onExport?: () => void;
  height?: number;
};

type Filter = "ALL" | "INFO" | "WARN" | "ERROR" | "DEBUG";

// LogConsole — fixed-height scrolling log surface with level filter,
// pause/clear/export actions. Auto-scrolls to bottom unless paused.
export default function LogConsole({
  records,
  onClear,
  onExport,
  height = 480,
}: Props): ReactElement {
  const [filter, setFilter] = useState<Filter>("ALL");
  const [paused, setPaused] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const filtered = filter === "ALL" ? records : records.filter((r) => r.level.toUpperCase() === filter);

  useEffect(() => {
    if (paused) return;
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "auto" });
  }, [filtered.length, paused]);

  return (
    <div className="flex flex-col" style={{ gap: 8 }}>
      <div className="flex items-center gap-2 flex-wrap">
        <Segmented<Filter>
          size="sm"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "ALL", label: "All" },
            { value: "INFO", label: "Info" },
            { value: "WARN", label: "Warn" },
            { value: "ERROR", label: "Error" },
            { value: "DEBUG", label: "Debug" },
          ]}
        />
        <span className="flex-1" />
        <Button size="sm" onClick={() => setPaused((p) => !p)}>
          {paused ? "▶ resume" : "⏸ pause"}
        </Button>
        {onClear ? (
          <Button size="sm" onClick={onClear}>
            clear
          </Button>
        ) : null}
        {onExport ? (
          <Button size="sm" onClick={onExport}>
            export
          </Button>
        ) : null}
        <Chip tone="neutral">{filtered.length} lines</Chip>
      </div>
      <div
        ref={ref}
        className="mono"
        style={{
          height,
          overflow: "auto",
          background: "var(--ts-bg)",
          border: "1px solid var(--ts-line)",
          borderRadius: 4,
          padding: "10px 12px",
          fontSize: 11,
          lineHeight: 1.55,
          color: "var(--ts-text-2)",
        }}
      >
        {filtered.length === 0 ? (
          <div style={{ color: "var(--ts-text-3)" }}>Waiting for log records…</div>
        ) : (
          filtered.map((r, i) => (
            <div key={i} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              <span style={{ color: "var(--ts-text-4)" }}>{r.time} </span>
              <span style={{ color: levelColor(r.level) }}>[{r.level}]</span>{" "}
              <span>{r.message}</span>
              {r.attrs && Object.keys(r.attrs).length > 0 ? (
                <span style={{ color: "var(--ts-text-3)" }}>
                  {" "}
                  {Object.entries(r.attrs)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(" ")}
                </span>
              ) : null}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function levelColor(level: string): string {
  switch (level.toUpperCase()) {
    case "DEBUG":
      return "var(--ts-text-3)";
    case "WARN":
      return "var(--ts-warn)";
    case "ERROR":
      return "var(--ts-bad)";
    default:
      return "var(--ts-info)";
  }
}
