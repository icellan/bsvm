import { useEffect, useRef, useState } from "react";

import { useSession } from "@/state/session";
import { ws } from "@/rpc/ws";
import Panel from "@/components/Panel";

type LogRecord = {
  time: string;
  level: string;
  message: string;
  attrs?: Record<string, string>;
};

// AdminLogs subscribes to the node's adminLogs WS stream and pretty-
// prints incoming records. The browser can't send headers on the WS
// upgrade, so we send `admin_authenticate` as the first message and
// only open the subscription after it resolves.
export default function AdminLogs() {
  const session = useSession((s) => s.session);
  const [records, setRecords] = useState<LogRecord[]>([]);
  const [paused, setPaused] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!session) return;
    const mgr = ws();
    if (session.kind === "devAuth") {
      mgr.setAuthToken({ kind: "devAuth", value: session.secret });
    } else {
      mgr.setAuthToken({ kind: "sessionNonce", value: session.serverNonce });
    }
    const handle = mgr.subscribe({
      type: "adminLogs",
      onEvent: (evt) => {
        const rec = evt as LogRecord;
        setRecords((r) => {
          const next = r.concat(rec);
          return next.length > 500 ? next.slice(-500) : next;
        });
      },
    });
    return () => handle.cancel();
  }, [session]);

  useEffect(() => {
    if (paused) return;
    containerRef.current?.scrollTo({
      top: containerRef.current.scrollHeight,
      behavior: "auto",
    });
  }, [records, paused]);

  return (
    <Panel
      title="Live logs"
      subtitle={
        <button
          onClick={() => setPaused((p) => !p)}
          className="text-xs text-muted hover:text-fg"
        >
          {paused ? "resume autoscroll" : "pause autoscroll"}
        </button>
      }
    >
      <div
        ref={containerRef}
        className="max-h-[60vh] overflow-auto rounded-md bg-bg p-3 font-mono text-xs"
      >
        {records.length === 0 ? (
          <p className="text-muted">
            Waiting for log records…
          </p>
        ) : (
          records.map((r, i) => (
            <div key={i} className="whitespace-pre-wrap">
              <span className={levelClass(r.level)}>[{r.level}]</span>{" "}
              <span className="text-muted">{r.time}</span> {r.message}{" "}
              {r.attrs && Object.keys(r.attrs).length > 0 ? (
                <span className="text-muted">
                  {Object.entries(r.attrs)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(" ")}
                </span>
              ) : null}
            </div>
          ))
        )}
      </div>
    </Panel>
  );
}

function levelClass(level: string): string {
  switch (level.toUpperCase()) {
    case "DEBUG":
      return "text-muted";
    case "WARN":
      return "text-warning";
    case "ERROR":
      return "text-danger";
    default:
      return "text-accent";
  }
}
