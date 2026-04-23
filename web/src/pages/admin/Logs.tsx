import { useEffect, useState } from "react";

import { useSession } from "@/state/session";
import { ws } from "@/rpc/ws";
import { Panel } from "@/components/ui";
import LogConsole, { LogRecord } from "@/components/admin/LogConsole";

// Admin Logs — live-streaming log console backed by the adminLogs WS
// subscription. Records held in a 500-line in-memory ring (older
// records drop as new ones arrive).
export default function AdminLogs() {
  const session = useSession((s) => s.session);
  const [records, setRecords] = useState<LogRecord[]>([]);

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

  function exportLogs() {
    const text = records
      .map((r) => {
        const attrs = r.attrs
          ? " " +
            Object.entries(r.attrs)
              .map(([k, v]) => `${k}=${v}`)
              .join(" ")
          : "";
        return `${r.time} [${r.level}] ${r.message}${attrs}`;
      })
      .join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bsvm-logs-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div>
        <div
          className="mono"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-text-3)",
          }}
        >
          Admin · logs
        </div>
        <h1
          className="mt-1"
          style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Live logs
        </h1>
      </div>

      <Panel title="Console" kicker="admin_logs · streaming" statusDot={records.length > 0 ? "ok" : "warn"}>
        <LogConsole
          records={records}
          onClear={() => setRecords([])}
          onExport={exportLogs}
          height={520}
        />
      </Panel>
    </div>
  );
}
