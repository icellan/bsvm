import { PropsWithChildren, ReactElement } from "react";
import { NavLink as RRNavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { useSession } from "@/state/session";
import { shorten } from "@/components/Copy";
import { adminRPC } from "@/pages/admin/rpc";
import { bsv } from "@/rpc/client";

type SideItem = {
  to: string;
  label: string;
  end?: boolean;
  tag?: string;
  tagTone?: "ok" | "warn" | "bad" | "info" | "accent" | "neutral";
};

// AdminShell — two-column layout shared by every admin view. Left
// sidebar holds the signed-in identity card + nav; right column is
// the page body.
export default function AdminShell({ children }: PropsWithChildren): ReactElement {
  const session = useSession((s) => s.session);
  const clear = useSession((s) => s.clear);
  const nav = useNavigate();

  const proposals = useQuery({
    queryKey: ["admin_listGovernanceProposals"],
    queryFn: () => adminRPC<{ id: string }[]>("admin_listGovernanceProposals"),
    refetchInterval: 15_000,
    enabled: !!session,
  });
  const proving = useQuery({
    queryKey: ["bsv_provingStatus"],
    queryFn: bsv.provingStatus,
    refetchInterval: 5_000,
    enabled: !!session,
  });
  const shard = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
    refetchInterval: 10_000,
    enabled: !!session,
  });

  const proposalCount = proposals.data?.length ?? 0;
  const proverMode = proving.data?.mode ?? "—";
  const restart = !!shard.data?.governance.frozen;

  const NAV: SideItem[] = [
    { to: "/admin", label: "Dashboard", end: true },
    {
      to: "/admin/governance",
      label: "Governance",
      tag: proposalCount > 0 ? String(proposalCount) : undefined,
      tagTone: "accent",
    },
    {
      to: "/admin/config",
      label: "Config",
      tag: restart ? "restart" : undefined,
      tagTone: "warn",
    },
    {
      to: "/admin/prover",
      label: "Prover",
      tag: proverMode === "paused" ? "paused" : undefined,
      tagTone: "warn",
    },
    { to: "/admin/logs", label: "Logs" },
  ];

  const identity =
    session?.kind === "brc100"
      ? shorten(session.identityKey)
      : session?.kind === "devAuth"
      ? "dev-auth"
      : "—";

  return (
    <div
      className="grid"
      style={{
        gridTemplateColumns: "220px 1fr",
        gap: 10,
        alignItems: "start",
      }}
    >
      <aside className="flex flex-col" style={{ gap: 10 }}>
        <div
          style={{
            border: "1px solid var(--ts-line)",
            borderRadius: 6,
            padding: 12,
            background: "var(--ts-bg-1)",
          }}
        >
          <div
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "var(--ts-text-3)",
            }}
          >
            Signed in
          </div>
          <div
            className="mono"
            style={{ marginTop: 4, fontSize: 12, color: "var(--ts-accent)" }}
          >
            {identity}
          </div>
          <div
            className="mono"
            style={{ marginTop: 4, fontSize: 10, color: "var(--ts-text-3)" }}
          >
            role · governance
          </div>
          <button
            onClick={() => {
              clear();
              nav("/admin/session");
            }}
            className="mono"
            style={{
              marginTop: 10,
              width: "100%",
              background: "transparent",
              border: "1px solid var(--ts-line-2)",
              borderRadius: 4,
              padding: "4px 8px",
              color: "var(--ts-text-3)",
              fontSize: 10,
              cursor: "pointer",
            }}
          >
            sign out
          </button>
        </div>
        <nav className="flex flex-col" style={{ gap: 1 }}>
          {NAV.map((it) => (
            <RRNavLink
              key={it.to}
              to={it.to}
              end={it.end}
              className={({ isActive }) =>
                "admin-side-link " + (isActive ? "is-active" : "")
              }
              style={({ isActive }) => ({
                padding: "8px 12px",
                fontSize: 12,
                color: isActive ? "var(--ts-text)" : "var(--ts-text-3)",
                background: isActive ? "var(--ts-bg-2)" : "transparent",
                borderLeft: isActive
                  ? "2px solid var(--ts-accent)"
                  : "2px solid transparent",
                borderRadius: 2,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
              })}
            >
              <span>{it.label}</span>
              {it.tag ? <SideTag label={it.tag} tone={it.tagTone ?? "neutral"} /> : null}
            </RRNavLink>
          ))}
        </nav>
      </aside>
      <main style={{ minWidth: 0 }}>{children}</main>
    </div>
  );
}

function SideTag({
  label,
  tone,
}: {
  label: string;
  tone: "ok" | "warn" | "bad" | "info" | "accent" | "neutral";
}) {
  const color =
    tone === "ok"
      ? "var(--ts-ok)"
      : tone === "warn"
      ? "var(--ts-warn)"
      : tone === "bad"
      ? "var(--ts-bad)"
      : tone === "info"
      ? "var(--ts-info)"
      : tone === "accent"
      ? "var(--ts-accent)"
      : "var(--ts-text-3)";
  return (
    <span
      className="mono"
      style={{
        fontSize: 9,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        color,
        border: "1px solid color-mix(in srgb, currentColor 45%, transparent)",
        borderRadius: 3,
        padding: "1px 5px",
        lineHeight: 1.3,
      }}
    >
      {label}
    </span>
  );
}
