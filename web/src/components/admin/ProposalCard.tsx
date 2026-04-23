import { ReactElement } from "react";
import { Bar, Button } from "@/components/ui";

export type SigChip = { pk: string; name?: string; signed: boolean };

type Props = {
  id: string;
  action: string;
  label?: string;
  required: number;
  sigs: number;
  signers: SigChip[];
  created?: string;
  expires?: string;
  ready?: boolean;
  onSign?: () => void;
  onBroadcast?: () => void;
  signPending?: boolean;
};

// ProposalCard — the atomic governance-proposal display: id, action,
// signature count, progress bar, sig-chip row, actions (sign / broad-
// cast). Used on /admin/governance and inline on /admin/config for
// the pending change panel.
export default function ProposalCard({
  id,
  action,
  label,
  required,
  sigs,
  signers,
  created,
  expires,
  ready,
  onSign,
  onBroadcast,
  signPending,
}: Props): ReactElement {
  const pct = required > 0 ? Math.min(100, (sigs / required) * 100) : 0;
  return (
    <div
      style={{
        border: "1px solid var(--ts-line)",
        borderRadius: 6,
        padding: 14,
        background: "var(--ts-bg-1)",
      }}
    >
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <div
            className="mono"
            style={{ fontSize: 10, color: "var(--ts-text-3)" }}
          >
            {id}
          </div>
          <div
            className="mt-1"
            style={{ fontSize: 20, fontWeight: 500, letterSpacing: "-0.01em" }}
          >
            <span style={{ color: "var(--ts-accent)" }}>{action}</span>
            {label ? (
              <span
                style={{
                  color: "var(--ts-text-3)",
                  marginLeft: 10,
                  fontSize: 14,
                }}
              >
                · {label}
              </span>
            ) : null}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div
            className="mono"
            style={{ fontSize: 26, fontWeight: 500, color: "var(--ts-text)" }}
          >
            {sigs}
            <span style={{ color: "var(--ts-text-4)", fontSize: 16 }}>
              /{required}
            </span>
          </div>
          <div
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: ready ? "var(--ts-ok)" : "var(--ts-text-3)",
            }}
          >
            {ready ? "ready" : "signatures"}
          </div>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <Bar
          value={pct}
          max={100}
          tone={ready ? "ok" : pct >= 50 ? "accent" : "info"}
        />
      </div>

      {signers.length > 0 ? (
        <div className="flex flex-wrap gap-2" style={{ marginTop: 12 }}>
          {signers.map((s, i) => (
            <span
              key={i}
              className="mono inline-flex items-center gap-1.5 px-2 py-0.5"
              title={s.pk}
              style={{
                fontSize: 10,
                borderRadius: 3,
                border: "1px solid var(--ts-line-2)",
                color: s.signed ? "var(--ts-ok)" : "var(--ts-text-3)",
                background: s.signed
                  ? "color-mix(in srgb, var(--ts-ok) 10%, transparent)"
                  : "transparent",
              }}
            >
              <span style={{ fontSize: 9 }}>{s.signed ? "✓" : "○"}</span>
              {s.name ?? s.pk.slice(0, 10)}
            </span>
          ))}
        </div>
      ) : null}

      <div
        className="flex items-center justify-between mt-3 flex-wrap gap-3"
        style={{
          paddingTop: 10,
          borderTop: "1px solid var(--ts-line)",
        }}
      >
        <div
          className="mono"
          style={{ fontSize: 10, color: "var(--ts-text-4)" }}
        >
          {created ? `created ${created}` : ""}
          {expires ? ` · expires ${expires}` : ""}
        </div>
        <div className="flex gap-2">
          {onSign ? (
            <Button variant="primary" onClick={onSign} disabled={signPending}>
              {signPending ? "Signing…" : "Sign with wallet"}
            </Button>
          ) : null}
          {onBroadcast ? (
            <Button
              variant={ready ? "accent-ghost" : "ghost"}
              onClick={onBroadcast}
              disabled={!ready}
            >
              {ready ? "Broadcast · ready" : "Broadcast"}
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
