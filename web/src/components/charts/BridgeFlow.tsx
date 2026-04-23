import { ReactElement } from "react";
import Panel from "@/components/ui/Panel";

type Props = {
  bsvLocked: string;
  wbsvSupply: string;
  subCovenants: number;
};

// BridgeFlow renders the two-pane BSV↔wBSV reserve panel. Left pane
// shows native BSV value locked; right pane shows the wrapped wBSV
// circulating supply. Separated by a "1:1" vertical divider that
// doubles as the peg assertion.
export default function BridgeFlow({
  bsvLocked,
  wbsvSupply,
  subCovenants,
}: Props): ReactElement {
  return (
    <Panel
      title="Bridge reserve"
      kicker="BSV ↔ wBSV · 1:1 peg"
      statusDot="ok"
      meta={`${subCovenants} sub-covenants`}
    >
      <div
        className="grid"
        style={{
          gridTemplateColumns: "1fr auto 1fr",
          gap: 24,
          alignItems: "center",
          minHeight: 140,
        }}
      >
        <div className="flex flex-col gap-2">
          <span
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "var(--ts-text-3)",
            }}
          >
            BSV locked
          </span>
          <span className="mono" style={{ fontSize: 34, lineHeight: 1 }}>
            {splitValue(bsvLocked).whole}
            <span style={{ color: "var(--ts-text-4)" }}>
              {splitValue(bsvLocked).dec}
            </span>
            <span
              style={{ color: "var(--ts-text-3)", fontSize: 14, marginLeft: 6 }}
            >
              wBSV
            </span>
          </span>
          <span
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            reserve held by covenant UTXOs
          </span>
        </div>

        <div
          className="flex items-center justify-center"
          style={{
            flexDirection: "column",
            gap: 8,
            color: "var(--ts-accent)",
          }}
        >
          <div
            style={{
              width: 1,
              height: 40,
              background:
                "linear-gradient(to bottom, transparent, var(--ts-line-2), transparent)",
            }}
          />
          <span
            className="mono"
            style={{
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: "0.08em",
              color: "var(--ts-accent)",
              padding: "2px 10px",
              border: "1px solid var(--ts-accent)",
              borderRadius: 3,
            }}
          >
            1 : 1
          </span>
          <div
            style={{
              width: 1,
              height: 40,
              background:
                "linear-gradient(to bottom, transparent, var(--ts-line-2), transparent)",
            }}
          />
        </div>

        <div
          className="flex flex-col gap-2"
          style={{ alignItems: "flex-end", textAlign: "right" }}
        >
          <span
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "var(--ts-text-3)",
            }}
          >
            wBSV supply
          </span>
          <span className="mono" style={{ fontSize: 34, lineHeight: 1 }}>
            {splitValue(wbsvSupply).whole}
            <span style={{ color: "var(--ts-text-4)" }}>
              {splitValue(wbsvSupply).dec}
            </span>
            <span
              style={{ color: "var(--ts-text-3)", fontSize: 14, marginLeft: 6 }}
            >
              wBSV
            </span>
          </span>
          <span
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            circulating on L2
          </span>
        </div>
      </div>
    </Panel>
  );
}

function splitValue(v: string): { whole: string; dec: string } {
  const i = v.indexOf(".");
  if (i < 0) return { whole: v, dec: "" };
  return { whole: v.slice(0, i), dec: v.slice(i) };
}
