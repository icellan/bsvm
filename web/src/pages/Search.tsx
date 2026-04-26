import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import SearchBar, { SearchBarResult } from "@/components/SearchBar";
import { Panel, Chip } from "@/components/ui";
import { resolve, ResolveResult, stageLabel, Stage } from "@/rpc/searchResolver";

// Search — full-page resolver. The wide SearchBar variant lives at
// the top, with an inline result panel below that mirrors the
// progressive feedback from the resolver. Two entry paths:
//
//   1. Direct navigation with `?q=` — the page runs the resolver
//      once and either redirects (on hit) or shows the miss panel.
//   2. Inline typing into the bar — the SearchBar drives the
//      result state and the page renders it without ever leaving
//      this route until the user clicks the resolved link.
export default function Search() {
  const [sp] = useSearchParams();
  const navigate = useNavigate();
  const initialQ = sp.get("q")?.trim() ?? "";

  const [result, setResult] = useState<SearchBarResult>(
    initialQ ? { state: "resolving", stage: "classifying", query: initialQ } : { state: "idle" },
  );
  const [urlResolved, setUrlResolved] = useState<ResolveResult | null>(null);
  const [urlStage, setUrlStage] = useState<Stage>("idle");

  // When the page is visited with `?q=`, resolve once on mount and
  // auto-redirect on a hit. The SearchBar takes over after the user
  // edits the input.
  useEffect(() => {
    if (!initialQ) return;
    let cancelled = false;
    (async () => {
      const r = await resolve(initialQ, {
        onStage: (s) => {
          if (!cancelled) setUrlStage(s);
        },
      });
      if (cancelled) return;
      setUrlResolved(r);
      if (r.kind !== "none") {
        navigate(r.route, { replace: true });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [initialQ, navigate]);

  return (
    <div className="flex flex-col" style={{ gap: 16, maxWidth: 720, margin: "0 auto" }}>
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
          Universal search
        </div>
        <h1
          className="mt-1 mono"
          style={{ fontSize: 18, fontWeight: 500, color: "var(--ts-text)" }}
        >
          Find a block, transaction, or address
        </h1>
      </div>

      <SearchBar
        variant="wide"
        autoFocus
        autoRedirect
        initialValue={initialQ}
        onResultChange={setResult}
      />

      <ResultPanel
        result={result}
        urlResolved={urlResolved}
        urlStage={urlStage}
        urlQuery={initialQ}
      />

      <Panel title="Tips" kicker="Accepted formats">
        <ul
          className="mono"
          style={{
            fontSize: 11,
            color: "var(--ts-text-3)",
            paddingLeft: 18,
            margin: 0,
            lineHeight: 1.8,
          }}
        >
          <li>
            <span style={{ color: "var(--ts-text)" }}>Block</span> — a decimal
            number (e.g. <code style={{ color: "var(--ts-accent)" }}>123456</code>) or short hex.
          </li>
          <li>
            <span style={{ color: "var(--ts-text)" }}>Transaction</span> — 0x followed by 64 hex chars.
          </li>
          <li>
            <span style={{ color: "var(--ts-text)" }}>Address</span> — 0x followed by 40 hex chars.
          </li>
          <li>
            <span style={{ color: "var(--ts-text)" }}>ENS</span> — recognised but not yet resolved on BSVM v1.
          </li>
        </ul>
      </Panel>
    </div>
  );
}

function ResultPanel(props: {
  result: SearchBarResult;
  urlResolved: ResolveResult | null;
  urlStage: Stage;
  urlQuery: string;
}) {
  // Prefer the live SearchBar state. Fall back to the URL-driven
  // resolver while the bar hasn't been touched (e.g. arriving with
  // `?q=` and the auto-redirect is still in flight).
  if (props.result.state === "idle") {
    if (props.urlQuery) {
      if (props.urlResolved && props.urlResolved.kind !== "none") {
        return (
          <Panel title="Hit" kicker={props.urlResolved.kind}>
            <ResolvedLink result={props.urlResolved} />
          </Panel>
        );
      }
      if (props.urlResolved && props.urlResolved.kind === "none") {
        return (
          <Panel title="No match" kicker={`for "${truncate(props.urlQuery)}"`}>
            <div
              className="mono"
              style={{ fontSize: 11, color: "var(--ts-text-3)" }}
            >
              {props.urlResolved.hint}
            </div>
          </Panel>
        );
      }
      return (
        <Panel title="Resolving" kicker={stageLabel(props.urlStage) || "..."}>
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
            Looking up <span style={{ color: "var(--ts-accent)" }}>{truncate(props.urlQuery)}</span>...
          </div>
        </Panel>
      );
    }
    return null;
  }

  if (props.result.state === "resolving") {
    return (
      <Panel title="Resolving" kicker={stageLabel(props.result.stage) || "..."}>
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
          Looking up <span style={{ color: "var(--ts-accent)" }}>{truncate(props.result.query)}</span>...
        </div>
      </Panel>
    );
  }

  if (props.result.state === "hit") {
    return (
      <Panel title="Hit" kicker={props.result.kind}>
        <div className="flex items-center gap-3">
          <Chip tone="ok" dot>
            match
          </Chip>
          <Link
            to={props.result.route}
            className="mono"
            style={{ fontSize: 12, color: "var(--ts-accent)" }}
          >
            open {props.result.route}
          </Link>
        </div>
      </Panel>
    );
  }

  // miss
  return (
    <Panel title="No match" kicker={`for "${truncate(props.result.query)}"`}>
      <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
        {props.result.hint || "Nothing matched the input."}
      </div>
    </Panel>
  );
}

function ResolvedLink({ result }: { result: ResolveResult }) {
  if (result.kind === "none") return null;
  return (
    <div className="flex items-center gap-3">
      <Chip tone="ok" dot>
        match
      </Chip>
      <Link
        to={result.route}
        className="mono"
        style={{ fontSize: 12, color: "var(--ts-accent)" }}
      >
        {result.route}
      </Link>
    </div>
  );
}

function truncate(v: string): string {
  if (v.length <= 24) return v;
  return `${v.slice(0, 14)}...${v.slice(-6)}`;
}
