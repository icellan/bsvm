import {
  ChangeEvent,
  FormEvent,
  KeyboardEvent,
  ReactElement,
  useEffect,
  useRef,
  useState,
} from "react";
import { useNavigate } from "react-router-dom";

import { resolve, Stage, stageLabel } from "@/rpc/searchResolver";

// SearchBar is the universal explorer search input. It debounces
// keystrokes by 250 ms, runs a single eth_* probe to classify the
// query (tx hash → address → block), and either redirects to the
// resolved detail page or surfaces an inline hint.
//
// The component renders in two visual modes:
//   * "compact" — used inside the top-of-page Chrome nav. Narrow,
//     mono-font, no inline status strip; submit/enter still works.
//   * "wide"    — used on the standalone /search route. Larger
//     input, progressive status strip ("looking up tx...") and
//     hint pill below.
//
// Auto-redirect can be disabled (`autoRedirect={false}`) when the
// caller wants to render the resolved result inline, e.g. on the
// /search page when the URL `?q=` is being typed by the user.

export type SearchBarProps = {
  variant?: "compact" | "wide";
  initialValue?: string;
  autoRedirect?: boolean;
  // onResultChange fires whenever the resolver settles on a hit or
  // miss. Used by the /search page to render the result body.
  onResultChange?: (result: SearchBarResult) => void;
  placeholder?: string;
  autoFocus?: boolean;
};

export type SearchBarResult =
  | { state: "idle" }
  | { state: "resolving"; stage: Stage; query: string }
  | { state: "hit"; route: string; query: string; kind: string }
  | { state: "miss"; query: string; hint: string };

export default function SearchBar(props: SearchBarProps): ReactElement {
  const {
    variant = "compact",
    initialValue = "",
    autoRedirect = true,
    placeholder = "block · tx · address",
    autoFocus = false,
  } = props;

  const [query, setQuery] = useState(initialValue);
  const [stage, setStage] = useState<Stage>("idle");
  const [result, setResult] = useState<SearchBarResult>({ state: "idle" });
  const navigate = useNavigate();

  // The debounce + abort controller combo keeps the resolver
  // single-flight: every new keystroke cancels the prior request,
  // so the UI never lands on a stale answer.
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  // Sequence id de-duplicates resolve() return values: when two
  // requests overlap (despite abort), only the latest one's result
  // is allowed to mutate state.
  const seqRef = useRef(0);

  // Surface result changes to the parent (used by /search to render
  // an inline hit/miss panel).
  useEffect(() => {
    props.onResultChange?.(result);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]);

  useEffect(() => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    abortRef.current?.abort();

    const t = query.trim();
    if (!t) {
      setStage("idle");
      setResult({ state: "idle" });
      return;
    }

    const controller = new AbortController();
    abortRef.current = controller;
    const seq = ++seqRef.current;

    debounceTimer.current = setTimeout(async () => {
      setResult({ state: "resolving", stage: "classifying", query: t });
      try {
        const res = await resolve(t, {
          signal: controller.signal,
          onStage: (s) => {
            if (seq !== seqRef.current) return;
            setStage(s);
            setResult({ state: "resolving", stage: s, query: t });
          },
        });
        if (seq !== seqRef.current || controller.signal.aborted) return;
        if (res.kind === "none") {
          setResult({ state: "miss", query: t, hint: res.hint });
        } else {
          setResult({
            state: "hit",
            route: res.route,
            query: t,
            kind: res.kind,
          });
          if (autoRedirect) navigate(res.route);
        }
      } catch {
        // Network failure mid-resolve — degrade silently. The caller
        // can retry by typing.
        if (seq === seqRef.current) {
          setResult({ state: "miss", query: t, hint: "lookup failed" });
        }
      } finally {
        if (seq === seqRef.current) setStage("idle");
      }
    }, 250);

    return () => {
      if (debounceTimer.current) clearTimeout(debounceTimer.current);
      controller.abort();
    };
  }, [query, autoRedirect, navigate]);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    // Submit acts as a "force navigate" — regex-classify and bypass
    // the resolver if the input is unambiguous, so power users with
    // hashes pasted from a CLI don't wait for the debounce.
    const t = query.trim();
    if (!t) return;
    if (/^0x[0-9a-fA-F]{64}$/.test(t)) return navigate(`/tx/${t}`);
    if (/^0x[0-9a-fA-F]{40}$/.test(t)) return navigate(`/address/${t}`);
    if (/^[0-9]+$/.test(t)) return navigate(`/block/${t}`);
    // Fall through to the /search route which renders the resolver
    // output inline (with a "no match" hint when applicable).
    navigate(`/search?q=${encodeURIComponent(t)}`);
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Escape") {
      setQuery("");
    }
  }

  function onChange(e: ChangeEvent<HTMLInputElement>) {
    setQuery(e.target.value);
  }

  if (variant === "compact") {
    return (
      <form
        onSubmit={onSubmit}
        className="flex items-center gap-2"
        style={{ minWidth: 0 }}
      >
        <div
          className="flex items-center gap-2"
          style={{
            background: "var(--ts-bg-2)",
            border: "1px solid var(--ts-line-2)",
            borderRadius: 4,
            padding: "4px 8px",
            minWidth: 280,
          }}
        >
          <input
            value={query}
            onChange={onChange}
            onKeyDown={onKeyDown}
            placeholder={placeholder}
            autoFocus={autoFocus}
            className="mono"
            style={{
              background: "transparent",
              border: "none",
              outline: "none",
              color: "var(--ts-text)",
              fontSize: 11,
              flex: 1,
              minWidth: 0,
            }}
            spellCheck={false}
            autoComplete="off"
          />
          <kbd
            className="mono"
            style={{
              fontSize: 10,
              padding: "1px 5px",
              color: "var(--ts-text-3)",
              border: "1px solid var(--ts-line-2)",
              borderRadius: 3,
            }}
          >
            /
          </kbd>
        </div>
      </form>
    );
  }

  // wide variant
  return (
    <form
      onSubmit={onSubmit}
      className="flex flex-col gap-2"
      style={{ width: "100%" }}
    >
      <div
        className="flex items-center gap-2"
        style={{
          background: "var(--ts-bg-1)",
          border: "1px solid var(--ts-line-2)",
          borderRadius: 6,
          padding: "10px 14px",
        }}
      >
        <span
          aria-hidden
          className="mono"
          style={{ color: "var(--ts-text-4)", fontSize: 14 }}
        >
          ⌕
        </span>
        <input
          value={query}
          onChange={onChange}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          autoFocus={autoFocus}
          className="mono"
          style={{
            background: "transparent",
            border: "none",
            outline: "none",
            color: "var(--ts-text)",
            fontSize: 14,
            flex: 1,
            minWidth: 0,
          }}
          spellCheck={false}
          autoComplete="off"
        />
      </div>
      <div
        className="mono"
        style={{
          fontSize: 11,
          color: "var(--ts-text-3)",
          minHeight: 16,
        }}
      >
        {stage !== "idle" ? stageLabel(stage) : null}
      </div>
    </form>
  );
}
