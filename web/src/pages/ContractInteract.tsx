import {
  ChangeEvent,
  DragEvent,
  ReactElement,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { eth } from "@/rpc/client";
import {
  AbiFragment,
  StoredAbi,
  clearAbi,
  loadAbi,
  parseAbiInput,
  saveAbi,
} from "@/contracts/abiStore";
import {
  callRead,
  classifyAbi,
  makeInterface,
  parseValueInput,
  sendWrite,
} from "@/contracts/methodCaller";
import { fetchAndDecode, DecodedLog } from "@/contracts/eventDecoder";
import {
  EvmWalletUnavailableError,
  hasEvmProvider,
  requestEvmAccounts,
} from "@/auth/wallet";
import Copy from "@/components/Copy";
import { Panel, KPI, Chip, Button, Segmented } from "@/components/ui";

// ContractInteract — per-address page that wraps eth_call (read
// methods), wallet-bridged eth_sendTransaction (write methods), and
// eth_getLogs decoding (event panel) behind a single tab UI.
//
// The page is reachable two ways:
//   1. As a sub-tab on the Address page (default Overview tab → Contract tab)
//   2. As a deep-linkable route at /address/:address/interact
//
// Either way, we render an ABI input strip at the top, then conditional
// method/event panels below once an ABI is present.

export default function ContractInteract(): ReactElement {
  const { address: rawAddress } = useParams<{ address: string }>();
  const address = rawAddress ?? "";

  const code = useQuery({
    queryKey: ["eth_getCode", address],
    queryFn: () => eth.getCode(address),
    enabled: !!address,
  });
  const isContract = !!code.data && code.data !== "0x";

  const [stored, setStored] = useState<StoredAbi | null>(() =>
    address ? loadAbi(address) : null,
  );
  // The ABI text area mirrors `stored.abi` but lets the user paste a
  // fresh ABI before committing it. Keeping it as a separate state
  // avoids re-parsing on every keystroke.
  const [abiText, setAbiText] = useState<string>("");
  const [abiError, setAbiError] = useState<string>("");

  useEffect(() => {
    setStored(address ? loadAbi(address) : null);
  }, [address]);

  function commitAbi(text: string, source?: string) {
    setAbiError("");
    try {
      const parsed = parseAbiInput(text);
      saveAbi(address, parsed, source);
      setStored({ abi: parsed, savedAt: Date.now(), source });
      setAbiText("");
    } catch (err) {
      setAbiError((err as Error).message);
    }
  }

  function clearStoredAbi() {
    clearAbi(address);
    setStored(null);
    setAbiText("");
    setAbiError("");
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
          Contract · interact
        </div>
        <h1
          className="mt-1 mono truncate"
          style={{ fontSize: 18, fontWeight: 500 }}
          title={address}
        >
          {address}
        </h1>
        <div className="mt-2 flex gap-3 items-center">
          <Copy value={address} label="copy address" />
          {isContract ? (
            <Chip tone="info" dot>contract</Chip>
          ) : code.isLoading ? (
            <Chip tone="neutral" dot>loading</Chip>
          ) : (
            <Chip tone="warn" dot>not a contract</Chip>
          )}
          <Link
            to={`/address/${address}`}
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-accent)" }}
          >
            ← back to overview
          </Link>
        </div>
      </div>

      {!isContract && !code.isLoading ? (
        <Panel title="No bytecode at this address" kicker="EOA">
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            This address has no deployed code. The contract interaction page
            only applies to contracts.
          </div>
        </Panel>
      ) : null}

      <AbiInputStrip
        stored={stored}
        abiText={abiText}
        abiError={abiError}
        onAbiTextChange={setAbiText}
        onCommit={commitAbi}
        onClear={clearStoredAbi}
      />

      {stored ? (
        <ContractPanels address={address} abi={stored.abi} />
      ) : null}
    </div>
  );
}

// AbiInputStrip — paste-or-drag-drop ABI capture. When an ABI is
// already saved, the strip collapses into a thin "ABI loaded — N
// fragments" badge with a clear button.
function AbiInputStrip(props: {
  stored: StoredAbi | null;
  abiText: string;
  abiError: string;
  onAbiTextChange: (v: string) => void;
  onCommit: (text: string, source?: string) => void;
  onClear: () => void;
}): ReactElement {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragHover, setDragHover] = useState(false);

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragHover(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    file.text().then((t) => props.onCommit(t, file.name));
  }

  function onFileSelect(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then((t) => props.onCommit(t, file.name));
    // Reset so re-selecting the same file fires onChange again.
    e.target.value = "";
  }

  if (props.stored) {
    return (
      <Panel title="ABI" kicker={props.stored.source ?? "manual paste"}>
        <div className="flex items-center gap-3 flex-wrap">
          <Chip tone="ok" dot>
            {props.stored.abi.length} fragments
          </Chip>
          <span
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)" }}
          >
            saved {new Date(props.stored.savedAt).toLocaleString()}
          </span>
          <div className="flex-1" />
          <Button onClick={props.onClear} variant="ghost" size="sm">
            replace ABI
          </Button>
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="ABI" kicker="paste JSON or drop a .json file">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragHover(true);
          }}
          onDragLeave={() => setDragHover(false)}
          onDrop={onDrop}
          style={{
            border: `1px dashed ${dragHover ? "var(--ts-accent)" : "var(--ts-line-2)"}`,
            background: dragHover ? "var(--ts-bg-2)" : "transparent",
            borderRadius: 6,
            padding: 14,
            textAlign: "center",
            color: "var(--ts-text-3)",
            fontSize: 11,
            transition: "background 120ms ease, border 120ms ease",
          }}
          className="mono"
        >
          drop a .json artifact here, or{" "}
          <button
            onClick={() => fileInputRef.current?.click()}
            className="mono"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--ts-accent)",
              cursor: "pointer",
              fontSize: 11,
              padding: 0,
            }}
          >
            choose a file
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            onChange={onFileSelect}
            style={{ display: "none" }}
          />
        </div>
        <textarea
          value={props.abiText}
          onChange={(e) => props.onAbiTextChange(e.target.value)}
          placeholder='[{"type":"function","name":"balanceOf","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"}]'
          spellCheck={false}
          className="mono"
          style={{
            background: "var(--ts-bg)",
            border: "1px solid var(--ts-line)",
            borderRadius: 4,
            color: "var(--ts-text-2)",
            fontSize: 11,
            padding: 10,
            minHeight: 120,
            resize: "vertical",
          }}
        />
        {props.abiError ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-bad)" }}
          >
            {props.abiError}
          </div>
        ) : null}
        <div className="flex items-center gap-2">
          <Button
            variant="primary"
            size="sm"
            onClick={() => props.onCommit(props.abiText, "manual paste")}
            disabled={!props.abiText.trim()}
          >
            load ABI
          </Button>
        </div>
      </div>
    </Panel>
  );
}

type Tab = "read" | "write" | "events";

function ContractPanels(props: {
  address: string;
  abi: AbiFragment[];
}): ReactElement {
  const classified = useMemo(() => classifyAbi(props.abi), [props.abi]);
  const iface = useMemo(() => makeInterface(props.abi), [props.abi]);
  const [tab, setTab] = useState<Tab>(
    classified.reads.length > 0
      ? "read"
      : classified.writes.length > 0
      ? "write"
      : "events",
  );

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        <KPI label="Read methods" value={classified.reads.length.toString()} />
        <KPI label="Write methods" value={classified.writes.length.toString()} />
        <KPI label="Events" value={classified.events.length.toString()} />
      </div>

      <Segmented<Tab>
        value={tab}
        onChange={setTab}
        options={[
          { value: "read", label: `Read (${classified.reads.length})` },
          { value: "write", label: `Write (${classified.writes.length})` },
          { value: "events", label: `Events (${classified.events.length})` },
        ]}
      />

      {tab === "read" ? (
        <ReadPanel address={props.address} reads={classified.reads} iface={iface} />
      ) : tab === "write" ? (
        <WritePanel address={props.address} writes={classified.writes} iface={iface} />
      ) : (
        <EventsPanel address={props.address} abi={props.abi} />
      )}
    </div>
  );
}

function ReadPanel(props: {
  address: string;
  reads: AbiFragment[];
  iface: ReturnType<typeof makeInterface>;
}): ReactElement {
  if (props.reads.length === 0) {
    return (
      <Panel title="Read methods" kicker="view / pure">
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
          No read-only functions in this ABI.
        </div>
      </Panel>
    );
  }
  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      {props.reads.map((f, i) => (
        <ReadMethod
          key={`${f.name}-${i}`}
          fragment={f}
          address={props.address}
          iface={props.iface}
        />
      ))}
    </div>
  );
}

function ReadMethod(props: {
  fragment: AbiFragment;
  address: string;
  iface: ReturnType<typeof makeInterface>;
}): ReactElement {
  const inputs = props.fragment.inputs ?? [];
  const [args, setArgs] = useState<string[]>(inputs.map(() => ""));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<{ raw: string; decoded: string } | null>(null);

  async function onCall() {
    setRunning(true);
    setError("");
    setResult(null);
    try {
      const r = await callRead(props.iface, props.fragment, props.address, args);
      setResult(r);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <Panel
      title={
        <span className="mono">
          {props.fragment.name}
          <span style={{ color: "var(--ts-text-4)" }}>
            ({inputs.map((i) => i.type).join(", ")})
          </span>
        </span>
      }
      kicker={props.fragment.stateMutability ?? "view"}
    >
      <div className="flex flex-col" style={{ gap: 8 }}>
        {inputs.length > 0 ? (
          <div className="grid" style={{ gridTemplateColumns: "1fr", gap: 6 }}>
            {inputs.map((input, i) => (
              <ArgInput
                key={i}
                label={input.name || `arg${i}`}
                type={input.type}
                value={args[i] ?? ""}
                onChange={(v) => {
                  const next = args.slice();
                  next[i] = v;
                  setArgs(next);
                }}
              />
            ))}
          </div>
        ) : null}
        <div className="flex items-center gap-2">
          <Button variant="primary" size="sm" onClick={onCall} disabled={running}>
            {running ? "calling..." : "call"}
          </Button>
        </div>
        {error ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)" }}>
            {error}
          </div>
        ) : null}
        {result ? (
          <div
            className="mono"
            style={{
              fontSize: 11,
              padding: 10,
              background: "var(--ts-bg)",
              border: "1px solid var(--ts-line)",
              borderRadius: 4,
              color: "var(--ts-text-2)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            <div style={{ color: "var(--ts-text-4)" }}>// decoded</div>
            <div>{result.decoded}</div>
            <div style={{ color: "var(--ts-text-4)", marginTop: 6 }}>// raw</div>
            <div style={{ color: "var(--ts-text-3)" }}>{result.raw}</div>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

function WritePanel(props: {
  address: string;
  writes: AbiFragment[];
  iface: ReturnType<typeof makeInterface>;
}): ReactElement {
  const evmAvailable = hasEvmProvider();
  const [from, setFrom] = useState<string | null>(null);
  const [connectError, setConnectError] = useState("");

  async function connect() {
    setConnectError("");
    try {
      const acc = await requestEvmAccounts();
      setFrom(acc);
    } catch (err) {
      setConnectError(
        err instanceof EvmWalletUnavailableError
          ? err.message
          : (err as Error).message,
      );
    }
  }

  if (props.writes.length === 0) {
    return (
      <Panel title="Write methods" kicker="state-changing">
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
          No state-changing functions in this ABI.
        </div>
      </Panel>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <Panel title="Wallet" kicker="EVM signer for writes">
        <div className="flex items-center gap-3 flex-wrap">
          {!evmAvailable ? (
            <>
              <Chip tone="bad" dot>no EVM wallet</Chip>
              <span
                className="mono"
                style={{ fontSize: 11, color: "var(--ts-text-3)" }}
              >
                Install MetaMask (or any EIP-1193 wallet) to send write
                transactions.
              </span>
            </>
          ) : from ? (
            <>
              <Chip tone="ok" dot>connected</Chip>
              <span className="mono" style={{ fontSize: 11, color: "var(--ts-text-2)" }}>
                {from}
              </span>
            </>
          ) : (
            <>
              <Chip tone="warn" dot>not connected</Chip>
              <Button variant="primary" size="sm" onClick={connect}>
                connect wallet
              </Button>
            </>
          )}
          {connectError ? (
            <span className="mono" style={{ fontSize: 11, color: "var(--ts-bad)" }}>
              {connectError}
            </span>
          ) : null}
        </div>
      </Panel>

      {props.writes.map((f, i) => (
        <WriteMethod
          key={`${f.name}-${i}`}
          fragment={f}
          address={props.address}
          iface={props.iface}
          from={from}
          enabled={evmAvailable && !!from}
        />
      ))}
    </div>
  );
}

function WriteMethod(props: {
  fragment: AbiFragment;
  address: string;
  iface: ReturnType<typeof makeInterface>;
  from: string | null;
  enabled: boolean;
}): ReactElement {
  const inputs = props.fragment.inputs ?? [];
  const payable = props.fragment.stateMutability === "payable";
  const [args, setArgs] = useState<string[]>(inputs.map(() => ""));
  const [valueRaw, setValueRaw] = useState("");
  const [gasRaw, setGasRaw] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [txHash, setTxHash] = useState<string | null>(null);

  async function onSend() {
    setRunning(true);
    setError("");
    setTxHash(null);
    try {
      if (!props.from) throw new Error("no connected EVM wallet");
      let valueWei: bigint | undefined;
      if (payable) {
        valueWei = parseValueInput(valueRaw);
      } else if (valueRaw.trim()) {
        throw new Error("value is only accepted for payable functions");
      }
      const gasLimit = gasRaw.trim() ? BigInt(gasRaw.trim()) : undefined;
      const hash = await sendWrite({
        iface: props.iface,
        fragment: props.fragment,
        to: props.address,
        rawArgs: args,
        from: props.from,
        valueWei,
        gasLimit,
      });
      setTxHash(hash);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <Panel
      title={
        <span className="mono">
          {props.fragment.name}
          <span style={{ color: "var(--ts-text-4)" }}>
            ({inputs.map((i) => i.type).join(", ")})
          </span>
        </span>
      }
      kicker={payable ? "payable" : "nonpayable"}
    >
      <div className="flex flex-col" style={{ gap: 8 }}>
        {inputs.length > 0 ? (
          <div className="grid" style={{ gridTemplateColumns: "1fr", gap: 6 }}>
            {inputs.map((input, i) => (
              <ArgInput
                key={i}
                label={input.name || `arg${i}`}
                type={input.type}
                value={args[i] ?? ""}
                onChange={(v) => {
                  const next = args.slice();
                  next[i] = v;
                  setArgs(next);
                }}
              />
            ))}
          </div>
        ) : null}
        {payable ? (
          <ArgInput
            label="value (wBSV)"
            type="decimal or wei"
            value={valueRaw}
            onChange={setValueRaw}
            placeholder='e.g. "1.5" (wBSV) or "1500000000000000000" (wei)'
          />
        ) : null}
        <ArgInput
          label="gas limit (optional)"
          type="uint256"
          value={gasRaw}
          onChange={setGasRaw}
          placeholder="leave blank for wallet auto-estimate"
        />
        <div className="flex items-center gap-2">
          <Button
            variant="primary"
            size="sm"
            onClick={onSend}
            disabled={running || !props.enabled}
          >
            {running ? "sending..." : "send"}
          </Button>
          {!props.enabled ? (
            <span className="mono" style={{ fontSize: 11, color: "var(--ts-text-4)" }}>
              connect an EVM wallet first
            </span>
          ) : null}
        </div>
        {error ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)" }}>
            {error}
          </div>
        ) : null}
        {txHash ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-ok)" }}>
            broadcast — tx{" "}
            <Link to={`/tx/${txHash}`} style={{ color: "var(--ts-accent)" }}>
              {txHash}
            </Link>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

function ArgInput(props: {
  label: string;
  type: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}): ReactElement {
  return (
    <label className="flex flex-col" style={{ gap: 3 }}>
      <span
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--ts-text-3)",
        }}
      >
        {props.label} <span style={{ color: "var(--ts-text-4)" }}>· {props.type}</span>
      </span>
      <input
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        placeholder={props.placeholder ?? `${props.type}`}
        className="mono"
        spellCheck={false}
        style={{
          background: "var(--ts-bg)",
          border: "1px solid var(--ts-line)",
          borderRadius: 4,
          color: "var(--ts-text-2)",
          fontSize: 11,
          padding: "6px 8px",
          outline: "none",
        }}
      />
    </label>
  );
}

function EventsPanel(props: {
  address: string;
  abi: AbiFragment[];
}): ReactElement {
  const [windowSize, setWindowSize] = useState<"100" | "1000" | "10000">("1000");
  const logs = useQuery({
    queryKey: ["contractLogs", props.address, windowSize],
    queryFn: () =>
      fetchAndDecode({
        address: props.address,
        abi: props.abi,
        window: Number.parseInt(windowSize, 10),
      }),
    refetchInterval: 10_000,
  });

  return (
    <Panel
      title="Recent events"
      kicker="decoded against ABI"
      meta={
        <Segmented<"100" | "1000" | "10000">
          size="sm"
          value={windowSize}
          onChange={setWindowSize}
          options={[
            { value: "100", label: "100" },
            { value: "1000", label: "1K" },
            { value: "10000", label: "10K" },
          ]}
        />
      }
      padded={false}
    >
      {logs.isLoading ? (
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}>
          loading logs...
        </div>
      ) : logs.error ? (
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-bad)", padding: 14 }}>
          failed: {(logs.error as Error).message}
        </div>
      ) : !logs.data || logs.data.length === 0 ? (
        <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}>
          No events in the last {windowSize} blocks.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="w-full text-left" style={{ borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["block", "tx", "event", "args"].map((h, i) => (
                  <th
                    key={i}
                    className="mono"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      color: "var(--ts-text-3)",
                      fontWeight: 500,
                      padding: "8px 14px",
                      borderBottom: "1px solid var(--ts-line)",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.data.map((log) => (
                <EventRow key={`${log.txHash}-${log.logIndex}`} log={log} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function EventRow({ log }: { log: DecodedLog }): ReactElement {
  return (
    <tr style={{ borderTop: "1px solid var(--ts-line)" }}>
      <td style={{ padding: "6px 14px" }}>
        <Link
          to={`/block/${log.blockNumber}`}
          className="mono"
          style={{ fontSize: 11, color: "var(--ts-accent)" }}
        >
          #{log.blockNumber.toLocaleString()}
        </Link>
      </td>
      <td style={{ padding: "6px 14px" }}>
        <Link
          to={`/tx/${log.txHash}`}
          className="mono"
          style={{ fontSize: 11, color: "var(--ts-accent)" }}
        >
          {log.txHash.slice(0, 10)}…{log.txHash.slice(-6)}
        </Link>
      </td>
      <td style={{ padding: "6px 14px" }}>
        {log.name ? (
          <span className="mono" style={{ fontSize: 11, color: "var(--ts-text)" }}>
            {log.name}
          </span>
        ) : (
          <Chip tone="warn">unknown</Chip>
        )}
      </td>
      <td style={{ padding: "6px 14px", maxWidth: 600 }}>
        {log.args ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {log.args.map((a, i) => (
              <div key={i}>
                <span style={{ color: "var(--ts-text-4)" }}>{a.name}</span>
                <span style={{ color: "var(--ts-text-4)" }}>: </span>
                <span style={{ color: "var(--ts-text-2)" }}>{a.value}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="mono truncate" style={{ fontSize: 11, color: "var(--ts-text-4)", maxWidth: 600 }}>
            topics: {log.raw.topics.join(",")}
          </div>
        )}
      </td>
    </tr>
  );
}
