import { useQuery } from "@tanstack/react-query";

import { adminRPC } from "@/pages/admin/rpc";
import Panel from "@/components/Panel";

type AdminConfig = {
  chainId: number;
  minGasPriceWei: string;
  maxBatchSize: number;
  maxBatchFlushMs: number;
  maxSpeculativeDepth: number;
  proveMode: string;
  restartRequired: boolean;
};

export default function AdminConfig() {
  const config = useQuery({
    queryKey: ["admin_getConfig"],
    queryFn: () => adminRPC<AdminConfig>("admin_getConfig"),
  });

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Runtime configuration">
        {config.isLoading ? (
          <p className="text-muted">Loading…</p>
        ) : config.data ? (
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
            <Row label="Chain ID" value={String(config.data.chainId)} />
            <Row label="Prove mode" value={config.data.proveMode || "—"} />
            <Row
              label="Min gas price (wei)"
              value={config.data.minGasPriceWei}
            />
            <Row label="Max batch size" value={String(config.data.maxBatchSize)} />
            <Row
              label="Max batch flush (ms)"
              value={String(config.data.maxBatchFlushMs)}
            />
            <Row
              label="Max speculative depth"
              value={String(config.data.maxSpeculativeDepth)}
            />
          </dl>
        ) : (
          <p className="text-danger">{String(config.error)}</p>
        )}
        {config.data?.restartRequired ? (
          <p className="mt-3 text-xs text-warning">
            Changing any of these requires a node restart (live reload
            landing in a follow-up).
          </p>
        ) : null}
      </Panel>
    </div>
  );
}

function Row(props: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted">{props.label}</dt>
      <dd className="mt-1 font-mono">{props.value}</dd>
    </div>
  );
}
