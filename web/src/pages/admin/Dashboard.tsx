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

type BridgeHealth = {
  mismatch: boolean;
  totalLocked: string;
  totalSupply: string;
  lastScanned: number;
  note?: string;
};

export default function AdminDashboard() {
  const config = useQuery({
    queryKey: ["admin_getConfig"],
    queryFn: () => adminRPC<AdminConfig>("admin_getConfig"),
  });
  const bridge = useQuery({
    queryKey: ["admin_bridgeHealth"],
    queryFn: () => adminRPC<BridgeHealth>("admin_bridgeHealth"),
  });

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Runtime config" subtitle="admin_getConfig">
        {config.data ? (
          <pre className="max-h-64 overflow-auto rounded-md bg-bg p-3 font-mono text-xs">
            {JSON.stringify(config.data, null, 2)}
          </pre>
        ) : config.error ? (
          <p className="text-sm text-danger">{String(config.error)}</p>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>

      <Panel title="Bridge health" subtitle="admin_bridgeHealth">
        {bridge.data ? (
          <pre className="max-h-64 overflow-auto rounded-md bg-bg p-3 font-mono text-xs">
            {JSON.stringify(bridge.data, null, 2)}
          </pre>
        ) : bridge.error ? (
          <p className="text-sm text-danger">{String(bridge.error)}</p>
        ) : (
          <p className="text-muted">Loading…</p>
        )}
      </Panel>
    </div>
  );
}
