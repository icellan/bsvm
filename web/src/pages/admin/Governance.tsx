import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { adminRPC } from "@/pages/admin/rpc";
import Panel from "@/components/Panel";
import { signMessage, sha256 } from "@/auth/wallet";
import { shorten } from "@/components/Copy";

type Proposal = {
  id: string;
  action: string;
  required: number;
  signatureCount: number;
  signatures: { pubKey: string; signature: string }[];
  createdAt: string;
  expiresAt: string;
  ready: boolean;
  broadcastTxid?: string;
};

export default function AdminGovernance() {
  const qc = useQueryClient();
  const [error, setError] = useState("");

  const list = useQuery({
    queryKey: ["admin_listGovernanceProposals"],
    queryFn: () => adminRPC<Proposal[]>("admin_listGovernanceProposals"),
  });

  const createMutation = useMutation({
    mutationFn: (action: "freeze" | "unfreeze") =>
      adminRPC<Proposal>("admin_createGovernanceProposal", [action]),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin_listGovernanceProposals"] }),
    onError: (err) => setError(String(err)),
  });

  async function sign(p: Proposal) {
    setError("");
    try {
      // Server derives the signing digest as sha256(proposalID).
      const digest = await sha256(new TextEncoder().encode(p.id));
      const sigHex = await signMessage(digest);
      await adminRPC<Proposal>("admin_signGovernanceProposal", [p.id, sigHex]);
      qc.invalidateQueries({ queryKey: ["admin_listGovernanceProposals"] });
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel title="New proposal">
        <div className="flex gap-2">
          <ActionButton
            label="Freeze shard"
            danger
            onClick={() => createMutation.mutate("freeze")}
          />
          <ActionButton
            label="Unfreeze shard"
            onClick={() => createMutation.mutate("unfreeze")}
          />
        </div>
        {error ? <p className="mt-2 text-xs text-danger">{error}</p> : null}
      </Panel>

      <Panel title={`Pending proposals (${list.data?.length ?? 0})`}>
        {list.isLoading ? (
          <p className="text-muted">Loading…</p>
        ) : !list.data || list.data.length === 0 ? (
          <p className="text-sm text-muted">No proposals.</p>
        ) : (
          <ul className="divide-y divide-border/50 text-sm">
            {list.data.map((p) => (
              <li key={p.id} className="py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div>
                    <span className="font-mono text-fg">{shorten(p.id)}</span>{" "}
                    <span className="text-muted">· {p.action}</span>
                  </div>
                  <span className="text-xs text-muted">
                    {p.signatureCount}/{p.required} signatures ·{" "}
                    {p.ready ? (
                      <span className="text-success">ready</span>
                    ) : (
                      "awaiting"
                    )}
                  </span>
                </div>
                <div className="mt-1 text-xs text-muted">
                  created {p.createdAt} · expires {p.expiresAt}
                </div>
                <div className="mt-2 flex gap-2">
                  <ActionButton label="Sign" onClick={() => sign(p)} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function ActionButton(props: {
  label: string;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={props.onClick}
      className={`rounded-md border px-3 py-1.5 text-xs font-semibold ${
        props.danger
          ? "border-danger/60 bg-danger/10 text-danger hover:bg-danger/20"
          : "border-accent/60 bg-accent/10 text-accent hover:bg-accent/20"
      }`}
    >
      {props.label}
    </button>
  );
}
