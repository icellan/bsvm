import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { adminRPC } from "@/pages/admin/rpc";
import { Panel, Button } from "@/components/ui";
import ProposalCard, { SigChip } from "@/components/admin/ProposalCard";
import { signMessage, sha256 } from "@/auth/wallet";

type Proposal = {
  id: string;
  action: string;
  required: number;
  signatureCount: number;
  signatures: { pubKey: string; signature: string }[];
  pending?: string[];
  createdAt: string;
  expiresAt: string;
  ready: boolean;
  broadcastTxid?: string;
};

// Admin Governance — "new proposal" action bar + stack of proposal
// cards. Signing calls the BRC-100 wallet; broadcast enables when
// signatures >= threshold.
export default function AdminGovernance() {
  const qc = useQueryClient();
  const [err, setErr] = useState("");
  const [signingId, setSigningId] = useState<string>("");

  const list = useQuery({
    queryKey: ["admin_listGovernanceProposals"],
    queryFn: () => adminRPC<Proposal[]>("admin_listGovernanceProposals"),
    refetchInterval: 8_000,
  });

  const create = useMutation({
    mutationFn: (action: "freeze" | "unfreeze") =>
      adminRPC<Proposal>("admin_createGovernanceProposal", [action]),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["admin_listGovernanceProposals"] }),
    onError: (e) => setErr(String(e)),
  });

  async function sign(p: Proposal) {
    setErr("");
    setSigningId(p.id);
    try {
      const digest = await sha256(new TextEncoder().encode(p.id));
      const sigHex = await signMessage(digest);
      await adminRPC<Proposal>("admin_signGovernanceProposal", [p.id, sigHex]);
      qc.invalidateQueries({ queryKey: ["admin_listGovernanceProposals"] });
    } catch (e) {
      setErr(String(e));
    } finally {
      setSigningId("");
    }
  }

  const proposals = list.data ?? [];

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
          Admin · governance
        </div>
        <h1
          className="mt-1"
          style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}
        >
          Proposals
        </h1>
      </div>

      <Panel title="New proposal" kicker="Governance actions">
        <div className="flex gap-2 flex-wrap">
          <Button variant="danger" onClick={() => create.mutate("freeze")}>
            Freeze shard
          </Button>
          <Button variant="accent-ghost" onClick={() => create.mutate("unfreeze")}>
            Unfreeze shard
          </Button>
          <Button disabled>Rotate key</Button>
          <Button disabled>Update config</Button>
        </div>
        {err ? (
          <div
            className="mono mt-3"
            style={{ fontSize: 11, color: "var(--ts-bad)" }}
          >
            {err}
          </div>
        ) : null}
      </Panel>

      {list.isLoading ? (
        <Panel title="Pending" padded={false}>
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--ts-text-3)", padding: 14 }}
          >
            Loading…
          </div>
        </Panel>
      ) : proposals.length === 0 ? (
        <Panel title="Pending" kicker="0 active">
          <div className="mono" style={{ fontSize: 11, color: "var(--ts-text-3)" }}>
            No pending proposals.
          </div>
        </Panel>
      ) : (
        <div className="flex flex-col" style={{ gap: 10 }}>
          {proposals.map((p) => {
            const signers: SigChip[] = [
              ...p.signatures.map((s) => ({ pk: s.pubKey, signed: true })),
              ...(p.pending ?? []).map((pk) => ({ pk, signed: false })),
            ];
            return (
              <ProposalCard
                key={p.id}
                id={p.id}
                action={p.action}
                required={p.required}
                sigs={p.signatureCount}
                signers={signers}
                created={p.createdAt}
                expires={p.expiresAt}
                ready={p.ready}
                signPending={signingId === p.id}
                onSign={() => sign(p)}
                onBroadcast={p.ready ? () => {} : undefined}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
