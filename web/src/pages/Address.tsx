import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { eth, hexToNumber, formatWei } from "@/rpc/client";
import Copy from "@/components/Copy";
import Panel from "@/components/Panel";

export default function Address() {
  const { address } = useParams<{ address: string }>();

  const balance = useQuery({
    queryKey: ["eth_getBalance", address],
    queryFn: () => eth.getBalance(address!),
  });
  const nonce = useQuery({
    queryKey: ["eth_getTransactionCount", address],
    queryFn: () => eth.getTransactionCount(address!),
  });
  const code = useQuery({
    queryKey: ["eth_getCode", address],
    queryFn: () => eth.getCode(address!),
  });

  const isContract = !!code.data && code.data !== "0x";

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-4">
      <Panel
        title={isContract ? "Contract" : "Address"}
        subtitle={<Copy value={address ?? ""} label={address} />}
      >
        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted">Balance</dt>
            <dd className="mt-1 font-mono">
              {balance.data
                ? `${formatWei(balance.data)} wBSV`
                : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted">Nonce</dt>
            <dd className="mt-1 font-mono">
              {nonce.data !== undefined
                ? hexToNumber(nonce.data).toLocaleString()
                : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted">Contract</dt>
            <dd className="mt-1">{isContract ? "yes" : "no"}</dd>
          </div>
        </dl>
      </Panel>

      {isContract ? (
        <Panel title="Bytecode">
          <pre className="max-h-96 overflow-auto rounded-md bg-bg p-3 font-mono text-xs text-muted">
            {code.data}
          </pre>
        </Panel>
      ) : null}

      <Panel title="Transactions">
        <p className="text-sm text-muted">
          Per-address transaction history will land with the event indexer
          (spec 15 follow-up). In the meantime, navigate to a block to see
          all transactions.
        </p>
      </Panel>
    </div>
  );
}
