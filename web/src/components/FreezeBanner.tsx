import { ReactElement } from "react";
import { useQuery } from "@tanstack/react-query";

import { bsv } from "@/rpc/client";
import StatusDot from "@/components/ui/StatusDot";

// FreezeBanner renders the full-width red alert strip above the
// chrome when governance has frozen the shard. Shown whenever
// bsv_shardInfo reports frozen=true; hidden otherwise.
export default function FreezeBanner(): ReactElement | null {
  const { data } = useQuery({
    queryKey: ["bsv_shardInfo"],
    queryFn: bsv.shardInfo,
    refetchInterval: 3_000,
  });

  if (!data?.governance.frozen) return null;

  return (
    <div
      role="alert"
      className="w-full"
      style={{
        background:
          "linear-gradient(90deg, color-mix(in srgb, var(--ts-bad) 40%, transparent) 0%, transparent 100%)",
        borderBottom:
          "1px solid color-mix(in srgb, var(--ts-bad) 60%, transparent)",
        padding: "6px 20px",
      }}
    >
      <div className="flex items-center gap-3">
        <StatusDot tone="bad" pulse="urgent" size={9} />
        <span
          className="mono"
          style={{
            fontSize: 11,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--ts-bad)",
            fontWeight: 600,
          }}
        >
          Shard frozen · governance halt · no advances accepted
        </span>
      </div>
    </div>
  );
}
