import { ReactElement } from "react";
import Chip from "./Chip";
import type { Tone } from "./StatusDot";

export type TierKind = "speculative" | "proven" | "finalized" | "frozen";

const TIER_TONE: Record<TierKind, Tone> = {
  speculative: "neutral",
  proven: "info",
  finalized: "ok",
  frozen: "bad",
};

const TIER_LABEL: Record<TierKind, string> = {
  speculative: "speculative",
  proven: "proven",
  finalized: "finalized",
  frozen: "frozen",
};

// Tier is a dedicated chip for block / tx confirmation state.
// Frozen animates via ts-pulse-fast to flag freeze events.
export default function Tier({ tier }: { tier: TierKind }): ReactElement {
  return (
    <Chip
      tone={TIER_TONE[tier]}
      dot
      className={tier === "frozen" ? "ts-pulse-fast" : ""}
    >
      {TIER_LABEL[tier]}
    </Chip>
  );
}

// tierFor derives the confirmation tier for a block from current shard
// tips. Frozen globally overrides per-block tiers.
export function tierFor(
  blockNumber: number,
  tips: { proven: number; finalized: number; frozen?: boolean }
): TierKind {
  if (tips.frozen) return "frozen";
  if (blockNumber <= tips.finalized) return "finalized";
  if (blockNumber <= tips.proven) return "proven";
  return "speculative";
}
