// ConfirmationBadge renders the L2 block confirmation status using a
// consistent colour scheme across the explorer.

export type ConfirmationTier = "speculative" | "proven" | "finalized" | "frozen";

export default function ConfirmationBadge(props: { tier: ConfirmationTier }) {
  const label =
    props.tier === "speculative"
      ? "Speculative"
      : props.tier === "proven"
        ? "Proven"
        : props.tier === "frozen"
          ? "Frozen"
          : "Finalized";
  const cls =
    props.tier === "speculative"
      ? "badge-speculative"
      : props.tier === "proven"
        ? "badge-proven"
        : props.tier === "frozen"
          ? "badge-frozen"
          : "badge-finalized";
  return <span className={`badge ${cls}`}>{label}</span>;
}

// tierForBlock picks the right tier label given a block number and
// the set of confirmation tips from the shard. Kept out of the
// component so pages can reuse the classification logic.
export function tierForBlock(
  blockNumber: number,
  tips: { provenTip: number; finalizedTip: number }
): ConfirmationTier {
  if (blockNumber <= tips.finalizedTip && tips.finalizedTip > 0) {
    return "finalized";
  }
  if (blockNumber <= tips.provenTip && tips.provenTip > 0) {
    return "proven";
  }
  return "speculative";
}
