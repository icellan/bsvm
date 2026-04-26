//! Forced-Inclusion Inbox Drain Verification (W4-3, spec 10/11/12)
//!
//! The inbox is an append-only hash chain maintained by the on-chain inbox
//! covenant (`pkg/covenant/contracts/inbox.runar.go`). Anyone can submit an
//! EVM transaction to BSV by spending the current inbox UTXO with a `submit`
//! call; the script extends the chain:
//!
//! ```text
//! genesis_root  = hash256(zeros(32))                       // = 0x9f64a747e1b97f...
//! root_{n+1}    = hash256(root_n || hash256(tx_n_RLP))
//! ```
//!
//! `inboxRootBefore` (public-values offset 176) is the chain root the prover
//! observed on BSV at batch-build time. `inboxRootAfter` (offset 208) is the
//! chain root after this batch drained the leading `drained` transactions
//! from the queue. The state covenant reads these two values out of the
//! STARK proof and enforces forced-inclusion (spec 10):
//!
//!   - `before == after`  →  no drain this batch (counter +1)
//!   - `before != after`  →  drain happened (counter reset to 0)
//!   - if counter would reach 10 with no drain  →  REJECT
//!
//! The guest's job is to make those two roots untrustworthy-host-proof:
//!
//!   1. The host hands us the **full ordered list** of transactions that
//!      were in the inbox at batch-build time and a `drained` count of how
//!      many leading entries this batch is consuming.
//!   2. We recompute the chain root from the full list and assert it equals
//!      `inbox_root_before` (this proves the host disclosed the true queue
//!      contents — censorship by withholding a tx is detectable here).
//!   3. We split the list at `drained`, apply the leading slice as part of
//!      the EVM batch, and recompute the chain root from the trailing
//!      remainder. That root is `inbox_root_after`.
//!
//! Cost is dominated by SHA-256, which SP1 accelerates via a precompile, so
//! the verification is essentially free even with hundreds of queued txs.
//!
//! Compatible with the Go-side encoding in `pkg/overlay/inbox_monitor.go`
//! (`hash256(prev || hash256(tx_rlp))`) and `pkg/covenant/inbox_state.go`
//! (`EmptyInboxState() = hash256(zeros(32))`).

use sha2::{Digest, Sha256};

/// Compute hash256 (double-SHA256) — BSV's `OP_HASH256`.
fn hash256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Empty-queue chain root. Matches `EmptyInboxState()` /
/// `NewInboxMonitor()` on the Go side: `hash256(zeros(32))`.
pub fn empty_inbox_root() -> [u8; 32] {
    hash256(&[0u8; 32])
}

/// Extend a hash chain by one leaf: `new_root = hash256(prev_root || hash256(tx_rlp))`.
///
/// Must stay byte-identical to:
///   - `pkg/overlay/inbox_monitor.go::AddInboxTransaction`
///   - `pkg/covenant/contracts/inbox.runar.go::Submit`
fn extend_chain(prev_root: [u8; 32], tx_rlp: &[u8]) -> [u8; 32] {
    let leaf = hash256(tx_rlp);
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&prev_root);
    buf[32..64].copy_from_slice(&leaf);
    hash256(&buf)
}

/// Compute the chain root for an arbitrary ordered slice of inbox tx RLPs,
/// starting from the empty-queue genesis root.
pub fn chain_root(txs: &[Vec<u8>]) -> [u8; 32] {
    let mut root = empty_inbox_root();
    for tx in txs {
        root = extend_chain(root, tx);
    }
    root
}

/// Errors surfaced by [`verify_and_split`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxError {
    /// The host's `drained` count is larger than the queue it provided.
    DrainCountExceedsQueue,
    /// The recomputed chain root does not match the claimed `inbox_root_before`.
    /// This indicates the host omitted, reordered, or fabricated inbox txs.
    BeforeRootMismatch,
    /// Forced-inclusion was triggered (`must_drain_all`) but the host left
    /// transactions in the queue, violating spec 10's escape-hatch rule.
    PartialDrainWhileForced,
}

/// Drain plan returned by [`verify_and_split`].
///
/// `drained`/`remainder` are exposed for callers that want to consume the
/// raw-RLP slice directly (e.g. for receipt logs); the production main
/// loop currently routes pre-decoded `EvmTransaction` values from the
/// `BatchInput::inbox_queue` field instead and only consumes
/// [`DrainPlan::root_after`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct DrainPlan<'a> {
    /// The leading slice of inbox txs this batch consumes — these are the
    /// raw RLP bytes the EVM must execute (the caller is responsible for
    /// decoding and routing them through revm at the head of the batch).
    pub drained: &'a [Vec<u8>],
    /// The trailing slice that remains queued for a future batch.
    pub remainder: &'a [Vec<u8>],
    /// The chain root after this batch's drain — `hash256(zero32)` if the
    /// remainder is empty (i.e. queue fully drained), else the chain root
    /// rebuilt from `remainder`.
    pub root_after: [u8; 32],
}

/// Verify the host's inbox witness and split the queue into drained vs. carry-forward.
///
/// `queue`            — the full ordered list of currently-queued inbox txs
///                      (raw EVM RLP bytes, exactly as submitted on-chain).
/// `claimed_before`   — the `inbox_root_before` value the host wants to commit.
/// `drain_count`      — how many leading entries this batch consumes.
/// `must_drain_all`   — set by the host when forced-inclusion (spec 10's
///                      `advancesSinceInbox >= 10`) is in play; if true the
///                      remainder MUST be empty or we abort the batch.
///
/// Returns the [`DrainPlan`] on success. The caller MUST then apply
/// `drained` to revm and use `root_after` as the public-values commit.
pub fn verify_and_split<'q>(
    queue: &'q [Vec<u8>],
    claimed_before: &[u8; 32],
    drain_count: usize,
    must_drain_all: bool,
) -> Result<DrainPlan<'q>, InboxError> {
    if drain_count > queue.len() {
        return Err(InboxError::DrainCountExceedsQueue);
    }

    // (1) Recompute the chain root over the FULL queue and compare against
    // the claimed `inbox_root_before`. This is the censorship-resistance
    // gate: if a malicious host hides a queued tx by omitting it from
    // `queue`, the recomputed root won't match what the on-chain inbox
    // covenant would have produced.
    let recomputed_before = chain_root(queue);
    if recomputed_before != *claimed_before {
        return Err(InboxError::BeforeRootMismatch);
    }

    let (drained, remainder) = queue.split_at(drain_count);

    if must_drain_all && !remainder.is_empty() {
        return Err(InboxError::PartialDrainWhileForced);
    }

    let root_after = if remainder.is_empty() {
        // Queue fully drained → reset to the genesis empty-chain marker.
        // Matches `pkg/covenant/inbox_state.go::EmptyInboxState`.
        empty_inbox_root()
    } else {
        chain_root(remainder)
    };

    Ok(DrainPlan {
        drained,
        remainder,
        root_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn empty_queue_root_matches_go_genesis() {
        // Equivalent to Go: hash256([]byte{0,...,0}) — the genesis empty
        // chain marker used by InboxMonitor / EmptyInboxState.
        let root = empty_inbox_root();
        let expected = hash256(&[0u8; 32]);
        assert_eq!(root, expected);
    }

    #[test]
    fn chain_root_is_deterministic() {
        let txs = vec![tx(1, 8), tx(2, 16), tx(3, 32)];
        assert_eq!(chain_root(&txs), chain_root(&txs));
    }

    #[test]
    fn chain_root_order_sensitive() {
        let a = vec![tx(1, 8), tx(2, 8)];
        let b = vec![tx(2, 8), tx(1, 8)];
        assert_ne!(chain_root(&a), chain_root(&b));
    }

    #[test]
    fn full_drain_yields_empty_marker() {
        let txs = vec![tx(7, 4), tx(8, 4), tx(9, 4)];
        let before = chain_root(&txs);
        let plan = verify_and_split(&txs, &before, 3, true).expect("verify_and_split");
        assert_eq!(plan.drained.len(), 3);
        assert!(plan.remainder.is_empty());
        assert_eq!(plan.root_after, empty_inbox_root());
    }

    #[test]
    fn partial_drain_carries_remainder() {
        let txs = vec![tx(1, 4), tx(2, 4), tx(3, 4), tx(4, 4)];
        let before = chain_root(&txs);
        let plan = verify_and_split(&txs, &before, 2, false).expect("verify_and_split");
        assert_eq!(plan.drained.len(), 2);
        assert_eq!(plan.remainder.len(), 2);
        assert_eq!(plan.root_after, chain_root(&txs[2..]));
        // The carry-forward root must NOT equal the empty-chain marker (the
        // covenant uses before == after as the no-drain signal).
        assert_ne!(plan.root_after, empty_inbox_root());
    }

    #[test]
    fn no_drain_keeps_root_unchanged() {
        let txs = vec![tx(1, 4), tx(2, 4)];
        let before = chain_root(&txs);
        let plan = verify_and_split(&txs, &before, 0, false).expect("verify_and_split");
        assert!(plan.drained.is_empty());
        assert_eq!(plan.root_after, before);
    }

    #[test]
    fn empty_queue_no_drain_is_ok() {
        let txs: Vec<Vec<u8>> = Vec::new();
        let before = empty_inbox_root();
        let plan = verify_and_split(&txs, &before, 0, false).expect("verify_and_split");
        assert!(plan.drained.is_empty());
        assert!(plan.remainder.is_empty());
        assert_eq!(plan.root_after, empty_inbox_root());
    }

    #[test]
    fn lying_host_is_caught() {
        // Host claims a different `before` root than the queue actually hashes to.
        let txs = vec![tx(1, 4)];
        let bogus = [0xAAu8; 32];
        let err = verify_and_split(&txs, &bogus, 1, false).unwrap_err();
        assert_eq!(err, InboxError::BeforeRootMismatch);
    }

    #[test]
    fn drain_count_overflow_is_caught() {
        let txs = vec![tx(1, 4), tx(2, 4)];
        let before = chain_root(&txs);
        let err = verify_and_split(&txs, &before, 3, false).unwrap_err();
        assert_eq!(err, InboxError::DrainCountExceedsQueue);
    }

    #[test]
    fn forced_inclusion_demands_full_drain() {
        let txs = vec![tx(1, 4), tx(2, 4), tx(3, 4)];
        let before = chain_root(&txs);
        // Only drain 2 of 3 while the covenant demands a full drain.
        let err = verify_and_split(&txs, &before, 2, true).unwrap_err();
        assert_eq!(err, InboxError::PartialDrainWhileForced);
    }

    #[test]
    fn extend_chain_matches_manual() {
        // Sanity: chain_root([t1, t2]) == hash256(hash256(genesis||hash256(t1))||hash256(t2))
        let t1 = tx(1, 5);
        let t2 = tx(2, 5);
        let manual = {
            let r0 = empty_inbox_root();
            let r1 = {
                let h1 = hash256(&t1);
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&r0);
                buf[32..].copy_from_slice(&h1);
                hash256(&buf)
            };
            let h2 = hash256(&t2);
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&r1);
            buf[32..].copy_from_slice(&h2);
            hash256(&buf)
        };
        assert_eq!(chain_root(&[t1, t2]), manual);
    }
}
