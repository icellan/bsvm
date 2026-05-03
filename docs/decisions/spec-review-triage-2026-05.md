# Spec-Review Triage 2026-05

**Reviewer report received**: 5 claims against the BSVM tree at HEAD on
worktree branch `worktree-agent-a80fcf8984bafb133`. This document
verifies each claim line-by-line against the cited code and the spec
set, assigns scope + mainnet blast radius, and recommends a path
forward. No code is changed in this pass.

This is an audit-only document. Each claim was verified by reading
both the cited file/line and the relevant spec passage (cited
explicitly so the next implementer does not have to re-derive).

---

## Claim 1: Real prover / devnet prove-mode is not fully wired (specs 12 / 16)

**Source (reviewer's wording)**: "config only exposes `mode` + `workers`;
spec wants real SP1 prover backend config, ELF paths,
mock/execute/prove distinction." Cited lines: `cmd/bsvm/config.go:199`,
`cmd/bsvm/config.go:627`, `cmd/bsvm/main.go:197`,
`cmd/bsvm/deploy_shard.go:347`, `cmd/bsvm/bsv_wiring.go:347`.

**Verification**:

- `cmd/bsvm/config.go:199-203` defines `ProverSection` as exactly two
  TOML fields: `mode` (string) and `workers` (int). No fields for ELF
  path, host-bridge binary path, prover-network URL, timeout, ProofMode,
  or SP1ProofMode.
- `cmd/bsvm/config.go:627-640` (`ToProverConfig`) only sets `pc.Mode`
  from the TOML knob and otherwise returns `prover.DefaultConfig()`.
  `Workers` is not even propagated. `HostBridgeBinary`,
  `GuestELFPath`, `NetworkURL`, `ProofMode`, `SP1ProofMode`, and
  `Timeout` (other than the 10-minute default) are unreachable from
  the operator's config file.
- `pkg/prover/config.go:50-78` (the destination type) defines all of
  the fields the spec requires (`HostBridgeBinary`, `GuestELFPath`,
  `NetworkURL`, `ProofMode`, `Timeout`, `SP1ProofMode`). The struct
  is fine; the wiring is not.
- `cmd/bsvm/main.go:197` lives inside `cmdInit` and handles the
  `--prove-mode execute` branch by setting verification defaults
  (`verification = "fri"`, `governanceMode = "single_key"`,
  `chainID = 31337`). It does NOT touch any prover backend config.
- `cmd/bsvm/deploy_shard.go:347` (`resolveVerificationMode`) maps
  `--prove-mode` to a covenant verification mode but explicitly
  errors out for `--prove-mode prove` (`prove-mode=prove (Groth16-WA)
  not yet wired in deploy-shard`).
- `cmd/bsvm/bsv_wiring.go:347` (`selectRollupSourceInputs`) emits an
  explicit "groth16-wa broadcast requires a real SP1 prover to
  regenerate proofs per batch" error.
- `cmd/bsvm/env.go:138-152` parses `BSVM_PROVE_MODE` but only routes
  it to `cmdInit`'s flag defaults — runtime proving config is never
  populated from it.
- Spec 16 §"Proving Modes" (lines 24-95) defines three named modes
  (`mock` / `execute` / `prove`) and is explicit that `execute` runs
  the SP1 guest in execute mode (no STARK) and `prove` generates a
  real STARK. Spec 12 §"SP1ProverConfig" (lines 612-618 and
  1779-1788) lists the canonical config fields:
  `GuestELFPath`, `ProverBinary`, `ProverNetworkURL`,
  `Timeout`, `Workers`, plus optional `GPUCount`,
  `ProverPoolURL`, `ProverNetworkFallback`.
- Verdict: **confirmed-gap (partially-confirmed on the deploy-shard
  bullet)**. The `ProverSection` is genuinely under-specified and
  `ToProverConfig` is genuinely a stub. The `deploy_shard.go:347` and
  `bsv_wiring.go:347` citations are not "wiring is missing" but
  rather "wiring is intentionally guarded behind an error string" —
  the reviewer is right that the path isn't reachable, but the code
  is at least loud about it.

**Scope**: M (≤1w). Adding TOML fields + plumbing them through
`ToProverConfig` is straightforward (≤1d). Wiring a real Rust
host-bridge subprocess + ELF load + `execute`-mode runtime selection
spans several files (host.go already supports `proveLocal` /
`proveNetwork` / `proveMock` at lines 199-203, but `execute` is not a
distinct mode — it would be a `proveLocal` invocation with a
`--mode execute` arg to the host bridge that does not exist yet).

**Mainnet blast radius**: **medium**. Devnet operators today silently
fall back to mock proving even when their TOML asks for `local`. On
mainnet this would mean a node believes it is producing real STARKs
but is producing mock proofs that the covenant FRI verifier would
reject — the BSV broadcast would fail and the operator would notice
quickly, but the operator-visible failure mode is "your batch never
landed" rather than "your config is wrong". A startup-time
validation that refuses `Mode=ProverLocal` without
`HostBridgeBinary` + `GuestELFPath` set would catch this loudly.

**Recommended path**:
- [x] **DONE** (2026-05-03): TOML key list agreed and shipped on
      `ProverSection` in `cmd/bsvm/config.go`:
      - `[prover].host_bridge_binary` (string, required when mode=local)
      - `[prover].guest_elf_path` (string, required when mode=local)
      - `[prover].network_url` (string, optional when mode=network —
        empty defers to the SP1 SDK default endpoint)
      - `[prover].timeout` (duration string; empty inherits the prover
        package's 10-minute default)
      - `[prover].sp1_proof_mode` (string: "compressed" / "core" /
        "groth16" / "execute")
      - `[prover].proof_mode` (string: "fri" / "groth16" / "groth16-wa";
        legacy "groth16-generic" / "groth16-witness" aliases accepted)
      - `[prover].workers` — wired via OverlayConfig.ProverWorkers
        (see WW-prover-mode-wiring-workers below)
      Each new field is round-tripped to `prover.Config` by
      `ToProverConfig` and exercised by
      `TestNodeConfig_ToProverConfig_Plumbing` /
      `TestNodeConfig_ToProverConfig_DefaultsPreserved` in
      `cmd/bsvm/config_test.go`. The example TOML
      (`cmd/bsvm/bsvm.example.toml`) documents every knob inline.
- [x] **DONE** (2026-05-03): Startup-time validation lives in
      `ProverSection.Validate()` and is invoked from `LoadNodeConfig`.
      It rejects:
      - unknown mode strings (typos like "lcoal" no longer fall
        through silently to mock),
      - `mode = "local"` without `host_bridge_binary` /
        `guest_elf_path` set, or with paths that don't exist on disk,
      - `mode = "network"` with a malformed `network_url`,
      - `mode = "mock"` combined with a Groth16 `proof_mode` (mock
        proofs cannot satisfy a Groth16 on-chain verifier — this is
        the contradiction guard the "mainnet blast radius" note
        called out),
      - unparseable `timeout` strings,
      - unrecognised `proof_mode` / `sp1_proof_mode` values.
      Coverage is in `TestProverSection_Validate` (17 sub-tests) plus
      `TestLoadNodeConfig_RejectsBadProverSection`.
- [x] Push back partially: the spec defines the *shape* of
      `SP1ProverConfig` but does not pin which TOML keys must exist.
      Before implementation, agree on:
      - `[prover].host_bridge_binary` (string, required when mode!=mock)
      - `[prover].guest_elf_path` (string, required when mode!=mock)
      - `[prover].network_url` (string, required when mode==network)
      - `[prover].timeout` (duration string)
      - `[prover].sp1_proof_mode` (string: "compressed" / "core" / "groth16")
      - `[prover].proof_mode` (string: "fri" / "groth16" / "groth16-wa")
      - `[prover].workers` (already exists in struct, unused) — propagate
- [x] **DONE** (2026-05-03, `WW-prover-mode-wiring-workers`):
      `[prover].workers` is now propagated through
      `OverlayConfig.ProverWorkers` into the existing
      `prover.NewParallelProverWithObservability(...)` call inside
      `pkg/overlay/node.go::NewOverlayNodeWithObservability`. The
      previous hard-coded `1` is replaced with `config.ProverWorkers`
      (clamped to 1 when zero / negative). `cmd/bsvm/main.go` keeps
      the single-prover construction at the call-site; the parallel
      coordinator already lives inside the overlay so no separate
      fan-out wrapper was needed. Coverage:
      `TestNodeConfig_ToOverlayConfig_PropagatesProverWorkers`
      (cmd/bsvm) and `TestOverlayNodeProverWorkersPropagation`
      (pkg/overlay) — the latter asserts `ParallelProver.Metrics().
      Workers` matches the configured value across {0,-3,2,8}.
- [x] **DONE** (2026-05-03, `WW-prover-mode-wiring-execute`): a new
      `prover.ProverExecute` mode was added next to local / network /
      mock. Setting `[prover].mode = "execute"` (or constructing a
      `prover.Config{Mode: ProverExecute}` directly) dispatches to
      `proveExecute` in `pkg/prover/host.go`, which invokes the
      host-bridge binary with envelope `mode = "execute"` so the
      Rust side runs revm in SP1's RISC-V emulator (no STARK).
      Output mirrors the bench harness shape: hex-decoded
      PublicValues + cycle count + VKHash + proving-time. Validation
      enforces the same HostBridgeBinary + GuestELFPath requirement
      as `local`. Coverage:
      `TestProveExecuteModeBranches_Switch` (end-to-end through a
      stub host-bridge, asserts cycles + PublicValues shape + that
      the bridge envelope carried `mode = "execute"`),
      `TestProveExecuteModeBranches_RequiresPaths`,
      `TestProveExecuteBridgeError`, `TestProveExecuteModeStringer`
      (pkg/prover) plus `TestNodeConfig_ToProverConfig` /
      `TestProverSection_Validate` updates (cmd/bsvm).

**Notes for the operator**: With the WW-prover-mode-wiring-workers
and WW-prover-mode-wiring-execute fixes the TOML path now drives
the runtime prover end-to-end: `[prover].mode` selects backend
(`mock` / `execute` / `local` / `network`), `[prover].workers`
controls the overlay's ParallelProver concurrency, and the
remaining knobs (`host_bridge_binary` / `guest_elf_path` /
`network_url` / `timeout` / `proof_mode` / `sp1_proof_mode`) round-
trip through `ToProverConfig`. The two `bsv_wiring.go:347` and
`deploy_shard.go:347` citations remain best read as "the rest of
the broadcast/deploy stack correctly refuses to lie about its
capability" rather than as separate gaps. `BSVM_PROVE_MODE` env var
is still wired to `cmdInit` flags only; it does NOT control the
runtime prover backend (use `[prover].mode` for that).

---

## Claim 2: BEEF / follower architecture only partially implemented (spec 17)

**Source (reviewer's wording)**: "`/bsvm/beef/covenant-chain` is a
generic POST handler instead of the spec-required GET catch-up;
consumers are mostly log-only." Cited lines:
`pkg/rpc/beef_routes.go:62`, `pkg/rpc/beef_routes.go:77`,
`pkg/rpc/beef_routes.go:99`, `cmd/bsvm/beef_wiring.go:139`.

**Verification**:

- `pkg/rpc/beef_routes.go:62-70` (`Mount`) registers
  `/bsvm/beef/covenant-chain` via `mux.HandleFunc` — no method
  pinning at the mux level.
- `pkg/rpc/beef_routes.go:77-79` (`handleCovenantChain`) delegates
  to `b.handle(...)` with no GET branch.
- `pkg/rpc/beef_routes.go:99-103` (`handle`) hard-rejects anything
  that is not POST: `if r.Method != http.MethodPost { ... method not
  allowed ... }`.
- `cmd/bsvm/beef_wiring.go:135-167` (`SetupBEEF`) builds a
  `bridgeConsumer` for real verification (via `makeBridgeConsumer`)
  but wires `InboxConsumer` / `GovernanceConsumer` /
  `FeeWalletConsumer` / `CovenantConsumer` to the shared `logOnly(...)`
  closure. The inline comment at lines 137-141 explicitly admits
  this is a follow-up: "Inbox / governance / fee-wallet-funding /
  covenant-advance: log-only. Each intent will graduate to a real
  consumer once the matching subsystem is wired in a follow-up wave
  (W6-5+ for inbox / governance, overlay covenant manager for
  covenant-advance)."
- Spec 17 line 949 is unambiguous: "...calling a peer's `GET
  /bsvm/beef/covenant-chain?from=<tip>` RPC (exposed on the same
  HTTP server as the explorer UI, spec 15) to pull the covenant
  BEEFs sequentially". The bootstrap-from-peers path requires this
  endpoint to be a *GET that takes a cursor*, not a POST that
  accepts an envelope.
- Verdict: **confirmed-gap**. There are actually two gaps bundled
  here: (a) the GET catch-up endpoint is missing entirely, and
  (b) four out of five consumers are log-only. The bridge consumer
  is the only real one, courtesy of W6-4.

**Scope**: M (≤1w). The GET endpoint itself is small (≤1d) — iterate
the `BEEFStore` keyed by intent + cursor + return a stream of
serialised envelopes. The four log-only consumers are L (≤1mo)
because each requires its own subsystem to exist (inbox executor,
governance broadcaster, fee-wallet manager, overlay covenant
manager). The right framing is to land the GET endpoint now and
keep the consumer wiring as separate W6-5/W6-6/W6-7 line items.

**Mainnet blast radius**: **high**. Without the GET endpoint, a
fresh node has no bootstrap path that uses peers — it would fall
back to spec 11's `SyncFromBSV` walk, which spec 17 line 952-954
says is supposed to be "entirely replaced". On mainnet this means a
new node operator either consults BSV-node block bodies directly
(against spec 17's design) or cannot bootstrap from peers at all.
The log-only consumers are lower-priority because there's no
*incorrect* state being credited — bridge deposits are the only
intent that touches L2 balances, and that one is real.

**Recommended path**:
- [x] **DONE** (2026-05-03 via daec23c):
      `W6-beef-covenant-chain-get-endpoint` — `GET /bsvm/beef/
      covenant-chain?from=<txid>&limit=<n>` returns a length-prefixed
      concatenation of confirmed (intent 0x02) advance envelopes in
      receive order, strictly after the cursor; bootstrap-from-peers
      now works without falling back to spec 11's `SyncFromBSV`.
      Wire format pinned in `docs/decisions/W6-beef-covenant-chain-
      get.md`. Documented separately so a follower implementer
      doesn't have to reverse-engineer the response shape from the
      handler. Default limit 100, hard cap 500.
- [x] **DONE** (2026-05-03): `WW-inbox-consumer` —
      `cmd/bsvm/beef_wiring.go::makeInboxConsumer` now extracts the
      EVM `txRLP` from the BEEF target tx's input-0 unlock script
      (the inbox covenant Submit() call) via the in-tree decoder in
      `cmd/bsvm/beef_extractors.go::extractInboxTxRLP`, then queues
      it via `InboxMonitor.AddInboxTransaction`. A consumer-side
      dedup set keyed on target txid drops duplicate envelopes
      (re-broadcast, unconfirmed/confirmed pair) so the queue is not
      double-extended.
      Upstream gap: runar-go does not expose a public unlock-script
      decoder for the Submit() shape; the in-tree extractor relies
      on the codegen invariant `[codePart, opPushTxSig, txRLP]`
      (3 pushes for a single-public-method stateful contract). When
      runar-go grows its own decoder we should swap to it; that gap
      is tracked as `WW-runar-inbox-decoder`.
      Coverage: `TestWireBEEFEndpointsInboxConsumerWires` posts a
      Submit()-shaped envelope twice and asserts PendingCount goes
      0 → 1 → 1 (dedup); `TestWireBEEFEndpointsInboxConsumerNotWired`
      keeps the structured-log fallback path covered.
- [x] **DONE** (2026-05-03): `WW-governance-consumer` —
      `cmd/bsvm/beef_wiring.go::makeGovernanceConsumer` now decodes
      the new CovenantState from the BEEF target tx's output-0
      locking script via
      `cmd/bsvm/beef_extractors.go::extractCovenantStateFromTx`,
      diffs against `OverlayCovenantManager.CurrentState()`, and
      calls `governance.Workflow.CreateOrMerge` with a freeze /
      unfreeze proposal when the Frozen flag transitions. The
      content-addressed `Proposal.ID` dedups identical proposals
      across BEEF replays AND across the existing
      `covenantMgr.SetStateChangeCallback` path — the double-fire
      concern is structurally resolved by Workflow's content-hash
      ID derivation.
      Sub-gap (still open): the BEEF path does not yet emit
      `ActionUpgrade` proposals — recovering the new covenant
      script hash requires walking the BSV-tx output 0 for the
      pre-state covenant continuation script (different from the
      `CovenantState` push) and hashing it. Tracked separately as
      `WW-governance-upgrade-extractor`. When a 0x06 envelope
      records a state change that isn't a freeze/unfreeze
      transition, the consumer logs that named hook + skips
      proposal creation.
      Coverage: `TestWireBEEFEndpointsGovernanceConsumerWires`
      posts an envelope whose new state has Frozen=1 against an
      empty local tip; asserts a single freeze proposal is created
      and a re-POST is content-hash-deduped.
      `TestWireBEEFEndpointsGovernanceConsumerNotWired` keeps the
      structured-log fallback path covered.
- [x] **DONE** (2026-05-03): `WW-fee-wallet-consumer` —
      `cmd/bsvm/beef_wiring.go::makeFeeWalletConsumer` now reads
      the wallet's expected locking script via the new
      `FeeWallet.ExpectedScriptPubKey()` accessor, walks the BEEF
      target tx's outputs via
      `cmd/bsvm/beef_extractors.go::extractFeeWalletOutputs`, and
      credits each matching output as a FeeUTXO via the wallet's
      idempotent `AddUTXO` method. The cmd-side bsv_wiring.go
      publishes the wallet's expected script at boot
      (`feeWallet.SetExpectedScriptPubKey(bsv.BuildP2PKH(pkh))`)
      after deriving the fee-wallet key.
      AddUTXO is idempotent on (txid, vout) so a re-broadcast
      envelope is a wallet-level no-op without extra consumer-side
      dedup.
      Coverage: `TestWireBEEFEndpointsFeeWalletConsumerWires`
      posts an envelope with a matching output and asserts Balance
      goes 0 → matched-sats → matched-sats (idempotent re-credit).
      `TestWireBEEFEndpointsFeeWalletConsumerNoScript` keeps the
      structured-log fallback path covered for the boot edge case
      where the wallet has not yet published its script.
- [x] **DONE** (2026-05-03): `WW-overlay-covenant-consumer` —
      `cmd/bsvm/beef_wiring.go::makeCovenantConsumer` now extracts
      the spec-12 OP_RETURN payload (`BSVM\x02 || withdrawalRoot ||
      batchData`) from the BEEF target tx outputs via
      `cmd/bsvm/beef_extractors.go::extractCovenantAdvance`,
      decodes the embedded `block.BatchData`, constructs a
      `CovenantAdvanceEvent` with the target txid + IsOurs flag
      computed against `CovenantManager.CurrentTxID()`, and calls
      `RaceDetector.HandleCovenantAdvance`. A consumer-side dedup
      set keyed on target txid drops duplicate envelopes; the
      libp2p `MsgCovenantAdvance` path
      (`pkg/network/sync.go`) is independent and the RaceDetector
      itself tolerates two events for the same advance (the second
      is a no-op vs. consecutive-loss tracking).
      `L2BlockNum` is left zero by the BEEF-driven path: the
      `block.BatchData` blob carries `ParentHash` not block-number,
      and the race detector compares by txid not by height — the
      libp2p path keeps the height-precise dispatch when both
      sources are wired.
      Coverage: `TestWireBEEFEndpointsCovenantConsumerWires` feeds
      a real spec-12 OP_RETURN envelope twice through the consumer
      with a bare RaceDetector; asserts OnRaceLost fires once,
      observed event has the right txid + non-empty BatchData, and
      the dedup blocks the second call.
      `TestWireBEEFEndpointsCovenantConsumerNotWired` keeps the
      structured-log fallback path covered.
- [ ] **TODO** (`WW-runar-inbox-decoder`): runar-go does not expose
      a public unlock-script decoder for the inbox covenant's
      Submit() shape; the in-tree extractor in
      `cmd/bsvm/beef_extractors.go::extractInboxTxRLP` reverse-
      engineers the codegen invariant `[codePart, opPushTxSig,
      txRLP]` for stateful single-public-method contracts. When
      runar-go grows its own decoder (or exposes the artifact's ABI
      so the call site can be method-name-aware) the in-tree
      extractor should swap to the upstream API. No cross-repo
      edits in this PR — the gap is documented inline at the
      extractor's package comment.
- [ ] **TODO** (`WW-governance-upgrade-extractor`): the BEEF
      governance consumer does not yet emit `ActionUpgrade`
      proposals because the new covenant script hash is not in the
      `CovenantState` push — recovering it requires walking output
      0's locking script for the pre-state covenant continuation
      script (different from the 42-byte CovenantState push) and
      hashing it. When the upgrade flow lands the consumer's switch
      gains a third arm; the named hook is logged today when a
      state change isn't a freeze/unfreeze transition so an
      operator sees why an upgrade-shaped envelope wasn't enqueued.
- [ ] Push back (still open): spec 17 line 949 names the route but
      did not pin the wire format of the GET response until
      `docs/decisions/W6-beef-covenant-chain-get.md` landed. The
      original push-back wording should be folded into spec 17
      §"Bootstrap" so future readers see the contract inline rather
      than via a decisions doc cross-reference.

**Notes for the operator**: The reviewer's bullet-3 phrasing
("consumers are mostly log-only") was correct at the time of the
review but no longer applies — all four log-only consumers were
graduated to real receiver dispatches in the 2026-05-03 follow-up
(see DONE bullets above). Two named upstream gaps remain
(`WW-runar-inbox-decoder`, `WW-governance-upgrade-extractor`); both
are surfaced via structured-log `todo_hook` fields the operator can
grep when an envelope shape isn't yet handled.

---

## Claim 3: Admin UI / RPC not complete against spec 15

**Source (reviewer's wording)**: "`admin_setConfig` always errors;
bridge health/rescan are placeholders; multisig governance broadcast
is logged-only." Cited lines: `pkg/rpc/admin_api.go:92`,
`pkg/rpc/admin_api.go:225`, `pkg/rpc/admin_api.go:238`,
`cmd/bsvm/main.go:826`.

**Verification**:

- `pkg/rpc/admin_api.go:87-94` (`SetConfig`): "Until live-reload
  lands for individual settings, this handler accepts the request
  but always returns an error indicating a restart is required."
  The function body is `return nil, fmt.Errorf("admin_setConfig:
  live reload not yet implemented (restart required to change %q)",
  key)`. Confirmed.
- `pkg/rpc/admin_api.go:223-235` (`BridgeHealth`): "is a spec 15
  stub. A real implementation calls into pkg/bridge once the
  monitor is attached to the overlay node." Returns hard-coded
  zero state with a `note` field saying "bridge monitor not yet
  attached to overlay — returning zero state". Confirmed.
- `pkg/rpc/admin_api.go:237-240` (`RescanDeposits`): "is a spec
  15 stub." Always returns `fmt.Errorf("admin_rescanDeposits:
  bridge monitor not yet attached to overlay")`. Confirmed.
- `cmd/bsvm/main.go:826-836`: `proposalWorkflow.OnReady(...)` is
  configured to *log* when a proposal reaches threshold:
  `slog.Info("governance proposal ready for broadcast", ...)`.
  No BSV broadcast is performed. The inline comment at lines
  827-829 admits "v1: log when a proposal reaches threshold. The
  actual BSV broadcast path lands when the governance broadcaster
  is wired up to the covenant manager."
- Spec 15 §"Configuration" (lines 410-427) does say the UI
  consumes `admin_getConfig` and `admin_setConfig` and that "the
  UI shows a 'Restart Required' indicator for changes that need a
  node restart" — it does NOT promise live reload for any
  specific knob. So the always-error behaviour is a reasonable
  placeholder.
- Spec 15 §"Bridge Administration" (lines 449-463) and
  `admin_bridgeHealth` / `admin_rescanDeposits` schemas at lines
  555-567 are detailed; the current zero-state response satisfies
  the JSON shape but returns no useful data.
- Spec 15 §"Multisig governance actions" (lines 68-77, step 5)
  is explicit: "When M signatures are collected, the overlay
  node broadcasts the BSV transaction." The current `OnReady`
  handler does not broadcast.
- Verdict: **confirmed-gap (partially-confirmed on setConfig)**.
  All three placeholders are real. `admin_setConfig`'s always-error
  behaviour is *consistent with spec 15* (which doesn't promise
  live reload), but spec 15 *does* imply that some keys should
  apply at runtime ("Changes take effect immediately"). The bridge
  + governance gaps are unambiguous.

**Scope**:
- `admin_setConfig` live-reload subset: M (≤1w). Pick a
  whitelist of keys (gas price, batch size, flush delay, peer list)
  that can be applied to the overlay node without restart, then
  plumb through.
- `admin_bridgeHealth` + `admin_rescanDeposits` real
  implementations: M (≤1w) once the bridge monitor is attached
  to the overlay node — both are mostly read-only delegations to
  `pkg/bridge`.
- Multisig governance broadcast: M (≤1w). Build the BSV
  transaction in the OnReady callback, sign with the threshold
  signatures collected on the proposal, and submit via the
  existing ARC client.

**Mainnet blast radius**:
- `admin_setConfig`: **low**. Operators can restart to change
  config. No security-relevant knob is reachable via this method
  today, so the failure mode is "operator inconvenience" not
  "wrong state".
- `admin_bridgeHealth` / `admin_rescanDeposits`: **medium**.
  Operators cannot detect a `totalLocked != totalSupply`
  mismatch from the admin UI — they must read the bridge logs
  directly. Missed deposits cannot be rescanned via RPC. This is
  a monitoring gap rather than a correctness gap.
- Multisig governance broadcast: **high**. The whole point of
  multisig governance is that *the threshold signature should
  trigger a BSV broadcast*. Today the threshold is collected and
  then nothing happens. An operator who genuinely needs to
  freeze a misbehaving shard would discover at the worst possible
  moment that signatures don't actually broadcast. The workaround
  (manually craft + sign + broadcast the BSV tx) is feasible but
  defeats the spec 15 §"Multisig governance actions" UX.

**Recommended path**:
- [x] **DONE** (2026-05-03): `admin-setConfig-live-reload` —
      `pkg/rpc/admin_live_reload.go` defines a `LiveReloader` with a
      whitelist that `admin_setConfig` consults. Initial entry is
      `log_level` (mutates the slog `*LevelVar` in-place; persisted
      to `<datadir>/admin_overrides.json` and re-applied on the next
      boot). Non-whitelisted keys return `admin_setConfig: key %q
      requires restart (not in live-reload whitelist; whitelisted
      keys: [...])`. Additional whitelist candidates
      (`metrics.scrape_interval`, `network.gossip_max_peers`) stay
      deferred — those subsystems don't yet expose runtime setters,
      and shipping a half-wired applier would silently no-op. See
      `docs/operator/admin.md` §"Live-reload whitelist".
- [x] **DONE** (2026-05-03): `admin-bridge-monitor-rpc` —
      `pkg/rpc/admin_bridge.go` exposes `SetBridgeMonitor` /
      `SetBridgeRescanner` on `AdminAPI`. `cmd/bsvm/main.go` calls
      `SetBridgeMonitor` immediately after `BuildBridgeMonitor`.
      `admin_bridgeHealth` now reports the live (txid, balance,
      lastClaimedNonce, depositHorizon, pendingDeposits, shardId)
      tuple instead of zero-state. When `[bridge].bridge_script_hex`
      is empty the response surfaces `monitorAttached=false` with
      operator guidance. See `docs/operator/admin.md` §"Bridge admin".
- [x] **DONE** (2026-05-03): `WW-bridge-rescanner-attach` —
      `cmd/bsvm/bridge_blockscan_wiring.go` now exposes a
      `BlockScannerHandle` with channel-based command pattern
      (`RewindToHeight(uint64) (scheduled, error)` +
      `CurrentCursor() uint64`). The supervisor goroutine retains
      sole ownership of the resume cursor; the handle's methods
      enqueue typed `rewindCmd`s the goroutine drains in its select
      loop, between block events, during reconnect-backoff sleeps,
      and around chaintracks subscribe attempts. `cmd/bsvm/main.go`
      installs a closure on `AdminAPI.SetBridgeRescanner` that calls
      `handle.RewindToHeight(fromHeight)` whenever
      `startBridgeBlockScanner` returns a non-nil handle (i.e.
      whenever bridge AND chaintracks are configured). The rewind
      is one-shot (does NOT alter resume-after-restart semantics);
      idempotent (rewinds to ≥ current cursor are no-ops);
      tip-failure-tolerant (cursor change still applies, scheduled
      degrades to 0 with the wrapped error). Coverage in
      `cmd/bsvm/bridge_blockscan_rescan_test.go` drives the full
      AdminAPI → closure → handle → cursor-rewind path with a fake
      chaintracks subscriber. See `docs/operator/admin.md`
      §"Bridge admin".
- [x] **DONE** (2026-05-03): `governance-broadcast-onready` —
      `cmd/bsvm/main.go`'s `OnReady` callback is no longer log-only.
      Freeze + unfreeze proposals at threshold now build a real BSV
      spend tx (via `pkg/covenant.BuildFreezeUnlockScript` /
      `BuildUnfreezeUnlockScript` and
      `deploy/covenant.BuildUpgradeSpendTx`) and broadcast through
      the daemon's ARC client. ARC failures surface at WARN with the
      full assembled tx hex so operators can retry; the proposal
      stays in the workflow store so a re-sign re-fires the
      threshold event. Upgrade proposals stay deferred — the
      proposal payload as defined in spec 15 doesn't carry the SP1
      proof bundle `BuildUpgradeUnlockScript` requires; that
      sub-gap is tracked separately as
      `WW-governance-payload-extension`. See
      `docs/operator/admin.md` §"Multisig governance proposals".
- [x] **DONE** (2026-05-03): documented the threshold flow + the
      ARC-failure UX in `docs/operator/admin.md` so an operator
      reading the runbook knows exactly what happens at threshold
      time AND which actions are deferred.

**Notes for the operator**: The three sub-claims have very
different urgencies. Multisig broadcast is the only one that
matters for a security-incident response, and it is the easiest
of the three to fix (~1 day). The bridge-health placeholder is
gated on the monitor wiring landing first.

---

## Claim 4: EVM fork target does not match spec 01 (Cancun vs Prague/Pectra)

**Source (reviewer's wording)**: "spec calls for Prague/Pectra-era
pre-EOF; implementation is Cancun (Prague aliased to Cancun)." Cited
lines: `cmd/bsvm/config.go:93`, `prover/guest/src/main.rs:557`,
`pkg/vm/jump_table.go:89`, `pkg/vm/evm.go:475`.

**Verification**:

- `cmd/bsvm/config.go:93-99`: "supportedEVMForks" allows ONLY
  `"cancun"`. Comment at lines 84-90: "Only \"cancun\" is supported
  in v1. The Rust SP1 guest pins SpecId::CANCUN; the Go EVM
  defaults DefaultL2Config to CancunTime=0 (active from genesis)."
  Comment explicitly excludes EOF / Fusaka.
- `prover/guest/src/main.rs:557`: `Context::new(db.clone(),
  SpecId::CANCUN);` — confirmed, Rust guest is pinned to Cancun.
- `pkg/vm/jump_table.go:89-92`: `newPragueInstructionSet()` returns
  `validate(newCancunInstructionSet())` — Prague is literally an
  alias for Cancun, with no Prague-specific opcodes activated.
  None of the canonical Prague EIPs (EIP-7702 SetCode for EOAs,
  EIP-2537 BLS12-381 precompiles, EIP-7251 increase MAX_EFFECTIVE_BALANCE,
  EIP-6110 deposit requests, EIP-7549 attestations) are wired.
- `pkg/vm/evm.go:474-486`: `resolveCode` and `resolveCodeHash` have
  comments about "After Prague, it can also resolve code pointed to
  by a delegation designator" but the implementations just delegate
  straight to `StateDB.GetCode` / `GetCodeHash` — no EIP-7702
  delegation handling.
- Spec 01 line 9: "use a geth tag from the **Prague/Electra
  (Pectra) hardfork** era, before EOF activation". Spec 01 line 116
  in the example `DefaultL2Config`: `PragueTime: &zeroTime` (i.e.
  Prague active from genesis).
- Verdict: **confirmed-gap (partially-confirmed)**. The reviewer
  is correct that the implementation is Cancun-equivalent and that
  spec 01 calls for Prague/Pectra. However:
  - `pkg/vm/config.go:24-50` *does* include `PragueTime` and
    activates it at genesis (so the chain rules report
    `IsPrague=true`), and
  - `cmd/bsvm/config.go:84-90`'s comment explicitly states this
    discrepancy is a *known choice* ("Only 'cancun' is supported
    in v1"), not an oversight.
  So this is best characterised as "code intentionally lags spec";
  either spec 01 needs to relax to "Cancun for v1, Prague for vN"
  or the implementation needs to add the Prague EIPs.

**Scope**: L (≤1mo) for the full Prague delta:
- EIP-7702 SetCode for EOAs — non-trivial: needs new tx type,
  delegation-designator code path, both Go EVM and Rust guest
  changes.
- EIP-2537 BLS12-381 precompiles (0x0b-0x11) — substantial: need
  pure-Go BLS12-381 implementations or cgo-bound `blst`.
- The consensus-layer Prague EIPs (6110, 7002, 7251, 7549, 7685)
  are mostly L1-validator-economy and likely **not relevant** to
  an L2 — but spec 01 doesn't say which Prague EIPs are in scope.

If the answer is "v1 ships Cancun; relax the spec", the scope
shrinks to S (≤1d) for the spec-update PR.

**Mainnet blast radius**: **medium** if we ship as Cancun and call
it Prague (subtle compatibility surprise: contracts compiled with a
solc Prague target may emit opcodes / precompile calls the EVM
doesn't have); **low** if we ship as Cancun and *say so*. The
biggest concrete risk is third-party tooling that asks
`eth_chainId` + assumes Prague rules and gets surprised when an
EIP-7702 delegated-call fails.

**Recommended path**:
- [x] **DONE** (2026-05-03): spec 01 §"Source" updated to state
      "v1 fork target: Cancun (Prague deferred)" and the §"EVM
      version note" near the point-evaluation precompile section
      mirrors the same wording. `DefaultL2Config` example in spec
      01 now shows `PragueTime: nil` with a comment pointing at the
      hook. The Prague delta is tracked under the
      `WW-prague-fork-bump` named hook; bumping the
      `supportedEVMForks` set in `cmd/bsvm/config.go` is part of
      that work. The inline comment in `cmd/bsvm/config.go:74-99`
      now also names `WW-prague-fork-bump` so a code reader can
      grep for it.

**Notes for the operator**: The implementation+spec mismatch is
real. The simplest resolution is the spec update — the
implementation's "Cancun-only" stance is well-defended by the
config.go comment and by the deliberate `PragueTime` reservation.
If we go the implementation-update route, EIP-7702 alone is
~2 weeks of work because it changes the call resolver in *both*
EVMs (Go and the Rust SP1 guest) and the proof public-values
layout has to stay byte-identical between them.

---

## Claim 5: BSV precompile status ambiguous (spec 01)

**Source (reviewer's wording)**: "spec 01 both says 'reserved/not
active' and 'completed in later milestone' — code registers stubs
returning `ErrBSVPrecompileNotActive`. Could be a spec wording bug,
not a code bug." Cited lines: `pkg/vm/contracts.go:77`,
`pkg/vm/contracts.go:742`.

**Verification**:

- `pkg/vm/contracts.go:77-92`: BSV precompiles at 0x80, 0x81, 0x82
  are registered with `&stubBSVPrecompile{}` only when
  `rules.IsBSVM` is true. Comment at lines 77-87 explicitly notes
  the design intent: "Per Spec 01, these must be present so that
  calls to 0x80-0x82 revert rather than silently succeeding with
  empty return data."
- `pkg/vm/contracts.go:742-751`: `stubBSVPrecompile` implementation
  consumes `len(input)` gas and returns
  `(nil, ErrBSVPrecompileNotActive)`. This matches spec 01 lines
  468-481 *exactly* (including the gas formula).
- Spec 01 §"Custom BSV Precompiles" (lines 445-489):
  - Line 455-456: "Interfaces are defined in Phase 1 (Milestone 1)
    alongside the standard precompiles. Implementations are
    completed in Milestone 5 (Overlay Node) when BSV connectivity
    is available."
  - Line 460-462: "**Before implementation (Milestones 1-4)**:
    Calls to BSV precompile addresses (0x80-0xFF) revert with an
    error indicating the precompile is not yet active."
  - Line 483: "**BSV Precompile Input/Output Formats** (reserved,
    not active in v1)". This phrasing, taken alone, *could* be
    read as "stays a stub forever in v1". Combined with line 456
    ("completed in Milestone 5") and CLAUDE.md's "Packages and
    Concepts That Do NOT Exist" list — which includes "Any
    BSV-specific gas payment logic in the EVM or RPC layer" but
    does NOT exclude SPV/script-verify precompiles — the intent
    seems to be "stubs in M1, real in M5".
- Verdict: **not-a-gap-and-here-is-why** — the code matches
  spec 01's M1-M4 behaviour exactly. The reviewer's hypothesis
  ("could be a spec wording bug, not a code bug") is correct: the
  spec phrasing at line 483 ("reserved, not active in v1") is in
  tension with line 456 ("completed in Milestone 5"). Spec 09's
  implementation order has us at Milestone 7+ today, so the M5
  promise is overdue, but that is a separate question from
  whether the *current* stub behaviour is wrong (it is not).

**Scope**: S (≤1d) for the spec-clarification PR. The implementation
work to actually wire the three precompiles to the overlay's BSV
connectivity is separately L (≤1mo) — it requires producing
deterministic SPV proofs that survive being re-executed inside
the SP1 guest, which is non-trivial.

**Mainnet blast radius**: **low** as long as the stubs stay loud.
Contracts that try to call 0x80-0x82 today fail explicitly with
`ErrBSVPrecompileNotActive` and consume all provided gas — same
behaviour as a non-existent precompile address. The risk on
mainnet is "third-party Solidity contract assumes BSV_VERIFY_TX
exists, deploys, fails at runtime" — that is a
contract-developer-facing failure, not a node-correctness failure.

**Recommended path**:
- [x] **DONE** (2026-05-03): spec 01 §"Custom BSV Precompiles"
      rewritten so both the lead-in paragraph and the I/O-formats
      paragraph use consistent "reserved in v1 / activated under
      `BSV-precompiles-activation`" wording. The earlier
      "completed in Milestone 5" claim is gone; the spec now
      matches the stub behaviour committed in
      `pkg/vm/contracts.go`. The stub doc comments in
      `pkg/vm/contracts.go` (the registration block and the
      `stubBSVPrecompile` type comment) now name the
      `BSV-precompiles-activation` hook so a code reader can grep
      for it.
- [ ] Open a tracked TODO with named hook
      `BSV-precompiles-activation` once the activation plan is
      ready — the implementation work depends on the SPV
      witness format the SP1 guest can verify.

**Notes for the operator**: Do not change the precompile code in
this pass. The stub is the contract spec 01 §"Before
implementation" requires. If anything, the gas cost
(`len(input)`) is more generous than mainnet's "consume all gas"
norm for failed precompiles — worth revisiting at M5
activation time but harmless today.

---

## Aggregate ranking

Sorted by (mainnet blast radius × scope), highest priority first.
Blast radius is the dominant axis — a high-blast item with M scope
beats a medium-blast item with M scope.

| Rank | Claim                                                      | Verdict                  | Scope | Blast radius | Recommended TODO hook                  |
|------|------------------------------------------------------------|--------------------------|-------|--------------|----------------------------------------|
| 1    | #2 BEEF GET catch-up endpoint (sub-bullet a only)          | confirmed-gap            | S-M   | high         | `W6-beef-covenant-chain-get-endpoint`  |
| 2    | #3c Multisig governance broadcast on threshold             | confirmed-gap            | M     | high         | `governance-broadcast-onready`         |
| 3    | #1 Prover backend config + ELF / host-bridge wiring        | DONE (2026-05-03)        | M     | medium       | `WW-prover-mode-wiring` (workers + execute closed) |
| 4    | #3b Bridge-health / rescan RPC plumbing to bridge monitor  | confirmed-gap            | M     | medium       | `admin-bridge-monitor-rpc`             |
| 5    | #4 EVM Cancun-vs-Prague spec-vs-code mismatch              | partial (spec-update)    | S     | medium       | spec 01 wording PR                     |
| 6    | #2 four log-only BEEF consumers (sub-bullet b only)        | DONE 2026-05-03          | L     | medium       | `WW-{inbox,governance,fee-wallet,overlay-covenant}-consumer` (graduated; two named follow-ups: `WW-runar-inbox-decoder`, `WW-governance-upgrade-extractor`) |
| 7    | #3a admin_setConfig live-reload whitelist                  | partial (spec-implies)   | M     | low          | `admin-setConfig-live-reload`          |
| 8    | #5 BSV precompile status ambiguity                         | not-a-gap (spec wording) | S     | low          | spec 01 wording PR (line 483)          |

**Pick-up order recommendation for the operator**: items 1 and 2 are
the only ones with "high" blast radius and bounded scope; both can
land in <1 week each. Item 3 (prover wiring) is a prerequisite for
any honest pre-mainnet readiness claim. Items 5 and 8 are
spec-wording PRs that should be posted together (single
"spec-drift round 2" PR) so the spec catches up to the
implementation in one cycle. Item 6 stays as a parked epic — it
needs the dependent subsystems to land first.

## Items I could not verify

None. All five claims and all 12 cited file:line locations were
read at HEAD; spec 01, 12, 15, 16, 17 were spot-checked against
the cited claim text in each case. The only items I am unsure
about are forward-looking decisions (e.g. whether spec 01 should
be relaxed to Cancun-only or whether the EVM should be brought up
to Prague), which by construction the operator owns and not me.
