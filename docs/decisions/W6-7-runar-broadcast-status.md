# W6-7 — `runar_broadcast.go` triage status

## Verdict
**Not legacy. Actively in use. No action.**

## Background
Earlier W6 triage flagged `pkg/covenant/runar_broadcast.go` as a possible
legacy direct-RPC adapter that the spec-17 ARC client (`pkg/arc/`) was
meant to replace. The file was reported missing from the tree.

## Verification
- `find . -name '*runar*broadcast*'` returns
  `pkg/covenant/runar_broadcast.go` (10.7 KB, 317 LOC).
- `git log --all --diff-filter=D --name-only | grep -i runar.*broadcast`
  returns no deletions — the path has only ever been added/modified.
- The file is the implementation of `covenant.RunarBroadcastClient`,
  which `cmd/bsvm/bsv_wiring.go:144` constructs as the BSV
  covenant-advance broadcaster. It builds Rúnar `advanceState` calls
  via the runar-go SDK and submits them via the BSV `RPCProvider`.
  It does **not** duplicate the ARC client's role: ARC is for raw
  user-tx broadcast; this is the spec-12 covenant-advance path that
  must produce the contract call body via Rúnar.

## Conclusion
The triage hypothesis was incorrect. The file is the production
covenant-broadcast adapter, not a deprecated direct-RPC stub, and is
required by the bsvm binary. No deletion is performed.

If the orchestrator still wants this consolidated against ARC, that
is a larger redesign (collapsing the BSV-RPC `sendrawtransaction`
path inside `RunarBroadcastClient` onto `arc.MultiClient.Broadcast`)
and lives outside the W6 cleanup sweep.
