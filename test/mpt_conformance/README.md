# MPT Conformance Tests

Cross-implementation Merkle Patricia Trie conformance suite. The Go MPT
(`pkg/mpt/`, used by the overlay node) and the Rust `alloy-trie` (used inside
the SP1 guest) MUST produce byte-identical state roots for the same state, or
the prover will reject blocks the overlay accepts. This directory enforces
that invariant on every CI run.

## Running

- `go test ./test/mpt_conformance/...` — runs everything (Go-only fixtures
  and the cross-runner agreement test against `alloy-trie`). The first
  invocation runs `cargo build --release` inside `rust_runner/`, which is
  cached after that.
- `go test ./test/mpt_conformance/... -short` — skips the cross-runner test;
  useful when iterating on Go code without a Rust toolchain installed.
- `./rust_runner/target/release/rust_runner --fixture empty_trie.json --report /tmp/r.json`
  — runs a fixture standalone. Exit code is non-zero if any case's final
  root disagrees with the fixture's `expectedRoot`. The JSON report contains
  per-step roots so the cross-runner test can diff against the Go MPT after
  every operation. If `cargo` is not on `PATH`, the cross-runner test is
  skipped with a clear message.

## Adding a fixture

Drop a new `*.json` file in this directory. Each file is an array of cases
shaped like:

```json
[{
  "name": "human-readable description",
  "operations": [
    {"action": "put",    "key": "<32-byte hex>", "value": "<hex>"},
    {"action": "delete", "key": "<32-byte hex>", "value": ""}
  ],
  "expectedRoot": "0x<32-byte hex root after the last op, or empty>"
}]
```

`TestCrossRunnerAgreement` auto-discovers every `*.json` in this directory,
so no Go-side wiring is needed. Set `expectedRoot: ""` to skip the absolute
root check (useful while bootstrapping a fixture); the cross-runner test
still verifies Go ↔ Rust agreement step-by-step.

## Interpreting the report

The Rust runner emits one JSON object per fixture:

- `pass`: aggregate boolean, false if any case's final root mismatches
  `expectedRoot` or any case errored.
- `cases[].steps[]`: ordered list of `{index, action, actual}` — the trie
  root after each operation. The cross-runner test asserts `actual` matches
  the Go MPT's `Hash()` after the same operation.
- `cases[].final_root` / `cases[].final_match`: the root after every op was
  applied, plus whether it equals the fixture's `expectedRoot` (true if the
  fixture leaves `expectedRoot` empty).
- `cases[].error`: non-null only on malformed input (bad hex, unknown
  action). A correctness divergence does NOT populate this field — it shows
  up as a step-level mismatch in the cross-runner test.

A divergence between Go and Rust at any step is a P0 bug in either
`pkg/mpt/` or `prover/guest/src/mpt.rs`. Investigate before merging.
