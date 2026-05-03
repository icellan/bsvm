# W6 — `GET /bsvm/beef/covenant-chain` catch-up wire format

## Status
Implemented. See `pkg/rpc/beef_routes.go` (handler) and
`pkg/beef/store.go` (`Store.IterateSince`).

## Background
Spec 17 §"Bootstrap" (line 949) says a fresh follower bootstraps a
shard by repeatedly calling

```
GET /bsvm/beef/covenant-chain?from=<tip>
```

on a peer to pull the covenant BEEFs sequentially, "until it has
caught up to the shard tip". Spec 17 names the route but does **not**
pin the wire format of the response.

Without this endpoint, a follower has no peer-driven bootstrap path.
Spec 11's `SyncFromBSV` walk (`findNextCovenantAdvance`) is the
fallback, but spec 17 §"Bootstrap" says it is "entirely replaced" —
on mainnet that means a new operator either consults BSV-node block
bodies directly (against the spec 17 design) or cannot bootstrap at
all and must wait for live gossip, which may never converge.

The triage doc
`docs/decisions/spec-review-triage-2026-05.md` ("Claim 2") proposed
the wire format below. This document formalises it so spec 17 §949
can reference it.

## Decision

### Request

```
GET /bsvm/beef/covenant-chain?from=<txid>&limit=<n>
```

| Param   | Required | Format                                           | Default | Cap |
|---------|----------|--------------------------------------------------|---------|-----|
| `from`  | yes      | 32-byte hex txid (with or without `0x` prefix)   | n/a     | n/a |
| `limit` | no       | positive integer 1..500                          | 100     | 500 |

The all-zero `from` (`0x000…0`) is the **genesis cursor**: the
response includes every covenant-advance envelope from the start of
the chain up to `limit`, oldest first. Operationally this is the
sentinel a brand-new follower uses on its first request.

`from` is interpreted as "the txid the follower already has". The
response stream contains envelopes **strictly after** `from` in
covenant-chain (oldest-first) order. The follower's next request
uses the txid of the last envelope it received as the new `from`.

Only **confirmed** covenant-advance envelopes
(`IntentCovenantAdvanceConfirmed = 0x02`) are returned. Unconfirmed
advances have no SPV proof yet, so a fresh follower cannot validate
them; surfacing them on the catch-up path would force followers to
trust the serving peer.

### Response

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: <total bytes>

<u32 BE length><envelope bytes>     # envelope #1
<u32 BE length><envelope bytes>     # envelope #2
…
<u32 BE length><envelope bytes>     # envelope #N  (N <= limit)
```

- `length` is the byte length of `<envelope bytes>`, encoded as a
  4-byte big-endian unsigned integer.
- `<envelope bytes>` is exactly the wire form produced by
  `beef.EncodeEnvelope(header, body)`: the 17-byte gossip envelope
  header followed by the BRC-62 BEEF body. Bytes are byte-identical
  to what a peer would have POSTed under the gossip-receive path on
  the same route.
- Envelopes appear in covenant-chain order, oldest first. The store
  orders by `ReceivedAt`; for the confirmed covenant chain that
  matches block-height order in steady state.
- An empty body (`Content-Length: 0`, body `""`) is a **valid 200
  response**: it means the follower is already at the tip. The
  follower polls again after a backoff.

### Errors

| Condition               | Status | Body                              |
|-------------------------|--------|-----------------------------------|
| missing `from`          | 400    | `from query param required`       |
| malformed `from`        | 400    | `from must be 32-byte hex txid`   |
| unknown `from` in store | 404    | `from txid not found`             |
| `limit` out of range    | 400    | `limit must be 1..500`            |
| store unavailable       | 503    | `beef store unavailable`          |
| store error             | 500    | `store error`                     |
| method not GET/POST     | 405    | `method not allowed`              |

The 404 case **does** distinguish from the 200/empty case: a 404
means the cursor itself is unknown to this peer (the follower should
either retry against another peer or fall back further along its
chain), while a 200 with empty body means "you are at the tip".

The genesis cursor (`0x000…0`) is **always** considered "found" so a
brand-new follower can request `from=0x000…0` and receive a 200 with
the full chain (or 200 with empty body if the peer has none yet).

### Method dispatch on the same path

`/bsvm/beef/covenant-chain` serves both directions:

- `GET`  → catch-up stream (this document)
- `POST` → existing covenant-advance gossip-receive path (spec 17
  §"Gossip receive")
- anything else → 405

The POST behaviour is unchanged from before this commit.

## Worked example: follower pulls 3 envelopes

A fresh follower has just connected to a peer and wants to bootstrap
the covenant chain.

### Step 1 — first request (genesis cursor)

```
GET /bsvm/beef/covenant-chain?from=0x0000000000000000000000000000000000000000000000000000000000000000&limit=3
```

Peer responds:

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1547

00 00 02 21  <545 bytes — envelope for covenant tx A>
00 00 01 e0  <480 bytes — envelope for covenant tx B>
00 00 01 fa  <506 bytes — envelope for covenant tx C>
```

Each `00 00 NN NN` quad is the u32 BE length prefix of the envelope
that follows.

The follower's parser:

```go
pos := 0
for pos < len(body) {
    if pos+4 > len(body) { /* truncated */ }
    n := binary.BigEndian.Uint32(body[pos : pos+4])
    pos += 4
    if pos+int(n) > len(body) { /* truncated */ }
    envBytes := body[pos : pos+int(n)]
    pos += int(n)

    hdr, beefBody, err := beef.DecodeEnvelopeHeader(envBytes)
    // hdr.Intent == beef.IntentCovenantAdvanceConfirmed
    // verify the BEEF (BUMP, ancestry, SP1 proof) and apply.
}
```

After applying envelopes A, B, C in order, the follower's local
tip is C.

### Step 2 — next request (from = txid(C))

```
GET /bsvm/beef/covenant-chain?from=<txid_C>&limit=3
```

Peer responds with up to 3 more envelopes in the same framing. The
follower repeats until it receives a 200 with `Content-Length: 0`,
at which point it transitions to live gossip and starts polling
periodically (or relies on inbound gossip pushed by the peer).

### Step 3 — peer doesn't know the cursor

If the follower's `from` cursor is on a chain branch this peer has
never seen (e.g. the follower was previously talking to a peer on a
forked tip), the request returns:

```
HTTP/1.1 404 Not Found

from txid not found
```

The follower then either tries another peer or falls back to a
known-good earlier cursor (e.g. its last-finalized covenant tip)
and retries.

## Implementation notes

- The cursor lookup is implemented in `beef.Store.IterateSince`,
  added in this commit. Both `MemoryStore` and `LevelStore` walk the
  same in-memory list of envelopes (sorted oldest-first by
  `ReceivedAt`, the same ordering used by the existing `Iterate`
  method) and skip past the cursor before emitting up to `limit`
  successors. Returning `(found bool, err error)` lets the handler
  cleanly distinguish "cursor unknown → 404" from "cursor known but
  no successors → 200 empty".
- The handler buffers the framed body in memory before writing the
  response so the 200 vs. 404 decision is taken before any bytes are
  sent. With `limit ≤ 500` and typical envelope sizes (a few hundred
  KB at the upper bound for Mode 1 advances), the buffer stays well
  below the 10 MB gossip-receive cap a peer is already willing to
  accept.
- The response intentionally omits a chain-version header. If the
  peer is on a different shard or covenant-script version, that is
  detected at envelope-validation time on the follower (the gossip
  envelope's `ShardID` and the BEEF's covenant-script ancestry both
  pin the chain). Adding a version preamble is a future option; it
  is not required for spec 17 §949 conformance.

## Open follow-ups

- **Spec 17 §949 update**: spec 17 currently names the route but
  does not pin the wire format. A follow-up edit to spec 17 should
  point at this decision doc; until then, the handler carries an
  inline `TODO(spec-17)` comment referencing this file.
- **True chain-ordering**: today the catch-up uses `ReceivedAt`
  ordering, which is correct for confirmed covenant advances on the
  serving peer. If a peer has both branches of a recent fork in its
  store, the catch-up could in principle interleave them. This is
  not a correctness hazard (the follower validates each envelope
  against its own running tip and rejects branches that don't link),
  but a future refinement could index covenant-advance envelopes by
  parent txid to serve a canonical linear walk.
