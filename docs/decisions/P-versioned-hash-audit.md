# P: EIP-4844 Versioned-Hash Prefix Audit — point-evaluation precompile

Author: agent-aeee86d58aa899fb3 (task P)
Branch: `worktree-agent-aeee86d58aa899fb3`
Specs: EIP-4844 §"Point evaluation precompile" (precompile address `0x0a`).

## Context

Earlier task M wired EIP-4844 type-3 (blob) transaction RLP decode but
deliberately skipped the per-versioned-hash `0x01` prefix check at the
wire decoder, on the grounds that the point-evaluation precompile
already enforces it. This document audits that claim.

## Audit verdict: PRESENT (functionally equivalent)

The version-prefix check is enforced — implicitly but unconditionally —
by the equality check between the supplied versioned hash and the
freshly computed `kzgVersionedHash(commitment)`.

### Implementation references

`pkg/vm/contracts.go:670-681` — `pointEvaluation.Run`:

```go
var versionedHash [32]byte
copy(versionedHash[:], input[0:32])
z := input[32:64]
y := input[64:96]
commitment := input[96:144]
proof := input[144:192]

// Verify versioned hash matches commitment.
expectedHash := kzgVersionedHash(commitment)
if versionedHash != expectedHash {
    return nil, errors.New("versioned hash does not match commitment")
}
```

`pkg/vm/kzg.go:13-19` — the helper that the equality check is run against:

```go
// kzgVersionedHash computes the versioned hash of a KZG commitment.
// versioned_hash = 0x01 || SHA256(commitment)[1:]
func kzgVersionedHash(commitment []byte) [32]byte {
    h := sha256.Sum256(commitment)
    h[0] = 0x01 // Version byte
    return h
}
```

### Why this is functionally equivalent to an explicit prefix check

`kzgVersionedHash` always returns a 32-byte value whose first byte is
`0x01`. Therefore the equality test at `contracts.go:679` can only
succeed when `input[0] == 0x01`. Any other prefix (notably the
undefined `0x00`) makes the equality check fail, returning the
"versioned hash does not match commitment" error before any KZG pairing
work runs. This matches EIP-4844's pseudocode:

```
assert kzg_to_versioned_hash(commitment) == versioned_hash
```

EIP-4844 does not mandate that the version byte be tested separately
from the commitment binding — the spec is satisfied so long as the
precompile rejects every input where `versioned_hash != 0x01 ||
SHA256(commitment)[1:]`. The current code rejects all such inputs.

### Existing test coverage

`pkg/vm/kzg_test.go:78-97` — `TestPointEvaluationMismatchedVersionedHash`
already exercises the all-zero (i.e. `0x00`-prefixed) versioned hash
case and asserts the precompile returns the rejection error. No new
test is required.

## Conclusion

Task M's deferral was correct. The point-evaluation precompile rejects
every non-`0x01` prefix as a side effect of binding the versioned hash
to the commitment. No code change is needed.

## Related observations

- The point-evaluation precompile is wired into the precompile map
  under the `IsCancun` rule at `pkg/vm/contracts.go:74-76`. Whether
  the project's chain config actually flips `IsCancun = true` at the
  active fork is out of scope for this audit (task M owns tx-decode
  wiring; the broader Cancun bringup, including BLOBHASH opcode
  semantics, is a separate piece of work and is NOT audited here).
- No code change in this task; therefore no `go test` run was required
  by the playbook.
