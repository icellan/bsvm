# U: `test/evmtest/testdata` — Submodule Status Investigation

Author: agent-a5a853b4cf5c1dec5 (U-testdata-submodule)
Date: 2026-04-26
Branch: `worktree-agent-a5a853b4cf5c1dec5`

## TL;DR

`test/evmtest/testdata` is a **registered git gitlink (mode 160000)
pointing at ethereum/tests, but `.gitmodules` was never committed**.
Both this worktree's index AND the main repo's index have the gitlink
at commit `c67e485ff8b5be9abc8ad15345ec21aa22e290d9`. The "modified"
status comes from a nested submodule (`LegacyTests`) inside
ethereum/tests itself that is uninitialized in our checkout.

This is not a code bug, not lost data, and not destructive to ignore.
It is a long-standing repository hygiene issue: the gitlink was added
without a `.gitmodules` mapping, so `git submodule` commands cannot
operate on it.

## Evidence

### 1. The gitlink

```
$ git ls-files --stage test/evmtest/testdata
160000 c67e485ff8b5be9abc8ad15345ec21aa22e290d9 0	test/evmtest/testdata
```

Mode `160000` is the gitlink mode — git knows this is a submodule
pointer.

### 2. No `.gitmodules` mapping

```
$ cat .gitmodules
cat: .gitmodules: No such file or directory

$ git log --all --oneline -- .gitmodules
(empty — never committed on any branch)
```

Result: `git submodule status` errors:

```
fatal: no submodule mapping found in .gitmodules for path 'test/evmtest/testdata'
```

### 3. The pointed-to commit IS checked out (in main repo)

In the main repo (not this worktree), `test/evmtest/testdata` IS
populated with a real ethereum/tests checkout:

```
$ ls /Users/siggioskarsson/gitcheckout/bsv-evm/test/evmtest/testdata
ABITests/  ansible/  BasicTests/  BlockchainTests/  CHANGELOG.md
DifficultyTests/  docs/  EOFTests/
fixtures_blockchain_tests.tgz  fixtures_general_state_tests.tgz
GeneralStateTests/  GenesisTests/  JSONSchema/  KeyStoreTests/
LegacyTests/  LICENSE  PoWTests/  PRLOG.md  README.md
requirements.txt  ...

$ cd test/evmtest/testdata && git remote -v
origin  https://github.com/ethereum/tests.git (fetch)
origin  https://github.com/ethereum/tests.git (push)

$ git rev-parse HEAD
c67e485ff8b5be9abc8ad15345ec21aa22e290d9   ← matches the index gitlink

$ git log --oneline -3
c67e485 update LegacyTests
```

So the directory contents ARE the canonical `ethereum/tests` repo at a
specific commit, and that commit IS the one the parent repo's index
expects. **Nothing is lost.**

### 4. Worktree-side: directory is empty

In **this worktree**:

```
$ ls -la test/evmtest/testdata
total 0
drwxr-xr-x  2 siggioskarsson  staff   64 Apr 27 22:45 .
drwxr-xr-x  6 siggioskarsson  staff  192 Apr 27 22:45 ..
```

The directory is empty because git's worktree-create logic does not
materialize submodule content for a worktree that lacks
`.gitmodules`. The gitlink is present in the worktree's index but no
files are checked out. This is normal for a worktree of an
unregistered submodule — the parent repo's checkout has the content,
the worktree does not. The `test/evmtest/vm_test.go` runner accepts
an empty `testdata/` and skips the suite (see `t.Skipf` at the top of
`pkg/evmtest`-style runners).

### 5. The "modified content" status — root cause

In the **main repo**, `git status` shows:

```
modified:   test/evmtest/testdata (modified content)
```

This is NOT because the gitlink itself drifted (HEAD == indexed
commit). It is because ethereum/tests itself has a nested submodule:

```
$ cat test/evmtest/testdata/.gitmodules
[submodule "LegacyTests"]
	path = LegacyTests
	url = https://github.com/ethereum/legacytests

$ cd test/evmtest/testdata && git status --short
 M .gitignore
$ git submodule
-1f581b8ccdc4c63acf5f2c5c1b155c690c32a8eb LegacyTests
```

The `-` prefix on the LegacyTests submodule means it is registered
but not initialized. The `M .gitignore` is upstream's own state —
ethereum/tests has an uncommitted `.gitignore` change in its repo.
Both bubble up through the parent's "modified content" reporting.

So:

- The bsvm gitlink → ethereum/tests at `c67e485` is **clean**.
- The ethereum/tests checkout has its own nested submodule
  (`LegacyTests`) uninitialized.
- That uninitialization is reported by git as "modified content" of
  the bsvm-level submodule, even though bsvm's pointer is fine.

### 6. What `test/evmtest/` actually consumes

The runner files in `test/evmtest/`:

- `helpers.go` — JSON parsers (`StateTest`, `EnvJSON`, etc.).
- `state_test_runner.go` — drives the BSVM EVM through
  GeneralStateTest fixtures.
- `vm_test.go` — Go test entrypoint, walks
  `testdata/GeneralStateTests/` if present.

The fixtures consumed (`GeneralStateTests/`) live inside the
ethereum/tests submodule. They are the canonical Ethereum Foundation
state-test fixtures. CLAUDE.md spec 09 calls these out as the
"correctness oracle" for the EVM extraction.

So `testdata/` IS ethereum/tests fixtures — not vendored, not
accidentally committed `.git` data, and not unrelated content. The
gitlink is structurally correct; just the registration is missing.

## What the options are

### Option A — Re-register as a proper submodule (recommended)

Write `.gitmodules`:

```
[submodule "test/evmtest/testdata"]
	path = test/evmtest/testdata
	url = https://github.com/ethereum/tests.git
```

Commit `.gitmodules`. Run `git submodule init && git submodule
update --init --recursive` once, on operator workstations. CI gets a
`submodules: recursive` flag.

Pros:
- `git submodule status` works.
- `git clone --recurse-submodules` populates the fixture set
  automatically.
- `LegacyTests` (the nested sub) is correctly handled by
  `--recursive`.
- No content change — the gitlink still points at the same commit.

Cons:
- Operators with stale checkouts must run `git submodule init` once.
- CI needs the `recursive` flag added (see `.github/workflows/`).
- The nested `LegacyTests` submodule is ~150 MB extra; consider
  `--depth 1` cloning if disk matters.

### Option B — Vendor as a checked-in directory

Replace the gitlink with a regular directory of fixtures committed
straight into bsvm.

Pros:
- Simplest: no submodule machinery at all.
- `git clone` is self-sufficient.
- Worktrees behave correctly.

Cons:
- ethereum/tests is ~600 MB of fixtures + ~150 MB of LegacyTests.
  Inflates bsvm clone size dramatically.
- Updates to ethereum/tests now require manual re-vendor.
- Re-introduces "we have a copy of someone else's code" risk
  (LICENSE compliance — ethereum/tests is MIT, so legally fine, but
  still noisy for diffing bsvm changes).

Not recommended unless the project chooses to pin a specific
fixture set forever.

### Option C — Commit the current state (do nothing)

Keep the gitlink, keep no `.gitmodules`. Operators rsync / manually
clone ethereum/tests into the directory. The "modified content"
warning persists in `git status`.

Pros:
- Zero work.

Cons:
- Confuses every fresh contributor.
- `git submodule` commands stay broken.
- Worktrees never get fixtures (this worktree doesn't have them).
- The drift report in this folder lists this submodule among the
  "long-standing repository hygiene issues."

Not recommended.

### Option D — Delete the gitlink

Remove the directory and the gitlink entirely. Move the EVM-test
fixture path into env var `BSVM_ETHEREUM_TESTS_DIR` that points at a
local clone the operator manages.

Pros:
- Cleanest separation: bsvm doesn't ship test fixtures.
- Operators control which fixture revision they test against.

Cons:
- CI now needs to clone ethereum/tests separately (fine, just a
  workflow line).
- Loses the per-commit pinning of "which fixtures we expect to
  pass". With this option, an `ethereum/tests` upstream change can
  silently break bsvm's CI without any bsvm-level commit.

Tradeoff: gives flexibility, loses reproducibility. Not the right
move for a project whose CLAUDE.md says "ethereum/tests is the
ultimate correctness oracle" — that demands a pinned fixture set.

## Recommendation: **Option A (re-register)**

Cleanest fix, keeps the existing pinning, costs ~5 lines of YAML and
one `.gitmodules` commit. The nested `LegacyTests` submodule is
handled via `--recursive` (which the project should standardize on
anyway, since this is a recursive-submodule pattern).

Concrete action items (for whoever does the fix — NOT taken in this
investigation):

1. Add `.gitmodules` at the repo root with the entry shown in
   Option A.
2. Verify `git submodule status` reports the gitlink cleanly.
3. Update `.github/workflows/go-test.yml` to checkout with
   `submodules: recursive`.
4. Document in `README.md` that `git clone` should use
   `--recurse-submodules`.
5. Consider `--depth 1` for the ethereum/tests clone on CI if
   bandwidth becomes an issue.

## Action taken in THIS commit

**None.** This is a documentation-only investigation. No `.gitmodules`
was created; no gitlink was modified; no testdata was deleted. The
worktree state is identical before and after this commit, except for
this decision document.

The dirty `m test/evmtest/testdata` line in `git status` is a
red-herring (per Evidence section 5) and can stay until Option A is
executed.
