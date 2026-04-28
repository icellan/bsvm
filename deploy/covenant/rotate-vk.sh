#!/usr/bin/env bash
# deploy/covenant/rotate-vk.sh — operator wrapper for the SP1
# verifying-key rotation procedure.
#
# Workflow:
#   1. Pre-flight: confirm Go installed, rotation config readable,
#      NEW VK hash file present, OLD VK hash file present (optional).
#   2. Dry-run: build + run rotate-vk binary --dry-run, dump JSON
#      summary (NEW + OLD locking-script hex side-by-side), ask the
#      operator to confirm.
#   3. Broadcast: --broadcast (requires governanceSigsHex in config).
#
# Env overrides:
#   ROTATE_CONFIG     path to rotate-vk config JSON   (default: deploy/covenant/rotation.json)
#   ROTATE_OUT        path for the JSON summary       (default: deploy/covenant/.last-rotation.json)
#   ROTATE_OLD_VK     path to OLD SP1VerifyingKeyHash (default: empty — no diff)
#   ROTATE_BIN        path to built binary            (default: build/rotate-vk)
#   ROTATE_NO_BUILD   set to skip the go build step
#   ROTATE_NO_CONFIRM set to skip the interactive prompt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

ROTATE_CONFIG="${ROTATE_CONFIG:-deploy/covenant/rotation.json}"
ROTATE_OUT="${ROTATE_OUT:-deploy/covenant/.last-rotation.json}"
ROTATE_OLD_VK="${ROTATE_OLD_VK:-}"
ROTATE_BIN="${ROTATE_BIN:-build/rotate-vk}"

log() { printf '[rotate-vk] %s\n' "$*" >&2; }
die() { printf '[rotate-vk][FAIL] %s\n' "$*" >&2; exit 1; }

# 1. Pre-flight.
log "preflight: toolchain"
command -v go >/dev/null 2>&1 || die "Go is not on PATH"
log "  $(go version | awk '{print $3}') OK"

log "preflight: config $ROTATE_CONFIG"
[[ -r "$ROTATE_CONFIG" ]] || die "config $ROTATE_CONFIG missing or unreadable"

new_vk_file=$(python3 -c '
import json
with open("'"$ROTATE_CONFIG"'") as f:
    cfg = json.load(f)
print(cfg.get("newVKHashFile") or "")
')
if [[ -z "$new_vk_file" ]]; then
  new_vk_file="prover/guest/elf/SP1VerifyingKeyHash.txt"
fi
[[ -r "$new_vk_file" ]] || die "newVKHashFile $new_vk_file missing or unreadable"
log "  newVKHashFile = $new_vk_file"

if [[ -n "$ROTATE_OLD_VK" ]]; then
  [[ -r "$ROTATE_OLD_VK" ]] || die "ROTATE_OLD_VK $ROTATE_OLD_VK missing or unreadable"
  log "  ROTATE_OLD_VK = $ROTATE_OLD_VK"
fi

# 2. Build.
if [[ -z "${ROTATE_NO_BUILD:-}" ]]; then
  log "build: $ROTATE_BIN"
  mkdir -p "$(dirname "$ROTATE_BIN")"
  go build -o "$ROTATE_BIN" ./deploy/covenant/cmd/rotate-vk
fi
[[ -x "$ROTATE_BIN" ]] || die "$ROTATE_BIN not built"

# 3. Dry-run.
log "dry-run: invoking $ROTATE_BIN --dry-run"
old_vk_arg=()
if [[ -n "$ROTATE_OLD_VK" ]]; then
  old_vk_arg=(--old-vk-hash-file "$ROTATE_OLD_VK")
fi
"$ROTATE_BIN" --config "$ROTATE_CONFIG" --dry-run --out "$ROTATE_OUT" "${old_vk_arg[@]}" || \
  die "dry-run failed"
log "dry-run summary written to $ROTATE_OUT"
log "dry-run summary:"
cat "$ROTATE_OUT" >&2

# 4. Confirmation.
if [[ -z "${ROTATE_NO_CONFIRM:-}" ]]; then
  cat >&2 <<EOF

ATTENTION — VK rotation impact:
  * Every per-shard genesis manifest's sp1_verifying_key_hash MUST be
    repinned to the NEW value displayed above. Old proofs WILL NOT
    verify against the new covenant; queue a drain of pending advances
    BEFORE broadcasting the upgrade.
  * The bridge covenant's StateCovenantScriptHash readonly pins to the
    OLD rollup script. After the rotation lands, you MUST also redeploy
    the bridge with the NEW StateCovenantScriptHash. Pending withdrawal
    proofs constructed against the OLD bridge will be invalid.
  * If governance is multisig, all M signatures MUST be present in
    governanceSigsHex before --broadcast will succeed.

EOF
  printf 'Proceed with broadcast? [y/N] ' >&2
  read -r reply || reply=""
  case "$reply" in
    [yY]*) ;;
    *) log "aborted by operator"; exit 0 ;;
  esac
fi

# 5. Broadcast.
log "broadcast: invoking $ROTATE_BIN --broadcast"
"$ROTATE_BIN" --config "$ROTATE_CONFIG" --broadcast --out "$ROTATE_OUT" "${old_vk_arg[@]}" || \
  die "broadcast failed"
log "broadcast summary written to $ROTATE_OUT"
cat "$ROTATE_OUT" >&2
log "DONE — REMINDER: redeploy the bridge under the NEW StateCovenantScriptHash next."
