#!/usr/bin/env bash
# deploy/covenant/deploy.sh — operator wrapper for compiling and
# broadcasting a fresh BSVM shard's bridge + rollup covenant pair.
#
# Workflow:
#   1. Pre-flight: confirm Go is installed, deployer key file exists,
#      ARC endpoint reachable, VK hash file readable.
#   2. Dry-run: build + run the deploy binary with --dry-run, dump the
#      JSON summary, ask the operator to confirm.
#   3. Broadcast: re-run with --broadcast, capture txid, write summary
#      to deploy/covenant/.last-deploy.json for the next-step audit.
#
# All paths are repo-relative when invoked from the project root, but
# the script `cd`s to the repo root first so it works from any cwd.
#
# Env overrides:
#   DEPLOY_CONFIG    path to operator config JSON (default: deploy/covenant/operator.json)
#   DEPLOY_OUT       path for the JSON summary    (default: deploy/covenant/.last-deploy.json)
#   DEPLOY_BIN       path to the built binary     (default: build/deploy-covenant)
#   DEPLOY_NO_BUILD  set to skip the go build step
#   DEPLOY_NO_CONFIRM set to skip the interactive confirmation prompt
set -euo pipefail

# Resolve repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

DEPLOY_CONFIG="${DEPLOY_CONFIG:-deploy/covenant/operator.json}"
DEPLOY_OUT="${DEPLOY_OUT:-deploy/covenant/.last-deploy.json}"
DEPLOY_BIN="${DEPLOY_BIN:-build/deploy-covenant}"

log() { printf '[deploy-covenant] %s\n' "$*" >&2; }
die() { printf '[deploy-covenant][FAIL] %s\n' "$*" >&2; exit 1; }

# 1. Pre-flight.
log "preflight: toolchain"
command -v go >/dev/null 2>&1 || die "Go is not on PATH"
go_version="$(go version | awk '{print $3}')"
log "  $go_version OK"

log "preflight: config $DEPLOY_CONFIG"
[[ -r "$DEPLOY_CONFIG" ]] || die "config $DEPLOY_CONFIG missing or unreadable"

# Use python's json module to fish out the deployerKeyFile + arcEndpoint
# without bringing in jq. python3 ships on macOS / linux defaults.
deployer_key_file=$(python3 -c '
import json, sys
with open("'"$DEPLOY_CONFIG"'") as f:
    cfg = json.load(f)
print(cfg.get("deployerKeyFile") or "")
')
arc_endpoint=$(python3 -c '
import json, sys
with open("'"$DEPLOY_CONFIG"'") as f:
    cfg = json.load(f)
print(cfg.get("arcEndpoint") or "")
')

if [[ -n "$deployer_key_file" && ! -r "$deployer_key_file" ]]; then
  die "deployerKeyFile $deployer_key_file missing or unreadable"
fi
log "  config parses OK"
log "  deployerKeyFile = ${deployer_key_file:-<not set>}"
log "  arcEndpoint     = ${arc_endpoint:-<not set>}"

# 2. Build the binary.
if [[ -z "${DEPLOY_NO_BUILD:-}" ]]; then
  log "build: $DEPLOY_BIN"
  mkdir -p "$(dirname "$DEPLOY_BIN")"
  go build -o "$DEPLOY_BIN" ./deploy/covenant/cmd/deploy
fi
[[ -x "$DEPLOY_BIN" ]] || die "$DEPLOY_BIN not built"

# 3. Dry-run first.
log "dry-run: invoking $DEPLOY_BIN --dry-run"
"$DEPLOY_BIN" --config "$DEPLOY_CONFIG" --dry-run --out "$DEPLOY_OUT" || \
  die "dry-run failed; inspect the binary's stderr"
log "dry-run summary written to $DEPLOY_OUT"
log "dry-run summary:"
cat "$DEPLOY_OUT" >&2

# 4. Confirmation.
if [[ -z "${DEPLOY_NO_CONFIRM:-}" ]]; then
  printf 'Broadcast the genesis tx now? [y/N] ' >&2
  read -r reply || reply=""
  case "$reply" in
    [yY]*) ;;
    *) log "aborted by operator (re-run with DEPLOY_NO_CONFIRM=1 to skip)"; exit 0 ;;
  esac
fi

# 5. Broadcast.
[[ -n "$arc_endpoint" ]] || die "arcEndpoint missing in config; cannot --broadcast"
log "broadcast: invoking $DEPLOY_BIN --broadcast"
"$DEPLOY_BIN" --config "$DEPLOY_CONFIG" --broadcast --out "$DEPLOY_OUT" || \
  die "broadcast failed; inspect the binary's stderr"
log "broadcast summary written to $DEPLOY_OUT"
cat "$DEPLOY_OUT" >&2
log "DONE"
