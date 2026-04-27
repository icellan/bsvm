#!/usr/bin/env bash
# =============================================================================
# boot-testnet.sh — preflight + start a BSVM testnet node
# =============================================================================
#
# Usage:
#   ./boot-testnet.sh                          # uses defaults
#   BSVM_DATADIR=/srv/bsvm BSVM_BIN=./build/bsvm ./boot-testnet.sh
#   ./boot-testnet.sh --skip-chaintracks-check # skip network preflight
#
# The script:
#   1. Validates the toolchain (Go 1.22+, optional Rust for SP1, bsvm binary).
#   2. Validates the config TOML parses.
#   3. Ensures data + keys directories exist with the right perms.
#   4. Optionally probes the configured chaintracks provider for liveness.
#   5. Execs `bsvm run --config <toml> --datadir <dir>` so SIGINT/SIGTERM
#      reaches the daemon directly (no PID wrapping; clean shutdown).
#
# Idempotent: safe to re-run after Ctrl-C unless chaindata is corrupted.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Config (env-overridable). All paths are absolute or repo-relative; nothing
# is hardcoded into /Users/.. so the script works in CI containers too.
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BSVM_BIN="${BSVM_BIN:-${REPO_ROOT}/build/bsvm}"
BSVM_CONFIG="${BSVM_CONFIG:-${SCRIPT_DIR}/bsvm.testnet.toml}"
BSVM_DATADIR="${BSVM_DATADIR:-${REPO_ROOT}/data/testnet}"
BSVM_KEYSDIR="${BSVM_KEYSDIR:-${REPO_ROOT}/keys/testnet}"

# Optional: a genesis txid to bootstrap from (Phase 8 path). When set, the
# daemon derives the entire shard config from BSV — no shard.json needed.
# When empty, the legacy path expects ${BSVM_DATADIR}/shard.json.
BSVM_GENESIS_TXID="${BSVM_GENESIS_TXID:-}"
export BSVM_GENESIS_TXID

# Optional: pre-fetched genesis raw tx hex (lets followers boot without BSV RPC).
BSVM_GENESIS_TX_FILE="${BSVM_GENESIS_TX_FILE:-}"
export BSVM_GENESIS_TX_FILE

# Optional: BSVM_NODE_ROLE=follower skips fee-wallet + BSV-RPC requirements.
BSVM_NODE_ROLE="${BSVM_NODE_ROLE:-}"
export BSVM_NODE_ROLE

SKIP_CHAINTRACKS_CHECK=0
for arg in "$@"; do
    case "${arg}" in
        --skip-chaintracks-check) SKIP_CHAINTRACKS_CHECK=1 ;;
        --help|-h)
            grep -E '^# ' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
    esac
done

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()  { printf '[boot-testnet] %s\n' "$*" >&2; }
fail() { printf '[boot-testnet] FATAL: %s\n' "$*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

# -----------------------------------------------------------------------------
# Step 1 — toolchain preflight
# -----------------------------------------------------------------------------
log "preflight: toolchain"

require_cmd go

# Go 1.22 minimum (matches go.mod). Compare major.minor numerically.
GO_VERSION="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
if [[ -z "${GO_VERSION}" ]]; then
    fail "could not determine Go version"
fi
GO_MAJOR="${GO_VERSION%%.*}"
GO_MINOR="$(printf '%s' "${GO_VERSION}" | awk -F. '{print $2}')"
if (( GO_MAJOR < 1 )) || { (( GO_MAJOR == 1 )) && (( GO_MINOR < 22 )); }; then
    fail "Go ${GO_VERSION} is too old (need 1.22+); update via your toolchain manager"
fi
log "  Go ${GO_VERSION} OK"

# Rust is only required if [prover].mode = local|network. We don't parse the
# TOML here (would need a TOML parser dep); just warn if cargo is missing
# AND the operator hasn't disabled prove mode via BSVM_PROVE_MODE=mock.
if ! command -v cargo >/dev/null 2>&1; then
    if [[ "${BSVM_PROVE_MODE:-}" != "mock" ]]; then
        log "  WARN: cargo not on PATH; SP1 'local' prover will fail. Install Rust or set BSVM_PROVE_MODE=mock."
    fi
else
    log "  cargo $(cargo --version 2>/dev/null | awk '{print $2}') OK"
fi

# -----------------------------------------------------------------------------
# Step 2 — daemon binary
# -----------------------------------------------------------------------------
log "preflight: daemon binary at ${BSVM_BIN}"

if [[ ! -x "${BSVM_BIN}" ]]; then
    log "  ${BSVM_BIN} missing or not executable; building..."
    mkdir -p "$(dirname "${BSVM_BIN}")"
    (
        cd "${REPO_ROOT}"
        go build -o "${BSVM_BIN}" ./cmd/bsvm
    ) || fail "go build ./cmd/bsvm failed"
fi
log "  $("${BSVM_BIN}" version 2>&1 | head -n1) OK"

# -----------------------------------------------------------------------------
# Step 3 — config file
# -----------------------------------------------------------------------------
log "preflight: config file at ${BSVM_CONFIG}"

[[ -f "${BSVM_CONFIG}" ]] || fail "config not found: ${BSVM_CONFIG}"

# Best-effort TOML parse via python3 if available; non-fatal otherwise
# (the daemon will fail with a parser error on its own).
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import tomllib,sys; tomllib.loads(open(sys.argv[1]).read())" "${BSVM_CONFIG}" >/dev/null 2>&1; then
        fail "config does not parse as TOML: ${BSVM_CONFIG}"
    fi
fi
log "  config parses OK"

# -----------------------------------------------------------------------------
# Step 4 — data + keys directories
# -----------------------------------------------------------------------------
log "preflight: data dir ${BSVM_DATADIR}"
mkdir -p "${BSVM_DATADIR}"
if [[ ! -w "${BSVM_DATADIR}" ]]; then
    fail "data dir not writable: ${BSVM_DATADIR}"
fi
log "  data dir OK"

log "preflight: keys dir ${BSVM_KEYSDIR}"
mkdir -p "${BSVM_KEYSDIR}"
chmod 700 "${BSVM_KEYSDIR}"
log "  keys dir OK (mode 700)"

# Followers don't need a fee wallet on disk before boot — the daemon will
# auto-create one inside ${BSVM_DATADIR} on first run for prover nodes.
# We only check that any pre-placed governance.wif has tight perms.
if [[ -f "${BSVM_KEYSDIR}/governance.wif" ]]; then
    perm="$(stat -f '%Lp' "${BSVM_KEYSDIR}/governance.wif" 2>/dev/null || stat -c '%a' "${BSVM_KEYSDIR}/governance.wif" 2>/dev/null || echo "?")"
    if [[ "${perm}" != "600" ]]; then
        log "  WARN: ${BSVM_KEYSDIR}/governance.wif is mode ${perm}; tightening to 600"
        chmod 600 "${BSVM_KEYSDIR}/governance.wif"
    fi
fi

# -----------------------------------------------------------------------------
# Step 5 — chaintracks reachability (best effort, skippable)
# -----------------------------------------------------------------------------
if (( SKIP_CHAINTRACKS_CHECK == 0 )) && command -v curl >/dev/null 2>&1; then
    # Pull the first chaintracks provider URL out of the TOML with grep.
    # We deliberately avoid a TOML parser dep — this is preflight only,
    # and the daemon does its own chaintracks handshake at startup.
    CT_URL="$(awk '
        /^\[\[bsv\.chaintracks\.providers\]\]/ { in_block=1; next }
        in_block && /^url[[:space:]]*=/ {
            sub(/^url[[:space:]]*=[[:space:]]*"/, "")
            sub(/".*$/, "")
            print
            exit
        }
        in_block && /^\[/ { in_block=0 }
    ' "${BSVM_CONFIG}")"
    if [[ -n "${CT_URL}" && "${CT_URL}" != *"example"* ]]; then
        log "preflight: probing chaintracks ${CT_URL}"
        if curl --silent --fail --max-time 5 --output /dev/null --head "${CT_URL}" 2>/dev/null; then
            log "  chaintracks reachable"
        else
            log "  WARN: chaintracks ${CT_URL} not reachable; daemon will fail closed on bridge deposits"
        fi
    else
        log "  skipping chaintracks probe (placeholder URL still in config)"
    fi
fi

# -----------------------------------------------------------------------------
# Step 6 — exec daemon
# -----------------------------------------------------------------------------
log "starting bsvm run"
log "  config:  ${BSVM_CONFIG}"
log "  datadir: ${BSVM_DATADIR}"
[[ -n "${BSVM_GENESIS_TXID}" ]] && log "  genesis-txid: ${BSVM_GENESIS_TXID}"
[[ -n "${BSVM_NODE_ROLE}" ]]    && log "  role: ${BSVM_NODE_ROLE}"

# `exec` replaces this shell so SIGINT/SIGTERM go straight to bsvm. The
# daemon installs its own signal handlers for graceful shutdown
# (cmd/bsvm/main.go: signal.Notify on SIGINT, SIGTERM with a 30s drain).
exec "${BSVM_BIN}" run \
    --config  "${BSVM_CONFIG}" \
    --datadir "${BSVM_DATADIR}"
