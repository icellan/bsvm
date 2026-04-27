#!/usr/bin/env bash
# =============================================================================
# verify-testnet.sh — smoke-test a running BSVM testnet node
# =============================================================================
#
# Run AFTER boot-testnet.sh is up. Exercises the JSON-RPC + BEEF surfaces
# end-to-end:
#
#   1. Polls eth_blockNumber until the chain has advanced past genesis.
#   2. Submits a sample BEEF deposit envelope to /bsvm/bridge/deposit.
#      [REQUIRES: real BEEF envelope] — the script ships with a minimal
#      placeholder body that is shape-valid but ancestry-invalid; on a
#      properly configured node (real chaintracks + real bridge_script_hex)
#      this will be rejected by the BEEF verifier with HTTP 4xx, which is
#      exactly the right behaviour. To exercise the credit path replace
#      $BEEF_ENVELOPE_HEX_FILE with a real, ancestry-verifiable envelope
#      from your testnet wallet (BRC-62 BUMP + bridge tx).
#   3. Polls eth_getBalance for the depositor address.
#   4. Submits a signed L2 transfer via eth_sendRawTransaction.
#      Tx generation requires `cast` (Foundry) on PATH; if absent the step
#      is skipped with a warning.
#   5. Polls eth_getTransactionReceipt until status = 0x1 (or fail).
#
# Reports PASS/FAIL with detail on stderr; exits non-zero on any FAIL.
#
# Usage:
#   ./verify-testnet.sh                                   # uses defaults
#   BSVM_RPC=http://localhost:8545 ./verify-testnet.sh
#   BSVM_DEPOSIT_RECIPIENT=0xdead... ./verify-testnet.sh
#   BSVM_TEST_KEY=0x<32 byte hex> ./verify-testnet.sh     # signing key for step 4
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BSVM_RPC="${BSVM_RPC:-http://127.0.0.1:8545}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
POLL_INTERVAL="${POLL_INTERVAL:-2}"

# A throwaway recipient address for the bridge deposit step. Default is a
# stable test-only address documented in the README. The depositor's balance
# is checked AFTER the bridge mint; on a node with bridge_script_hex unset
# this stays zero (fail-closed) and the check is logged but does not abort.
BSVM_DEPOSIT_RECIPIENT="${BSVM_DEPOSIT_RECIPIENT:-0xD0E057051000000000000000000000000000DEAD}"

# Path to a hex-encoded BEEF envelope to POST to /bsvm/bridge/deposit.
# When unset, the script generates a syntactically-valid placeholder that
# the BEEF verifier will reject. See [REQUIRES] note above.
BEEF_ENVELOPE_HEX_FILE="${BEEF_ENVELOPE_HEX_FILE:-}"

# A funded testnet test key (32-byte hex, 0x-prefixed). When set, step 4
# signs and broadcasts a transfer with `cast` and asserts the receipt.
# When empty, step 4 prints a [SKIPPED] notice and the script still
# passes if steps 1-3 succeed.
BSVM_TEST_KEY="${BSVM_TEST_KEY:-}"
BSVM_TEST_RECIPIENT="${BSVM_TEST_RECIPIENT:-0x000000000000000000000000000000000000C0DE}"

REQUIRE_CMDS=(curl)
for c in "${REQUIRE_CMDS[@]}"; do
    command -v "${c}" >/dev/null 2>&1 || { echo "FATAL: missing required command: ${c}" >&2; exit 2; }
done

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()  { printf '[verify-testnet] %s\n' "$*" >&2; }
pass() { printf '[verify-testnet] PASS: %s\n' "$*" >&2; }
fail() { printf '[verify-testnet] FAIL: %s\n' "$*" >&2; FAILED=1; }

FAILED=0

# rpc_call <method> <params-json>
# Echoes the JSON-RPC `result` field (or `error.message` prefixed with ERR:).
rpc_call() {
    local method="$1"; shift
    local params="$1"; shift
    local body
    body=$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "${method}" "${params}")
    local resp
    resp=$(curl --silent --fail --show-error \
              --max-time 10 \
              -H 'content-type: application/json' \
              -d "${body}" \
              "${BSVM_RPC}" 2>&1) || {
        echo "ERR:transport: ${resp}"
        return 1
    }
    # Cheap JSON extraction: strip whitespace + extract result/error using
    # POSIX sed. Good enough for hex-string + small object responses.
    local err
    err=$(printf '%s' "${resp}" | sed -n 's/.*"error":[[:space:]]*{[^}]*"message":[[:space:]]*"\([^"]*\)".*/\1/p')
    if [[ -n "${err}" ]]; then
        echo "ERR:rpc: ${err}"
        return 1
    fi
    printf '%s' "${resp}" | sed -n 's/.*"result":[[:space:]]*"\([^"]*\)".*/\1/p; s/.*"result":[[:space:]]*\(true\|false\|null\).*/\1/p'
}

hex_to_dec() {
    # Strip 0x and convert. Avoids printf %d which trips on long hex.
    local h="${1#0x}"
    [[ -z "${h}" || "${h}" == "0" ]] && { echo 0; return; }
    # python3 if present, else awk fallback (handles up to 64-bit values).
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys; print(int(sys.argv[1], 16))" "${h}"
    else
        # awk -nvh works on values fitting in a double (≈2^53). Fine for
        # block numbers + small balances; not for full 256-bit balances.
        awk -v hex="${h}" 'BEGIN { printf "%d\n", strtonum("0x"hex) }'
    fi
}

# -----------------------------------------------------------------------------
# Step 0 — RPC reachable
# -----------------------------------------------------------------------------
log "step 0: probing ${BSVM_RPC}"
if ! curl --silent --fail --max-time 5 \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}' \
        "${BSVM_RPC}" >/dev/null; then
    fail "JSON-RPC at ${BSVM_RPC} is unreachable"
    exit 1
fi
pass "JSON-RPC reachable"

# -----------------------------------------------------------------------------
# Step 1 — chain advancing (eth_blockNumber > 0 within timeout)
# -----------------------------------------------------------------------------
log "step 1: polling eth_blockNumber for chain advance (timeout ${TIMEOUT_SECONDS}s)"
deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
last_bn="0x0"
while (( $(date +%s) < deadline )); do
    last_bn=$(rpc_call "eth_blockNumber" '[]' || echo "0x0")
    if [[ "${last_bn}" =~ ^0x[1-9a-fA-F] || "${last_bn}" =~ ^0x[0-9a-fA-F]{2,} ]]; then
        if [[ "$(hex_to_dec "${last_bn}")" -gt 0 ]]; then
            break
        fi
    fi
    sleep "${POLL_INTERVAL}"
done
last_bn_dec="$(hex_to_dec "${last_bn}")"
if (( last_bn_dec > 0 )); then
    pass "chain advanced to block ${last_bn_dec} (${last_bn})"
else
    fail "chain stayed at block 0 after ${TIMEOUT_SECONDS}s — check the daemon log for batcher errors"
fi

# -----------------------------------------------------------------------------
# Step 2 — submit BEEF deposit envelope
# -----------------------------------------------------------------------------
log "step 2: POST /bsvm/bridge/deposit"
DEPOSIT_URL="${BSVM_RPC%/}/bsvm/bridge/deposit"

if [[ -n "${BEEF_ENVELOPE_HEX_FILE}" ]]; then
    if [[ ! -f "${BEEF_ENVELOPE_HEX_FILE}" ]]; then
        fail "BEEF_ENVELOPE_HEX_FILE not found: ${BEEF_ENVELOPE_HEX_FILE}"
    else
        log "  using real BEEF envelope from ${BEEF_ENVELOPE_HEX_FILE}"
        if command -v xxd >/dev/null 2>&1; then
            tmpbin="$(mktemp)"
            xxd -r -p "${BEEF_ENVELOPE_HEX_FILE}" > "${tmpbin}"
            http_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
                              --max-time 10 \
                              -H 'content-type: application/octet-stream' \
                              --data-binary "@${tmpbin}" \
                              "${DEPOSIT_URL}" || echo "000")"
            rm -f "${tmpbin}"
        else
            fail "xxd not available for hex→bin conversion; install vim/xxd or supply pre-binary envelope"
            http_code="000"
        fi
        if [[ "${http_code}" == "204" || "${http_code}" == "200" ]]; then
            pass "BEEF deposit accepted (${http_code})"
        else
            fail "BEEF deposit POST returned HTTP ${http_code} (expected 204 on accept)"
        fi
    fi
else
    log "  [REQUIRES: real BEEF envelope] — using shape-valid placeholder; expect 4xx from verifier"
    # Build the minimal envelope that the route handler can parse:
    # - 8-byte BEEF envelope header (version=1, intent=bridge_deposit=1,
    #   flags=ShardBound=1, shard_id=little-endian uint32 from config)
    # - inner BEEF body: V1 magic 0xEFBE0001 + 0 BUMPs + 1 minimal tx
    # We don't bother computing the full inner tx hash — the daemon
    # rejects this in the verifier, which is exactly what we want to
    # observe on a properly secured node.
    SHARD_ID_LE="$(printf '%08x' 8453111 | tac -rs ..)"  # tac fallback below
    # tac/rs not portable on macOS; use printf-loop:
    SHARD_ID_HEX="$(printf '%08x' 8453111)"
    SHARD_ID_LE=""
    for ((i=${#SHARD_ID_HEX}-2; i>=0; i-=2)); do
        SHARD_ID_LE+="${SHARD_ID_HEX:$i:2}"
    done
    # 01 = version, 01 = intent(bridge_deposit), 01 = flags(ShardBound),
    # then 4-byte LE shard ID, then inner body.
    INNER_HEX="0100bef00100010001000000000000"
    PLACEHOLDER_HEX="010101${SHARD_ID_LE}${INNER_HEX}"
    if command -v xxd >/dev/null 2>&1; then
        tmpbin="$(mktemp)"
        printf '%s' "${PLACEHOLDER_HEX}" | xxd -r -p > "${tmpbin}"
        http_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
                          --max-time 10 \
                          -H 'content-type: application/octet-stream' \
                          --data-binary "@${tmpbin}" \
                          "${DEPOSIT_URL}" || echo "000")"
        rm -f "${tmpbin}"
        case "${http_code}" in
            204|200) log "  placeholder accepted (HTTP ${http_code}) — node likely has accept_unverified_bridge_deposits=true" ;;
            400|409|422) pass "placeholder rejected (HTTP ${http_code}) — verifier is fail-closed as expected on testnet" ;;
            *) fail "unexpected HTTP ${http_code} from ${DEPOSIT_URL}" ;;
        esac
    else
        log "  SKIPPED (xxd not available)"
    fi
fi

# -----------------------------------------------------------------------------
# Step 3 — depositor balance
# -----------------------------------------------------------------------------
log "step 3: eth_getBalance ${BSVM_DEPOSIT_RECIPIENT}"
bal_hex="$(rpc_call "eth_getBalance" "[\"${BSVM_DEPOSIT_RECIPIENT}\",\"latest\"]" || echo "0x0")"
if [[ "${bal_hex}" =~ ^ERR ]]; then
    fail "eth_getBalance failed: ${bal_hex}"
elif [[ "${bal_hex}" == "0x0" ]]; then
    log "  balance is 0x0 (expected when no real BEEF envelope was supplied)"
    pass "eth_getBalance succeeded (zero balance — fail-closed)"
else
    pass "depositor balance = ${bal_hex}"
fi

# -----------------------------------------------------------------------------
# Step 4 — signed L2 transfer
# -----------------------------------------------------------------------------
log "step 4: eth_sendRawTransaction"
if [[ -z "${BSVM_TEST_KEY}" ]]; then
    log "  [SKIPPED] BSVM_TEST_KEY not set — cannot sign a tx without a key"
elif ! command -v cast >/dev/null 2>&1; then
    log "  [SKIPPED] foundry 'cast' not on PATH — install Foundry or pre-sign and feed via BSVM_RAW_TX"
else
    chain_id_hex="$(rpc_call "eth_chainId" '[]' || echo "0x0")"
    chain_id_dec="$(hex_to_dec "${chain_id_hex}")"
    log "  chain id ${chain_id_dec}"
    sender="$(cast wallet address --private-key "${BSVM_TEST_KEY}" 2>/dev/null || true)"
    if [[ -z "${sender}" ]]; then
        fail "cast wallet address failed — check BSVM_TEST_KEY format (must be 32-byte hex)"
    else
        log "  sender ${sender}"
        # Use eth_getTransactionCount to set nonce, then sign + send.
        nonce_hex="$(rpc_call "eth_getTransactionCount" "[\"${sender}\",\"latest\"]" || echo "0x0")"
        nonce_dec="$(hex_to_dec "${nonce_hex}")"
        log "  nonce ${nonce_dec}"
        raw="$(cast mktx --rpc-url "${BSVM_RPC}" \
                          --private-key "${BSVM_TEST_KEY}" \
                          --chain "${chain_id_dec}" \
                          --nonce "${nonce_dec}" \
                          --gas-limit 21000 \
                          --priority-gas-price 1gwei \
                          --gas-price 2gwei \
                          --value 0 \
                          "${BSVM_TEST_RECIPIENT}" 2>/dev/null || true)"
        if [[ -z "${raw}" ]]; then
            fail "cast mktx returned empty — check that the sender has gas balance"
        else
            txhash="$(rpc_call "eth_sendRawTransaction" "[\"${raw}\"]" || echo "")"
            if [[ -z "${txhash}" || "${txhash}" =~ ^ERR ]]; then
                fail "eth_sendRawTransaction failed: ${txhash}"
            else
                pass "tx submitted: ${txhash}"

                # -----------------------------------------------------------
                # Step 5 — receipt status = 0x1
                # -----------------------------------------------------------
                log "step 5: poll eth_getTransactionReceipt ${txhash}"
                rcpt_deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
                status=""
                while (( $(date +%s) < rcpt_deadline )); do
                    rcpt="$(curl --silent --max-time 10 \
                              -H 'content-type: application/json' \
                              -d "$(printf '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["%s"]}' "${txhash}")" \
                              "${BSVM_RPC}" 2>/dev/null || true)"
                    status="$(printf '%s' "${rcpt}" | sed -n 's/.*"status":[[:space:]]*"\(0x[01]\)".*/\1/p')"
                    [[ -n "${status}" ]] && break
                    sleep "${POLL_INTERVAL}"
                done
                case "${status}" in
                    0x1) pass "receipt status=0x1 (success)" ;;
                    0x0) fail "receipt status=0x0 (reverted)" ;;
                    "")  fail "no receipt within ${TIMEOUT_SECONDS}s" ;;
                esac
            fi
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo
if (( FAILED == 0 )); then
    pass "all checks passed"
    exit 0
else
    fail "one or more checks failed"
    exit 1
fi
