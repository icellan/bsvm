#!/bin/bash
# Build the bsvm Docker image tagged for both the developer devnet and the
# Go test harness. Keeping one build in one place prevents drift between
# the two composes (docker-compose.yml at repo root, and
# test/multinode/docker/docker-compose.yml).
#
# Must run from any directory under the repo — the script resolves the
# parent of bsv-evm/ so the go.mod `replace => ../runar/...` directives
# remain valid inside the Docker build context.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARENT_DIR="$(cd "$REPO_ROOT/.." && pwd)"

# Build the React SPA first so //go:embed picks up fresh assets. The
# Go build inside Docker pulls pkg/webui/dist/ from the build context,
# so an out-of-date SPA on the host would ship to users. When
# SKIP_WEB_BUILD is set (CI that already built) we trust the caller.
if [[ -z "${SKIP_WEB_BUILD:-}" && -f "$REPO_ROOT/web/package.json" ]]; then
  if command -v npm >/dev/null; then
    echo "Building React SPA into pkg/webui/dist..."
    ( cd "$REPO_ROOT/web" && npm ci --prefer-offline --no-audit --no-fund >/dev/null 2>&1 || npm install --no-audit --no-fund >/dev/null )
    ( cd "$REPO_ROOT/web" && npm run build )
  else
    echo "WARNING: npm not found on PATH — using whatever pkg/webui/dist already contains."
  fi
fi

echo "Building bsvm image from context: $PARENT_DIR"
docker build \
  -f "$REPO_ROOT/Dockerfile" \
  -t bsvm:devnet \
  -t bsvm:test \
  -t bsvm:latest \
  "$PARENT_DIR"

echo
echo "Built: bsvm:devnet, bsvm:test, bsvm:latest"
docker image inspect bsvm:devnet --format 'size={{.Size}} created={{.Created}}' || true
