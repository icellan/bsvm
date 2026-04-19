#!/bin/bash
# Build the bsvm:test Docker image.
# Runs from the parent directory (containing bsv-evm/ and runar/) so that
# go.mod replace directives resolve inside the Docker build context.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PARENT_DIR="$(cd "$REPO_ROOT/.." && pwd)"

echo "Building bsvm:test from context: $PARENT_DIR"
docker build -f "$REPO_ROOT/Dockerfile" -t bsvm:test "$PARENT_DIR"
