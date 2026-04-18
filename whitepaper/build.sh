#!/usr/bin/env bash
set -euo pipefail

# Build the BSVM whitepaper + security-model PDFs from LaTeX source.
#
# Usage: ./whitepaper/build.sh [tex-stem...]
#
# With no arguments, builds all default documents. With arguments, builds
# only the named stems (e.g. `./build.sh bsvm-whitepaper`).
#
# Requires a LaTeX distribution. Install options:
#   macOS:   brew install --cask mactex-no-gui   (or: brew install tectonic)
#   Ubuntu:  sudo apt install texlive-full
#   Minimal: cargo install tectonic

cd "$(dirname "$0")"

DEFAULT_STEMS=(bsvm-whitepaper bsvm-security-model)

if [[ $# -gt 0 ]]; then
    STEMS=("$@")
else
    STEMS=("${DEFAULT_STEMS[@]}")
fi

# Pick an engine once. We look up all three and prefer latexmk > tectonic
# > pdflatex. Each document is built in its own engine invocation so a
# failure in one does not skip cleanup for the other.
ENGINE=""
if command -v latexmk &>/dev/null; then
    ENGINE=latexmk
elif command -v tectonic &>/dev/null; then
    ENGINE=tectonic
elif command -v pdflatex &>/dev/null; then
    ENGINE=pdflatex
else
    echo "Error: No LaTeX engine found." >&2
    echo "Install one of:" >&2
    echo "  brew install --cask mactex-no-gui" >&2
    echo "  brew install tectonic" >&2
    echo "  cargo install tectonic" >&2
    exit 1
fi

# cleanup_artifacts removes standard pdflatex/latexmk/bibtex/hyperref
# side files for every stem we are or were building. Registered on EXIT
# so it fires on both success and failure; tectonic produces none of
# these (the rm calls are no-ops in that case).
cleanup_artifacts() {
    local stem ext
    for stem in "${STEMS[@]}"; do
        for ext in aux fdb_latexmk fls log out toc bbl blg lof lot idx ind ilg nav snm vrb synctex.gz; do
            rm -f "${stem}.${ext}"
        done
    done
}
trap cleanup_artifacts EXIT

build_one() {
    local stem="$1"
    local tex="${stem}.tex"
    if [[ ! -f "$tex" ]]; then
        echo "Error: $tex not found in $(pwd)" >&2
        return 1
    fi
    echo "Building ${tex} with ${ENGINE}..."
    local rc=0
    case "$ENGINE" in
        latexmk)
            latexmk -pdf -interaction=nonstopmode -halt-on-error "$tex" || rc=$?
            ;;
        tectonic)
            tectonic "$tex" || rc=$?
            ;;
        pdflatex)
            # Run twice for references/citations
            pdflatex -interaction=nonstopmode -halt-on-error "$tex" || rc=$?
            if [[ $rc -eq 0 ]]; then
                pdflatex -interaction=nonstopmode -halt-on-error "$tex" || rc=$?
            fi
            ;;
    esac
    if [[ $rc -ne 0 ]]; then
        echo "Failed to build ${tex} (exit ${rc})" >&2
        return "$rc"
    fi
    echo "Built: whitepaper/${stem}.pdf"
}

FAILURES=()
for stem in "${STEMS[@]}"; do
    if ! build_one "$stem"; then
        FAILURES+=("$stem")
    fi
done

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo "Failed: ${FAILURES[*]}" >&2
    exit 1
fi
