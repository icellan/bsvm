#!/usr/bin/env bash
set -euo pipefail

# Build the BSVM whitepaper PDF from LaTeX source.
#
# Usage: ./whitepaper/build.sh
#
# Requires a LaTeX distribution. Install options:
#   macOS:   brew install --cask mactex-no-gui   (or: brew install tectonic)
#   Ubuntu:  sudo apt install texlive-full
#   Minimal: cargo install tectonic

cd "$(dirname "$0")"
TEX=bsvm-whitepaper.tex
PDF=bsvm-whitepaper.pdf

# Pick the best available engine
if command -v latexmk &>/dev/null; then
    echo "Building with latexmk..."
    latexmk -pdf -interaction=nonstopmode -halt-on-error "$TEX"
elif command -v tectonic &>/dev/null; then
    echo "Building with tectonic..."
    tectonic "$TEX"
elif command -v pdflatex &>/dev/null; then
    echo "Building with pdflatex..."
    # Run twice for references/citations
    pdflatex -interaction=nonstopmode -halt-on-error "$TEX"
    pdflatex -interaction=nonstopmode -halt-on-error "$TEX"
else
    echo "Error: No LaTeX engine found." >&2
    echo "Install one of:" >&2
    echo "  brew install --cask mactex-no-gui" >&2
    echo "  brew install tectonic" >&2
    echo "  cargo install tectonic" >&2
    exit 1
fi

echo "Built: whitepaper/$PDF"

# Clean up LaTeX build artifacts
rm -f "${TEX%.tex}.aux" "${TEX%.tex}.fdb_latexmk" "${TEX%.tex}.fls" \
      "${TEX%.tex}.log" "${TEX%.tex}.out"
