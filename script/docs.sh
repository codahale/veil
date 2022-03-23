#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

latexmk -cd docs/design.tex -pdf
latexmk -cd docs/manual.tex -pdf
