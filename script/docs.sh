#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

case "${1:-}" in
"clean")
  latexmk -cd docs/design.tex -C
  latexmk -cd docs/manual.tex -C
  ;;
"view")
  latexmk -cd docs/"$2".tex -pvc
  ;;
*)
  latexmk -cd docs/design.tex -pdf
  latexmk -cd docs/manual.tex -pdf
  ;;
esac
