#!/usr/bin/env bash
# Run markcleanse from anywhere without installing anything.
#   ln -s "$(pwd)/markcleanse.sh" ~/.local/bin/markcleanse
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
exec env PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" python3 -m markcleanse "$@"
