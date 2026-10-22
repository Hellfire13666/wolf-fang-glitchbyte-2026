#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
KEYS_FILE="$HOME/.config/wolf-fang/keys.env"
if [[ -f "$KEYS_FILE" ]]; then
    if [[ ! -O "$KEYS_FILE" ]] || [[ -n "$(find "$KEYS_FILE" -maxdepth 0 -perm /077 -print -quit)" ]]; then
        echo "WOLF FANG: refusing insecure API keys file. Must be owned by you and mode 600: $KEYS_FILE" >&2
        exit 1
    fi
    # Only ever source your own locally configured, owner-readable key file.
    # Do not download third-party key files or commit this file to GitHub.
    # shellcheck disable=SC1090
    source "$KEYS_FILE"
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
if [[ $# -eq 0 ]]; then
    python3 -m wolf_fang --demo
else
    python3 -m wolf_fang "$@"
fi
