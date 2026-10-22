#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
echo '🐺 WOLF FANG // RELEASE CHECK (OFFLINE)'
for name in wolf_fang tests assets README.md SECURITY.md .gitignore; do
  if [[ ! -e "$name" ]]; then echo "FAIL: Missing $name" >&2; exit 1; fi
done
# Never publish raw result exports or API keys from this repository tree.
if find . -type f \( -name 'keys.env' -o -name '.env' -o -name '*.pem' -o -name '*.key' \) -print | grep -q .; then
  echo 'FAIL: secret-like files found in source tree; remove them from this publish copy' >&2
  exit 1
fi
bash ./RUN_TESTS.sh
bash ./OPEN_WOLF_FANG.sh --doctor
# Demo output is redirected to a disposable HOME; no real providers are queried.
TMPHOME="$(mktemp -d)"
trap 'rm -rf "$TMPHOME"' EXIT
HOME="$TMPHOME" bash ./OPEN_WOLF_FANG.sh --demo
printf 'PASS: Offline release checks completed. No files have been published.\n'
