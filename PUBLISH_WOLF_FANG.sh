#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
REPO='Hellfire13666/wolf-fang-glitchbyte-2026'
MODE="${1:---check}"
case "$MODE" in
  --check|--publish) ;;
  *) echo 'Usage: ./PUBLISH_WOLF_FANG.sh [--check|--publish]' >&2; exit 2;;
esac
bash ./RELEASE_CHECK.sh
if [[ "$MODE" == --check ]]; then
  echo '🐺 Release kit prepared locally. Use --publish only after the Ubuntu tests pass.'
  exit 0
fi
for c in git gh; do
  command -v "$c" >/dev/null || { echo "Missing $c. Install/login separately, then retry." >&2; exit 1; }
done
gh auth status >/dev/null
login="$(gh api user -q .login)"
if [[ "$login" != 'Hellfire13666' ]]; then
  echo "GitHub signed in as $login, expected Hellfire13666. Refusing to publish." >&2
  exit 1
fi
if [[ -d .git ]]; then
  echo 'This folder already has Git metadata. Review it manually; not auto-publishing.' >&2
  exit 1
fi
if gh repo view "$REPO" --json name >/dev/null 2>&1; then
  echo "$REPO already exists. Stopped so no existing work is overwritten." >&2
  exit 1
fi
echo "This will create a PUBLIC GitHub repository: $REPO"
echo 'Only files in this source bundle will be committed. No user reports or API keys.'
read -r -p 'Type PUBLISH to approve creating the PUBLIC repo and draft release: ' answer
[[ "$answer" == PUBLISH ]] || { echo 'Cancelled.'; exit 1; }
git init -b main
git add .github .gitignore README.md SECURITY.md GITHUB_BRANDING.md UPGRADE_NOTES.md RELEASE_NOTES.md GITHUB_PUBLISH_GUIDE.md \
  RUN_TESTS.sh RELEASE_CHECK.sh PUBLISH_WOLF_FANG.sh CONFIGURE_KEYS.sh OPEN_WOLF_FANG.sh OPEN_FANG_VISION.sh wolf_fang tests assets examples
git diff --cached --check
git diff --cached --stat
git commit -m 'WOLF FANG v0.1.3: FANG VISION and approved wolf branding'
gh repo create "$REPO" --public --source=. --remote=origin --push \
  --description 'WOLF FANG: GlitchByte Phantom Labs IP intelligence and offline FANG VISION dashboard'
ZIP="$HOME/Downloads/WOLF-FANG-GLITCHBYTE-PHANTOM-LABS-v0.1.3.zip"
SUM="$ZIP.sha256"
assets=()
if [[ -f "$ZIP" ]]; then assets+=("$ZIP"); fi
if [[ -f "$SUM" ]]; then assets+=("$SUM"); fi
gh release create v0.1.3 "${assets[@]}" --repo "$REPO" \
  --title 'WOLF FANG v0.1.3 · Visual Edition' --notes-file RELEASE_NOTES.md --draft
printf '\nDRAFT release created. Review before publishing: https://github.com/%s/releases\n' "$REPO"
