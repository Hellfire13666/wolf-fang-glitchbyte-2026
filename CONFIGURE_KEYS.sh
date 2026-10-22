#!/usr/bin/env bash
set -euo pipefail
umask 077
CFG_DIR="$HOME/.config/wolf-fang"
KEYS_FILE="$CFG_DIR/keys.env"
mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"
if [[ -f "$KEYS_FILE" ]]; then
    if [[ ! -O "$KEYS_FILE" ]] || [[ -n "$(find "$KEYS_FILE" -maxdepth 0 -perm /077 -print -quit)" ]]; then
        echo "Refusing to read insecure existing key file: $KEYS_FILE" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$KEYS_FILE"
fi
echo '🐺 WOLF FANG // OPTIONAL API KEY SETUP'
echo 'Only enter keys from providers you personally registered with.'
echo 'Press Enter to keep any existing value; missing keys can stay empty.'
tmp="$(mktemp "$CFG_DIR/.keys.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
for name in GREYNOISE_API_KEY ABUSEIPDB_API_KEY IPINFO_TOKEN OTX_API_KEY; do
    current="${!name-}"
    read -r -s -p "$name (hidden, Enter to keep current): " entry || true
    printf '\n'
    if [[ -n "$entry" ]]; then
        if [[ ! "$entry" =~ ^[A-Za-z0-9._-]+$ ]]; then
            echo "Invalid key characters in $name; setup cancelled" >&2
            exit 1
        fi
        current="$entry"
    fi
    if [[ -n "$current" ]]; then
        printf 'export %s=%q\n' "$name" "$current" >> "$tmp"
    fi
    unset entry current
done
chmod 600 "$tmp"
mv -f "$tmp" "$KEYS_FILE"
trap - EXIT
echo "Saved private key configuration with owner-only access: $KEYS_FILE"
echo 'No keys were printed. Run ./OPEN_WOLF_FANG.sh --doctor to check configuration.'
