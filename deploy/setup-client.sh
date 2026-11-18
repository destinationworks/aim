#!/usr/bin/env bash
# Configure the AIM client (`aim`) on a Linux or macOS machine.
#
# Usage:
#   ./deploy/setup-client.sh /path/to/ca.crt /path/to/<host>.key [https://aim.example.internal:11460/aim]
set -euo pipefail
umask 077

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <path-to-ca.crt> <path-to-host.key> [https://aim.example.internal:11460/aim]" >&2
    exit 1
fi

CA_SRC="$1"
KEY_SRC="$2"
AIM_URL="${3:-https://aim.example.internal:11460/aim}"

CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/aim"
install -d -m 0700 "$CONF_DIR"
install -m 0644 "$CA_SRC" "$CONF_DIR/ca.crt"
install -m 0600 "$KEY_SRC" "$CONF_DIR/host.key"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$REPO_DIR/Cargo.toml" ]]; then
    cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml" -p aim
    install -d -m 0755 "$HOME/.local/bin"
    install -m 0755 "$REPO_DIR/target/release/aim" "$HOME/.local/bin/aim"
    AIM_BIN="$HOME/.local/bin/aim"
elif command -v aim >/dev/null 2>&1; then
    AIM_BIN="$(command -v aim)"
else
    echo "error: aim binary not found and Cargo workspace not present" >&2
    exit 1
fi

"$AIM_BIN" init --force \
    --url "$AIM_URL" \
    --ca-cert "$CONF_DIR/ca.crt" \
    --key-file "$CONF_DIR/host.key"

"$AIM_BIN" health
"$AIM_BIN" status
