#!/usr/bin/env bash
# Build and install the AIM hub (`aim-server` + `aim`) on a Linux host.
#
# Usage:
#   ./deploy/install-server.sh --san aim.example.internal --san 10.0.0.10 --host workstation --host macbook
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SANS=()
HOSTS=()
LISTEN="${AIM_LISTEN:-0.0.0.0:11460}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --san)
            SANS+=("$2")
            shift 2
            ;;
        --host)
            HOSTS+=("$2")
            shift 2
            ;;
        --listen)
            LISTEN="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--san <DNS_OR_IP>]... [--host <HOST_NAME>]... [--listen <ADDR:PORT>]" >&2
            exit 1
            ;;
    esac
done

if [[ ${#SANS[@]} -eq 0 ]]; then
    SANS=("aim.example.internal")
fi

echo "==> Building release binaries (aim-server, aim)..."
cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml"

sudo install -m 0755 "$REPO_DIR/target/release/aim-server" /usr/local/bin/aim-server
sudo install -m 0755 "$REPO_DIR/target/release/aim" /usr/local/bin/aim

if ! id -u aim >/dev/null 2>&1; then
    sudo useradd --system --home-dir /var/lib/aim --create-home --shell /usr/sbin/nologin aim
fi

sudo install -d -m 0750 -o root -g aim /etc/aim
sudo install -d -m 0700 -o root -g root /etc/aim/ca-private
sudo install -d -m 0700 -o root -g root /etc/aim/client-keys
sudo install -d -m 0700 -o aim -g aim /var/lib/aim

# Migrate legacy /etc/aim/ca.key into root-only /etc/aim/ca-private/ca.key if present.
if sudo test -f /etc/aim/ca.key && ! sudo test -f /etc/aim/ca-private/ca.key; then
    sudo mv /etc/aim/ca.key /etc/aim/ca-private/ca.key
    sudo chown root:root /etc/aim/ca-private/ca.key
    sudo chmod 0600 /etc/aim/ca-private/ca.key
fi

if ! sudo test -f /etc/aim/ca.crt || ! sudo test -f /etc/aim/ca-private/ca.key; then
    echo "==> Initializing AIM private CA..."
    sudo /usr/local/bin/aim-server init-ca \
        --ca-cert /etc/aim/ca.crt \
        --ca-key /etc/aim/ca-private/ca.key
    sudo chown root:aim /etc/aim/ca.crt
    sudo chmod 0644 /etc/aim/ca.crt
    sudo chown root:root /etc/aim/ca-private/ca.key
    sudo chmod 0600 /etc/aim/ca-private/ca.key
fi

if ! sudo test -f /etc/aim/server.crt || ! sudo test -f /etc/aim/server.key; then
    echo "==> Issuing server TLS certificate..."
    SAN_ARGS=()
    for s in "${SANS[@]}"; do
        SAN_ARGS+=(--san "$s")
    done
    sudo /usr/local/bin/aim-server init-cert \
        --ca-cert /etc/aim/ca.crt \
        --ca-key /etc/aim/ca-private/ca.key \
        --cert /etc/aim/server.crt \
        --key /etc/aim/server.key \
        "${SAN_ARGS[@]}"
    sudo chown root:aim /etc/aim/server.crt
    sudo chmod 0644 /etc/aim/server.crt
    sudo chown aim:aim /etc/aim/server.key
    sudo chmod 0600 /etc/aim/server.key
fi

if ! sudo test -f /etc/aim/server.toml; then
    echo "==> Writing /etc/aim/server.toml..."
    sudo /usr/local/bin/aim-server init-config \
        --config /etc/aim/server.toml \
        --listen "$LISTEN" \
        --data-dir /var/lib/aim \
        --tls-cert /etc/aim/server.crt \
        --tls-key /etc/aim/server.key
    sudo chown aim:aim /etc/aim/server.toml
    sudo chmod 0600 /etc/aim/server.toml
fi

for h in "${HOSTS[@]}"; do
    KEY_PATH="/etc/aim/client-keys/${h}.key"
    if ! sudo test -f "$KEY_PATH"; then
        echo "==> Generating client key for host '$h'..."
        sudo /usr/local/bin/aim-server keygen \
            --config /etc/aim/server.toml \
            --host "$h" \
            --out-key "$KEY_PATH" >/dev/null
        sudo chown root:root "$KEY_PATH"
        sudo chmod 0600 "$KEY_PATH"
        sudo chown aim:aim /etc/aim/server.toml
        sudo chmod 0600 /etc/aim/server.toml
    fi
done

sudo install -m 0644 "$SCRIPT_DIR/aim-server.service" /etc/systemd/system/aim-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now aim-server.service
sudo systemctl restart aim-server.service

for _ in {1..20}; do
    if /usr/local/bin/aim --url "https://${SANS[0]}:11460/aim" --ca-cert /etc/aim/ca.crt health >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

echo "==> aim-server.service status:"
sudo systemctl status --no-pager aim-server.service | head -n 12
