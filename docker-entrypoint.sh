#!/bin/sh
set -e

DATA_DIR="${KEYFENCE_HOME:-/data}"
CONFIG_FILE="${KEYFENCE_CONFIG:-$DATA_DIR/config.yaml}"
CONFIG_EXAMPLE="${KEYFENCE_CONFIG_EXAMPLE:-/app/config.example.yaml}"

if ! mkdir -p "$DATA_DIR/certs" 2>/dev/null || [ ! -w "$DATA_DIR" ]; then
  echo "[keyfence] $DATA_DIR is not writable by $(id -un) (uid $(id -u))." >&2
  echo "[keyfence] keyfence keeps the vault, the audit log and the CA certificate there." >&2
  echo "[keyfence] fix it on the host, then start again:" >&2
  echo "[keyfence]   sudo chown -R $(id -u):$(id -g) ./data" >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
  echo "[keyfence] config created at $CONFIG_FILE (edit freely)"
fi

if [ "$1" = "proxy" ] || [ -z "$1" ]; then
  echo "[keyfence] starting proxy on port 8888"
  echo "[keyfence] CA certificate: $DATA_DIR/certs/mitmproxy-ca-cert.pem (on the host)"
  exec mitmdump \
    -s /app/keyfence/addon.py \
    --listen-host 0.0.0.0 \
    --listen-port 8888 \
    --set confdir="$DATA_DIR/certs" \
    --set block_global=true
fi

exec keyfence "$@"
