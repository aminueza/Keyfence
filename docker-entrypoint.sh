#!/bin/sh
set -e

DATA_DIR="${KEYFENCE_HOME:-/data}"
CONFIG_FILE="${KEYFENCE_CONFIG:-$DATA_DIR/config.yaml}"
CONFIG_EXAMPLE="${KEYFENCE_CONFIG_EXAMPLE:-/app/config.example.yaml}"

refuse() {
  echo "[keyfence] $1 is not writable by $(id -un) (uid $(id -u))." >&2
  echo "[keyfence] keyfence keeps the vault, the audit log and the CA certificate in $DATA_DIR." >&2
  echo "[keyfence] fix it on the host, then start again:" >&2
  echo "[keyfence]   sudo chown -R $(id -u):$(id -g) ./data" >&2
  exit 1
}

if ! mkdir -p "$DATA_DIR/certs" || [ ! -w "$DATA_DIR" ]; then
  refuse "$DATA_DIR"
fi

for path in "$DATA_DIR/vault.json" "$DATA_DIR/audit.log"; do
  if { [ -e "$path" ] || [ -L "$path" ]; } && [ ! -w "$path" ]; then
    refuse "$path"
  fi
done

if [ ! -f "$DATA_DIR/certs/mitmproxy-ca-cert.pem" ] && [ ! -w "$DATA_DIR/certs" ]; then
  refuse "$DATA_DIR/certs"
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
