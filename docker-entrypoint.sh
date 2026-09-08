#!/bin/sh
set -e

mkdir -p /data/certs

if [ ! -f /data/config.yaml ]; then
  cp /app/config.example.yaml /data/config.yaml
  echo "[keyfence] config created at ./data/config.yaml (edit freely)"
fi

if [ "$1" = "proxy" ] || [ -z "$1" ]; then
  echo "[keyfence] starting proxy on port 8888"
  echo "[keyfence] CA certificate: ./data/certs/mitmproxy-ca-cert.pem (on the host)"
  exec mitmdump \
    -s /app/keyfence/addon.py \
    --listen-host 0.0.0.0 \
    --listen-port 8888 \
    --set confdir=/data/certs \
    --set block_global=true
fi

exec keyfence "$@"
