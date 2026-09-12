#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

export KEYFENCE_HOME="$(mktemp -d)"
export KEYFENCE_CONFIG="$KEYFENCE_HOME/config.yaml"
UPSTREAM_PORT=${UPSTREAM_PORT:-9999}
PROXY_PORT=${PROXY_PORT:-8899}
FAKE_KEY="ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
VAULT_SECRET="senha-interna-sem-formato-2026"
ENV_SECRET="envOnlyTokenValue987654"
PIDS=()

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

write_config() { printf 'mode: %s\nextra_hosts: ["127.0.0.1", "localhost"]\n' "$1" > "$KEYFENCE_CONFIG"; }

UPSTREAM_PORT=$UPSTREAM_PORT python3 - <<'EOF' &
import json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG = os.path.join(os.environ["KEYFENCE_HOME"], "upstream_received.log")
class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_chunk(self, data):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(LOG, "ab") as fh:
            fh.write(body + b"\n")
        if self.path.endswith("/stream"):
            text = json.loads(body)["content"]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(text), 5):
                chunk = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text[i:i + 5]}}
                self.send_chunk(f"event: content_block_delta\ndata: {json.dumps(chunk)}\n\n".encode())
                time.sleep(0.01)
            self.send_chunk(b'event: message_stop\ndata: {"type":"message_stop"}\n\n')
            self.wfile.write(b"0\r\n\r\n")
            return
        payload = b'{"upstream_received": ' + body + b'}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), Echo).serve_forever()
EOF
PIDS+=($!)

python3 -c "from keyfence.vault import Vault; Vault().add('$VAULT_SECRET')"

start_proxy() {
  mitmdump -q -s keyfence/addon.py --listen-port "$PROXY_PORT" --set block_global=false &
  PROXY_PID=$!
  PIDS+=($PROXY_PID)
  for _ in $(seq 1 50); do
    python3 -c "import socket; socket.create_connection(('127.0.0.1', $PROXY_PORT), timeout=0.2)" 2>/dev/null && return
    sleep 0.2
  done
  echo "FAILED: proxy did not start"; exit 1
}
stop_proxy() { kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null || true; }
post() { curl -s --noproxy "" -x "http://127.0.0.1:$PROXY_PORT" -d "$1" "http://127.0.0.1:$UPSTREAM_PORT$2"; }

echo "=== 1) redact mode ==="
write_config redact
start_proxy
RESP=$(post "{\"messages\":[{\"role\":\"user\",\"content\":\"my token is $FAKE_KEY and the password is $VAULT_SECRET\"}]}" /v1/chat/completions)
echo "$RESP"
[[ "$RESP" != *"$FAKE_KEY"* ]]     || { echo "FAILED: key leaked"; exit 1; }
[[ "$RESP" != *"$VAULT_SECRET"* ]] || { echo "FAILED: vault secret leaked"; exit 1; }
[[ "$RESP" == *"REDACTED"* ]]      || { echo "FAILED: nothing redacted"; exit 1; }
echo "OK: upstream never saw the secrets"

echo
echo "=== 2) clean request passes untouched ==="
RESP=$(post '{"messages":[{"role":"user","content":"explain entropy"}]}' /v1/chat/completions)
[[ "$RESP" == *"explain entropy"* ]] || { echo "FAILED: body altered"; exit 1; }
echo "OK: body intact"
stop_proxy

echo
echo "=== 3) placeholder mode + buffered rehydration ==="
write_config placeholder
start_proxy
RESP=$(post "{\"content\":\"use the key $FAKE_KEY ok\"}" /v1/chat/completions)
echo "$RESP"
[[ "$RESP" == *"$FAKE_KEY"* ]] || { echo "FAILED: rehydration did not happen"; exit 1; }
grep -q "<<SECRET_" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: upstream did not get placeholder"; exit 1; }
! grep -q "$FAKE_KEY" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: key reached upstream"; exit 1; }
echo "OK: model saw <<SECRET_1>>, client got the real value back"

echo
echo "=== 4) placeholder mode + streaming (SSE split across events) ==="
RESP=$(post "{\"content\":\"the key is $FAKE_KEY done\"}" /v1/stream)
echo "$RESP" | head -c 400; echo
[[ "$RESP" == *"text/event-stream"* ]] && { echo "FAILED: unexpected"; exit 1; }
[[ "$RESP" != *"<<SECRET_"* ]] || { echo "FAILED: placeholder left in stream"; exit 1; }
JOINED=$(echo "$RESP" | python3 -c "
import sys, json
print(''.join(json.loads(l[5:])['delta']['text'] for l in sys.stdin if l.startswith('data:') and 'delta' in l))")
[[ "$JOINED" == "the key is $FAKE_KEY done" ]] || { echo "FAILED: stream text was '$JOINED'"; exit 1; }
[[ "$RESP" == *"message_stop"* ]] || { echo "FAILED: chunked stream ended early"; exit 1; }
echo "OK: streamed placeholder split across SSE events was restored"
stop_proxy

echo
echo "=== 5) block mode ==="
write_config block
start_proxy
RESP=$(curl -s -o /dev/null -w '%{http_code}' --noproxy "" -x "http://127.0.0.1:$PROXY_PORT" -d "{\"content\":\"$FAKE_KEY\"}" "http://127.0.0.1:$UPSTREAM_PORT/v1/x")
[[ "$RESP" == "403" ]] || { echo "FAILED: expected 403, got $RESP"; exit 1; }
echo "OK: blocked with 403"
stop_proxy

echo
echo "=== 6) keyfence exec: env snapshot becomes a vault entry ==="
write_config redact
MY_SERVICE_TOKEN="$ENV_SECRET" PROXY_PORT=$PROXY_PORT UPSTREAM_PORT=$UPSTREAM_PORT \
  python3 -m keyfence exec -p "$PROXY_PORT" -- bash -c \
  'curl -s --noproxy "" -d "{\"content\":\"token=$MY_SERVICE_TOKEN\"}" "http://127.0.0.1:$UPSTREAM_PORT/v1/x"' > "$KEYFENCE_HOME/exec_resp.txt"
cat "$KEYFENCE_HOME/exec_resp.txt"; echo
grep -q "REDACTED:vault" "$KEYFENCE_HOME/exec_resp.txt" || { echo "FAILED: env secret not redacted via exec"; exit 1; }
! grep -q "$ENV_SECRET" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: env secret reached upstream"; exit 1; }
echo "OK: value only known from the environment was caught"

echo
echo "=== audit log ==="
cat "$KEYFENCE_HOME/audit.log"
echo
echo "ALL INTEGRATION TESTS PASSED"
