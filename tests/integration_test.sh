#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

export KEYFENCE_HOME="$(mktemp -d)"
export KEYFENCE_CONFIG="$KEYFENCE_HOME/config.yaml"
UPSTREAM_PORT=${UPSTREAM_PORT:-9999}
WS_PORT=${WS_PORT:-9998}
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
probe() { curl -s --noproxy "" -x "http://127.0.0.1:$PROXY_PORT" http://keyfence.invalid/; }
ws_send() {
  WS_PORT=$WS_PORT PROXY_PORT=$PROXY_PORT python3 - "$1" <<'EOF'
import os, socket, sys
from wsproto import ConnectionType, WSConnection
from wsproto.events import Message, Request, TextMessage
port = os.environ["WS_PORT"]
ws = WSConnection(ConnectionType.CLIENT)
sock = socket.create_connection(("127.0.0.1", int(os.environ["PROXY_PORT"])), timeout=10)
sock.settimeout(5)
sock.sendall(ws.send(Request(host=f"127.0.0.1:{port}", target=f"http://127.0.0.1:{port}/ws")))
ws.receive_data(sock.recv(65535))
list(ws.events())
sock.sendall(ws.send(Message(data=sys.argv[1])))
try:
    ws.receive_data(sock.recv(65535))
except (TimeoutError, socket.timeout):
    print("NO FRAME CAME BACK")
else:
    for event in ws.events():
        if isinstance(event, TextMessage):
            print(event.data)
EOF
}

echo "=== 0) the addon is live under mitmproxy's real script loader ==="
write_config redact
start_proxy
VERSION=$(python3 -c "import keyfence; print(keyfence.__version__)")
PROBE=""
for _ in $(seq 1 50); do
  PROBE=$(probe)
  [[ "$PROBE" == *"\"keyfence\": \"$VERSION\""* ]] && break
  sleep 0.2
done
echo "$PROBE"
[[ "$PROBE" == *"\"keyfence\": \"$VERSION\""* ]] || { echo "FAILED: addon not answering the probe: $PROBE"; exit 1; }
[[ "$PROBE" == *'"mode": "redact"'* ]]           || { echo "FAILED: probe did not report the mode"; exit 1; }
echo "OK: mitmdump loaded keyfence/addon.py and the addon answers"
python3 -c "from keyfence import runner; import sys; sys.exit(0 if runner.addon_live($PROXY_PORT) else 1)" || { echo "FAILED: runner.addon_live says the addon is down"; exit 1; }
echo "OK: runner.addon_live agrees"

echo
echo "=== 1) redact mode ==="
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

echo
echo "=== 2b) redact keeps JSON valid when a secret sits next to an escape ==="
BODY=$(python3 -c "import json; print(json.dumps({'content': 'prefix\t$FAKE_KEY\n$VAULT_SECRET end'}))")
RESP=$(post "$BODY" /v1/chat/completions)
echo "$RESP"
python3 - "$RESP" <<'EOF' || { echo "FAILED: JSON broken or secret left next to the escape"; exit 1; }
import json, sys
content = json.loads(sys.argv[1])["upstream_received"]["content"]
import re
assert re.fullmatch(r"prefix\t\[REDACTED:github-[a-z]+\]\n\[REDACTED:vault\] end", content), content
EOF
echo "OK: upstream parsed the body, tab and newline kept, both secrets replaced"
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
echo "=== 5b) websocket frames to a monitored host ==="
WS_PORT=$WS_PORT python3 - <<'EOF' &
import os, socket, threading
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, CloseConnection, Message, Request, TextMessage
LOG = os.path.join(os.environ["KEYFENCE_HOME"], "ws_received.log")
def handle(conn):
    ws = WSConnection(ConnectionType.SERVER)
    while True:
        data = conn.recv(65535)
        if not data:
            return
        ws.receive_data(data)
        for event in ws.events():
            if isinstance(event, Request):
                conn.sendall(ws.send(AcceptConnection()))
            elif isinstance(event, TextMessage):
                with open(LOG, "a") as fh:
                    fh.write(event.data + "\n")
                conn.sendall(ws.send(Message(data=event.data)))
            elif isinstance(event, CloseConnection):
                conn.sendall(ws.send(event.response()))
                return
srv = socket.create_server(("127.0.0.1", int(os.environ["WS_PORT"])))
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
EOF
PIDS+=($!)
for _ in $(seq 1 50); do
  python3 -c "import socket; socket.create_connection(('127.0.0.1', $WS_PORT), timeout=0.2)" 2>/dev/null && break
  sleep 0.2
done
touch "$KEYFENCE_HOME/ws_received.log"

write_config redact
start_proxy
FRAME=$(ws_send "{\"text\":\"my token is $FAKE_KEY ok\"}")
echo "$FRAME"
grep -q "REDACTED:github" "$KEYFENCE_HOME/ws_received.log" || { echo "FAILED: the frame was not redacted"; exit 1; }
! grep -q "$FAKE_KEY" "$KEYFENCE_HOME/ws_received.log" || { echo "FAILED: key reached the websocket server"; exit 1; }
grep -q '"websocket": true' "$KEYFENCE_HOME/audit.log" || { echo "FAILED: the frame is not in the audit log"; exit 1; }
echo "OK: the text frame was redacted before it reached the server"
stop_proxy

write_config block
start_proxy
FRAMES_BEFORE=$(wc -l < "$KEYFENCE_HOME/ws_received.log")
FRAME=$(ws_send "{\"text\":\"$FAKE_KEY\"}")
[[ "$FRAME" == "NO FRAME CAME BACK" ]] || { echo "FAILED: block mode forwarded the frame: $FRAME"; exit 1; }
[[ "$(wc -l < "$KEYFENCE_HOME/ws_received.log")" == "$FRAMES_BEFORE" ]] || { echo "FAILED: the blocked frame reached the server"; exit 1; }
echo "OK: block mode dropped the frame"
stop_proxy

write_config placeholder
start_proxy
FRAME=$(ws_send "{\"text\":\"use $FAKE_KEY now\"}")
echo "$FRAME"
[[ "$FRAME" == *"$FAKE_KEY"* ]] || { echo "FAILED: the real value did not come back in the frame"; exit 1; }
grep -q "<<SECRET_" "$KEYFENCE_HOME/ws_received.log" || { echo "FAILED: the server did not get a placeholder"; exit 1; }
! grep -q "$FAKE_KEY" "$KEYFENCE_HOME/ws_received.log" || { echo "FAILED: key reached the websocket server"; exit 1; }
echo "OK: the server saw a placeholder and the client got the real value back"
stop_proxy

echo
echo "=== 6) keyfence exec: env snapshot becomes a vault entry ==="
write_config redact
MY_SERVICE_TOKEN="$ENV_SECRET" PROXY_PORT=$PROXY_PORT UPSTREAM_PORT=$UPSTREAM_PORT \
  python3 -m keyfence exec -p "$PROXY_PORT" -- bash -c \
  'echo "SSL_CERT_FILE=$SSL_CERT_FILE GIT_SSL_CAINFO=$GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS"; curl -s --noproxy "" -d "{\"content\":\"token=$MY_SERVICE_TOKEN\"}" "http://127.0.0.1:$UPSTREAM_PORT/v1/x"' > "$KEYFENCE_HOME/exec_resp.txt"
cat "$KEYFENCE_HOME/exec_resp.txt"; echo
grep -q "^SSL_CERT_FILE=$KEYFENCE_HOME/ca-bundle.pem GIT_SSL_CAINFO=$KEYFENCE_HOME/ca-bundle.pem NODE_EXTRA_CA_CERTS=$HOME/.mitmproxy/mitmproxy-ca-cert.pem$" "$KEYFENCE_HOME/exec_resp.txt" || { echo "FAILED: exec did not hand the child the bundle and the single CA"; exit 1; }
grep -q "REDACTED:vault" "$KEYFENCE_HOME/exec_resp.txt" || { echo "FAILED: env secret not redacted via exec"; exit 1; }
! grep -q "$ENV_SECRET" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: env secret reached upstream"; exit 1; }
echo "OK: value only known from the environment was caught"
grep -q "keyfence $VERSION: mode=redact | .* hosts monitored | .* rules | vault with .* secret(s)" "$KEYFENCE_HOME/proxy.log" || { echo "FAILED: startup summary missing from proxy.log"; exit 1; }
grep -q "REDACT -> 127.0.0.1: 1 secret(s) removed from request" "$KEYFENCE_HOME/proxy.log" || { echo "FAILED: detection line missing from proxy.log"; exit 1; }
! grep -qi "proxy listening\|Loading script" "$KEYFENCE_HOME/proxy.log" || { echo "FAILED: mitmproxy info chatter in proxy.log"; exit 1; }
echo "OK: proxy.log has the startup summary and the detection line, nothing else"

echo
echo "=== 7) keyfence exec: a canary hit is logged in proxy.log ==="
python3 -m keyfence canary "$KEYFENCE_HOME/.env" --name PLANTED_TOKEN
CANARY_VALUE=$(sed -n 's/^PLANTED_TOKEN=//p' "$KEYFENCE_HOME/.env")
CANARY_VALUE="$CANARY_VALUE" PROXY_PORT=$PROXY_PORT UPSTREAM_PORT=$UPSTREAM_PORT \
  python3 -m keyfence exec -p "$PROXY_PORT" -- bash -c \
  'curl -s --noproxy "" -d "{\"content\":\"token=$CANARY_VALUE\"}" "http://127.0.0.1:$UPSTREAM_PORT/v1/x"' > "$KEYFENCE_HOME/exec_canary.txt"
cat "$KEYFENCE_HOME/exec_canary.txt"; echo
grep -q "REDACTED:canary" "$KEYFENCE_HOME/exec_canary.txt" || { echo "FAILED: canary not redacted via exec"; exit 1; }
grep -q "CANARY tripped -> 127.0.0.1: .*/.env was read and sent" "$KEYFENCE_HOME/proxy.log" || { echo "FAILED: CANARY tripped missing from proxy.log"; exit 1; }
echo "OK: CANARY tripped with the file path is in proxy.log"
echo
echo "=== 7b) keyfence exec: a host it does not monitor is tunneled, not intercepted ==="
TLS_PORT=${TLS_PORT:-9997}
TLS_RECORD="$KEYFENCE_HOME/tls_received.log"
BODY="{\"content\":\"my token is $FAKE_KEY over tls\"}"

python3 - <<'EOF'
import datetime, ipaddress, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
home = os.environ["KEYFENCE_HOME"]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256()))
with open(f"{home}/tls.key", "wb") as fh:
    fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open(f"{home}/tls.crt", "wb") as fh:
    fh.write(cert.public_bytes(serialization.Encoding.PEM))
EOF

TLS_PORT=$TLS_PORT python3 - <<'EOF' &
import os, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG = os.path.join(os.environ["KEYFENCE_HOME"], "tls_received.log")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f'{os.environ["KEYFENCE_HOME"]}/tls.crt', f'{os.environ["KEYFENCE_HOME"]}/tls.key')

class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(LOG, "ab") as fh:
            fh.write(body + b"\n")
        payload = b'{"tls_upstream_received": ' + body + b'}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", int(os.environ["TLS_PORT"])), Echo)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
PIDS+=($!)
for _ in $(seq 1 50); do
  python3 -c "import socket; socket.create_connection(('127.0.0.1', $TLS_PORT), timeout=0.2)" 2>/dev/null && break
  sleep 0.2
done

cat > "$KEYFENCE_HOME/tls_client.py" <<'EOF'
import http.client, os, ssl, sys
tls_port, proxy_port, body = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(cafile=os.path.join(os.environ["KEYFENCE_HOME"], "tls.crt"))
conn = http.client.HTTPSConnection("127.0.0.1", proxy_port, context=ctx, timeout=10)
conn.set_tunnel("127.0.0.1", tls_port)
try:
    conn.request("POST", "/v1/tls", body.encode())
except ssl.SSLCertVerificationError:
    print("OFFERED: a certificate the listener never signed, so the TLS session was intercepted")
else:
    print("TUNNELED", conn.getresponse().read().decode())
EOF

cat > "$KEYFENCE_HOME/exec_tls.sh" <<EOF
python3 "$KEYFENCE_HOME/tls_client.py" "$TLS_PORT" "$PROXY_PORT" '$BODY'
EOF
cat > "$KEYFENCE_HOME/exec_both.sh" <<EOF
python3 "$KEYFENCE_HOME/tls_client.py" "$TLS_PORT" "$PROXY_PORT" '$BODY'
curl -s --noproxy "" -d '$BODY' "http://127.0.0.1:$UPSTREAM_PORT/v1/x"
echo
EOF

: > "$TLS_RECORD"
: > "$KEYFENCE_HOME/upstream_received.log"
printf 'mode: redact\nhosts: ["127.0.0.1"]\n' > "$KEYFENCE_CONFIG"
MONITORED="$KEYFENCE_HOME/exec_monitored.flows"
echo "--- 127.0.0.1 is monitored"
python3 -m keyfence exec -p "$PROXY_PORT" --record "$MONITORED" -- bash "$KEYFENCE_HOME/exec_both.sh" | tee "$KEYFENCE_HOME/exec_monitored.txt"
grep -q "OFFERED:" "$KEYFENCE_HOME/exec_monitored.txt" || { echo "FAILED: the monitored host was not intercepted"; exit 1; }
grep -q "REDACTED:github" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: the monitored host was not scanned and rewritten"; exit 1; }
! grep -q "$FAKE_KEY" "$KEYFENCE_HOME/upstream_received.log" || { echo "FAILED: the monitored secret reached the listener"; exit 1; }
echo "OK: the monitored host is intercepted, scanned and rewritten"
python3 - "$MONITORED" "$UPSTREAM_PORT" <<'EOF' || { echo "FAILED: the record does not hold the monitored request"; exit 1; }
import sys
from mitmproxy import io as mio
with open(sys.argv[1], "rb") as fh:
    flows = list(mio.FlowReader(fh).stream())
seen = [(f.request.method, f.request.port) for f in flows]
print("recorded:", seen)
bodies = [f.request.content for f in flows if f.request.method == "POST"]
assert bodies and b"REDACTED" in bodies[0], seen
EOF
echo "OK: the record holds the monitored request with the secret replaced"

: > "$TLS_RECORD"
printf 'mode: redact\nhosts: ["api.openai.com"]\n' > "$KEYFENCE_CONFIG"
UNMONITORED="$KEYFENCE_HOME/exec_unmonitored.flows"
echo "--- 127.0.0.1 is not monitored"
python3 -m keyfence exec -p "$PROXY_PORT" --record "$UNMONITORED" -- bash "$KEYFENCE_HOME/exec_tls.sh" | tee "$KEYFENCE_HOME/exec_unmonitored.txt"
grep -q "TUNNELED" "$KEYFENCE_HOME/exec_unmonitored.txt" || { echo "FAILED: the unmonitored host did not get the listener's own certificate"; exit 1; }
grep -q "$FAKE_KEY over tls" "$TLS_RECORD" || { echo "FAILED: the unmonitored body never reached the listener"; exit 1; }
echo "OK: the unmonitored host was tunneled with the real certificate and reached the listener untouched"
python3 - "$UNMONITORED" "$TLS_PORT" <<'EOF' || { echo "FAILED: the record holds traffic from a host that is not monitored"; exit 1; }
import sys
from mitmproxy import io as mio
with open(sys.argv[1], "rb") as fh:
    flows = list(mio.FlowReader(fh).stream())
seen = [(f.request.method, f.request.port, f.request.content) for f in flows]
print("recorded:", seen)
tls_port = int(sys.argv[2])
assert not [f for f in flows if f.request.port == tls_port and f.request.content], seen
EOF
echo "OK: the record holds no traffic from the host that is not monitored"
write_config redact

echo "=== 8) keyfence selftest proves each mode end to end without touching this home ==="
AUDIT_LINES_BEFORE=$(wc -l < "$KEYFENCE_HOME/audit.log")
VAULT_BEFORE=$(cat "$KEYFENCE_HOME/vault.json")
for mode in block redact placeholder audit; do
  write_config "$mode"
  python3 -m keyfence selftest > "$KEYFENCE_HOME/selftest_$mode.txt" || { cat "$KEYFENCE_HOME/selftest_$mode.txt"; echo "FAILED: selftest exited non-zero in $mode mode"; exit 1; }
  cat "$KEYFENCE_HOME/selftest_$mode.txt"
  ! grep -q "^FAIL" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest printed a FAIL line in $mode mode"; exit 1; }
  for step in mitmdump config proxy addon "CA certificate" "CA bundle" mode request response "audit log"; do
    grep -q "^ok    $step:" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest has no ok line for $step in $mode mode"; exit 1; }
  done
  grep -q "^ok    mode: the proxy reports $mode, as configured" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest did not confirm $mode mode"; exit 1; }
  grep -q "^ok    CA certificate: $HOME/.mitmproxy/mitmproxy-ca-cert.pem" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest CA path is not the exec one"; exit 1; }
  grep -q "^ok    CA bundle: $KEYFENCE_HOME/ca-bundle.pem, " "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest did not name the CA bundle it wrote"; exit 1; }
  grep -q "plus $HOME/.mitmproxy/mitmproxy-ca-cert.pem$" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest bundle line does not name the mitmproxy CA"; exit 1; }
  grep -q "BEGIN CERTIFICATE" "$KEYFENCE_HOME/ca-bundle.pem" || { echo "FAILED: the CA bundle has no certificate in it"; exit 1; }
  grep -q "in $mode mode" "$KEYFENCE_HOME/selftest_$mode.txt" || { echo "FAILED: selftest summary missing in $mode mode"; exit 1; }
  echo "OK: selftest passed in $mode mode"
done
grep -q "the listener received \[REDACTED:vault\]" "$KEYFENCE_HOME/selftest_redact.txt" || { echo "FAILED: redact selftest did not see the redaction"; exit 1; }
grep -q "the real value was restored in the response" "$KEYFENCE_HOME/selftest_placeholder.txt" || { echo "FAILED: placeholder selftest did not see the restoration"; exit 1; }
grep -q "HTTP 403 from the proxy, nothing reached the listener" "$KEYFENCE_HOME/selftest_block.txt" || { echo "FAILED: block selftest did not see the 403"; exit 1; }
grep -q "reached the listener unchanged, as audit mode should" "$KEYFENCE_HOME/selftest_audit.txt" || { echo "FAILED: audit selftest did not see the unchanged value"; exit 1; }
[[ "$(wc -l < "$KEYFENCE_HOME/audit.log")" == "$AUDIT_LINES_BEFORE" ]] || { echo "FAILED: selftest wrote to this home's audit log"; exit 1; }
[[ "$(cat "$KEYFENCE_HOME/vault.json")" == "$VAULT_BEFORE" ]] || { echo "FAILED: selftest changed this home's vault"; exit 1; }
echo "OK: this home's vault and audit log are untouched"
printf 'mode: nonsense\n' > "$KEYFENCE_CONFIG"
if python3 -m keyfence selftest > "$KEYFENCE_HOME/selftest_broken.txt"; then echo "FAILED: selftest passed with an invalid config"; exit 1; fi
cat "$KEYFENCE_HOME/selftest_broken.txt"
grep -q "^FAIL  config: .*invalid mode" "$KEYFENCE_HOME/selftest_broken.txt" || { echo "FAILED: selftest did not name the broken config"; exit 1; }
grep -q "NOT protecting traffic: config failed" "$KEYFENCE_HOME/selftest_broken.txt" || { echo "FAILED: selftest summary missing for the broken config"; exit 1; }
echo "OK: selftest exits 1 and names the failed step"
write_config redact

echo
echo "=== proxy log ==="
cat "$KEYFENCE_HOME/proxy.log"

echo
echo "=== audit log ==="
cat "$KEYFENCE_HOME/audit.log"
echo
echo "ALL INTEGRATION TESTS PASSED"
