import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from keyfence import export

ENTRY1 = {"ts": "2026-09-08T10:00:00-0300", "host": "api.anthropic.com", "path": "/v1/messages",
          "mode": "redact", "count": 2, "findings": [{"kind": "vault", "preview": "a", "key": "content"},
                                                     {"kind": "canary", "preview": "b", "key": "content", "label": "/w/.env"}]}
ENTRY2 = {"ts": "2026-09-08T11:00:00-0300", "host": "api.openai.com", "path": "/v1/chat",
          "mode": "block", "findings": [{"kind": "github-token", "preview": "c", "key": None}]}


@pytest.fixture
def audit(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text(json.dumps(ENTRY1) + "\nbroken line\n\n" + json.dumps(ENTRY2) + "\n")
    return path


def test_read_entries_skips_garbage_and_filters_since(audit):
    assert [e["host"] for e in export.read_entries(audit)] == ["api.anthropic.com", "api.openai.com"]
    since = export.parse_ts("2026-09-08T10:00:00-0300")
    assert [e["host"] for e in export.read_entries(audit, since)] == ["api.openai.com"]
    assert list(export.read_entries(audit.parent / "missing.log")) == []


def test_log_record_shape():
    record = export.to_log_record(ENTRY1)
    attrs = {a["key"]: a["value"] for a in record["attributes"]}
    assert record["severityText"] == "ERROR"
    assert attrs["keyfence.kinds"] == {"stringValue": "canary,vault"}
    assert attrs["keyfence.count"] == {"intValue": "2"}
    assert attrs["keyfence.canary"] == {"stringValue": "/w/.env"}
    assert record["timeUnixNano"].endswith("000000000")
    plain = export.to_log_record(ENTRY2)
    assert plain["severityText"] == "WARN"
    assert {a["key"] for a in plain["attributes"]} == {"keyfence.host", "keyfence.path", "keyfence.mode", "keyfence.count", "keyfence.kinds"}


def test_otlp_payload_wraps_records():
    payload = export.otlp_payload([ENTRY1, ENTRY2])
    logs = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(logs) == 2
    assert payload["resourceLogs"][0]["resource"]["attributes"][0] == {"key": "service.name", "value": {"stringValue": "keyfence"}}


class Collector(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Collector.received.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def collector():
    Collector.received = []
    server = HTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_send_otlp_posts_batches_with_headers(collector, monkeypatch):
    monkeypatch.setattr(export, "BATCH", 2)
    entries = [ENTRY1, ENTRY2, ENTRY1]
    sent = export.send_otlp(collector, entries, {"Authorization": "Bearer t"})
    assert sent == 3
    assert [p for p, _, _ in Collector.received] == ["/v1/logs", "/v1/logs"]
    assert Collector.received[0][1]["Authorization"] == "Bearer t"
    assert len(Collector.received[0][2]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]) == 2
    assert export.send_otlp(collector + "/v1/logs", []) == 0


def test_send_otlp_raises_on_error_status():
    class Response:
        status = 500

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    with pytest.raises(RuntimeError):
        export.send_otlp("http://collector", [ENTRY1], opener=lambda request, timeout: Response())


def test_cursor_roundtrip(tmp_path):
    cursor = tmp_path / "export.cursor"
    assert export.read_cursor(cursor) is None
    export.write_cursor(cursor, [])
    assert not cursor.exists()
    export.write_cursor(cursor, [ENTRY1, ENTRY2])
    assert export.read_cursor(cursor) == export.parse_ts(ENTRY2["ts"])
    cursor.write_text("garbage")
    assert export.read_cursor(cursor) is None
