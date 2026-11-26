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


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\u0085"])
def test_a_legacy_line_with_a_raw_separator_is_read_once(tmp_path, separator):
    key = f"note{separator}x"
    entry = {**ENTRY1, "findings": [{**ENTRY1["findings"][0], "key": key}]}
    line = json.dumps(entry, ensure_ascii=False)
    assert len(line.splitlines()) == 2
    path = tmp_path / "audit.log"
    path.write_text(line + "\n" + json.dumps(ENTRY2) + "\n", encoding="utf-8")
    assert export.count_lines(path) == 2
    entries = list(export.read_entries(path))
    assert [e["host"] for e in entries] == ["api.anthropic.com", "api.openai.com"]
    assert entries[0]["findings"][0]["key"] == key


def test_line_boundary_is_one_newline(tmp_path):
    path = tmp_path / "audit.log"
    assert export.count_lines(path) == 0
    path.write_text("")
    assert export.split_lines("") == []
    assert export.count_lines(path) == 0
    path.write_text(json.dumps(ENTRY1) + "\n")
    assert export.split_lines(path.read_text()) == [json.dumps(ENTRY1)]
    assert export.count_lines(path) == 1
    path.write_text(json.dumps(ENTRY1) + "\n" + json.dumps(ENTRY2))
    assert export.count_lines(path) == 2
    path.write_text(json.dumps(ENTRY1) + "\n\n")
    assert export.split_lines(path.read_text()) == [json.dumps(ENTRY1), ""]
    assert export.count_lines(path) == 2


def test_read_text_decodes_the_log_as_utf8(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text('{"key": "note\u2028x"}\n', encoding="utf-8")
    assert export.read_text(path) == '{"key": "note\u2028x"}\n'


def test_read_text_replaces_bytes_that_are_not_utf8(tmp_path):
    path = tmp_path / "audit.log"
    path.write_bytes(b'{"key": "\xff"}\n')
    assert export.read_text(path) == '{"key": "\ufffd"}\n'


def test_encoded_entry_escapes_non_ascii_and_separators():
    entry = {**ENTRY1, "findings": [{**ENTRY1["findings"][0], "key": "ação\u2028x"}]}
    line = export.encode_entry(entry)
    assert line.endswith("\n") and len(line.splitlines()) == 1
    assert line.isascii() and "\\u2028" in line
    assert json.loads(line) == entry


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
    assert export.read_cursor(cursor) == (0, 0)
    export.write_cursor(cursor, 2, 1234)
    assert export.read_cursor(cursor) == (2, 1234)
    # A cursor written by the older, timestamp-based version.
    cursor.write_text("2026-09-08T11:00:00-0300")
    assert export.read_cursor(cursor) == (0, 0)
    cursor.write_text("garbage")
    assert export.read_cursor(cursor) == (0, 0)
    cursor.write_text("-5")
    assert export.read_cursor(cursor) == (0, 0)


def test_entries_in_the_same_second_each_export_once(tmp_path):
    second = {**ENTRY1, "host": "api.openai.com", "path": "/v1/responses"}
    log = tmp_path / "audit.log"
    cursor = tmp_path / "export.cursor"
    log.write_text(json.dumps(ENTRY1) + "\n")
    stop = export.count_lines(log)
    first = list(export.read_entries(log, start=export.read_cursor(cursor)[0], stop=stop))
    export.write_cursor(cursor, stop, export.log_identity(log))
    assert [e["host"] for e in first] == ["api.anthropic.com"]

    with log.open("a") as fh:   # same ts, written after the first run
        fh.write(json.dumps(second) + "\n")
    stop = export.count_lines(log)
    rest = list(export.read_entries(log, start=export.read_cursor(cursor)[0], stop=stop))
    assert [e["path"] for e in rest] == ["/v1/responses"]


def test_websocket_entries_carry_the_flag():
    record = export.to_log_record({"ts": "2026-01-01T00:00:00+0000", "host": "api.openai.com",
                                   "path": "/v1/realtime", "mode": "redact", "count": 1,
                                   "findings": [{"kind": "vault"}], "websocket": True})
    attrs = {a["key"]: a["value"] for a in record["attributes"]}
    assert attrs["keyfence.websocket"] == {"boolValue": True}
