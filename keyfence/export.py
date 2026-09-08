from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

TS_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
BATCH = 100


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, TS_FORMAT)


def read_entries(path: Path, since: datetime | None = None) -> Iterator[dict]:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if since is not None and parse_ts(entry["ts"]) <= since:
            continue
        yield entry


def _attr(key: str, value) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def to_log_record(entry: dict) -> dict:
    ts = parse_ts(entry["ts"])
    kinds = sorted({f["kind"] for f in entry.get("findings", [])})
    labels = sorted({f["label"] for f in entry.get("findings", []) if f.get("label")})
    attributes = [
        _attr("keyfence.host", entry.get("host", "")),
        _attr("keyfence.path", entry.get("path", "")),
        _attr("keyfence.mode", entry.get("mode", "")),
        _attr("keyfence.count", int(entry.get("count", len(entry.get("findings", []))))),
        _attr("keyfence.kinds", ",".join(kinds)),
    ]
    if labels:
        attributes.append(_attr("keyfence.canary", ",".join(labels)))
    severity = "ERROR" if "canary" in kinds else "WARN"
    return {
        "timeUnixNano": str(int(ts.timestamp() * 1_000_000_000)),
        "severityText": severity,
        "body": {"stringValue": f"keyfence: {len(kinds)} kind(s) of secret in request to {entry.get('host', '')}"},
        "attributes": attributes,
    }


def otlp_payload(entries: Iterable[dict]) -> dict:
    return {
        "resourceLogs": [{
            "resource": {"attributes": [_attr("service.name", "keyfence")]},
            "scopeLogs": [{
                "scope": {"name": "keyfence"},
                "logRecords": [to_log_record(e) for e in entries],
            }],
        }],
    }


def send_otlp(endpoint: str, entries: list[dict], headers: dict[str, str] | None = None,
              opener=urllib.request.urlopen) -> int:
    url = endpoint.rstrip("/")
    if not url.endswith("/v1/logs"):
        url += "/v1/logs"
    sent = 0
    for i in range(0, len(entries), BATCH):
        batch = entries[i:i + BATCH]
        body = json.dumps(otlp_payload(batch)).encode()
        request = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json", **(headers or {})})
        with opener(request, timeout=30) as response:
            if response.status >= 300:
                raise RuntimeError(f"collector answered {response.status}")
        sent += len(batch)
    return sent


def read_cursor(path: Path) -> datetime | None:
    if not path.exists():
        return None
    try:
        return parse_ts(path.read_text().strip())
    except ValueError:
        return None


def write_cursor(path: Path, entries: list[dict]) -> None:
    if entries:
        path.write_text(entries[-1]["ts"] + "\n")
