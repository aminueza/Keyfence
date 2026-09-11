from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable

SOURCES = ("op", "vault", "doppler", "aws")


class SourceError(RuntimeError):
    pass


def _run(command: list[str]) -> str:
    if shutil.which(command[0]) is None:
        raise SourceError(f"{command[0]} is not installed or not on PATH")
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"{command[0]} failed: {exc}") from None
    if done.returncode != 0:
        raise SourceError(f"{' '.join(command[:3])} exited with {done.returncode}: {done.stderr.strip()[:200]}")
    return done.stdout


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


OP_CATEGORIES = "API Credential,Login,Password,Secure Note,Database,Server"


def from_op(path: str | None, run: Callable = _run) -> list[str]:
    command = ["op", "item", "list", "--format", "json", "--categories", OP_CATEGORIES]
    if path:
        command += ["--vault", path]
    items = json.loads(run(command) or "[]")
    values: list[str] = []
    for item in items:
        detail = json.loads(run(["op", "item", "get", item["id"], "--format", "json", "--reveal"]) or "{}")
        for field in detail.get("fields", []):
            if field.get("type") == "CONCEALED" and field.get("value"):
                values.append(field["value"])
    return values


def from_vault(path: str | None, run: Callable = _run) -> list[str]:
    if not path:
        raise SourceError("--path is required for vault, e.g. --path secret/myapp")
    data = json.loads(run(["vault", "kv", "get", "-format=json", path]) or "{}").get("data", {})
    if isinstance(data.get("data"), dict):
        data = data["data"]
    return _strings(data)


def from_doppler(path: str | None, run: Callable = _run) -> list[str]:
    command = ["doppler", "secrets", "download", "--no-file", "--format", "json"]
    if path:
        project, _, config = path.partition("/")
        command += ["--project", project]
        if config:
            command += ["--config", config]
    return _strings(json.loads(run(command) or "{}"))


def from_aws(path: str | None, run: Callable = _run) -> list[str]:
    if not path:
        raise SourceError("--path is required for aws, e.g. --path prod/db")
    raw = run(["aws", "secretsmanager", "get-secret-value", "--secret-id", path,
               "--query", "SecretString", "--output", "text"]).strip()
    try:
        return _strings(json.loads(raw))
    except ValueError:
        return [raw] if raw else []


FETCHERS = {"op": from_op, "vault": from_vault, "doppler": from_doppler, "aws": from_aws}


def fetch(source: str, path: str | None, run: Callable = _run) -> list[str]:
    try:
        fetcher = FETCHERS[source]
    except KeyError:
        raise SourceError(f"unknown source {source!r}; choose from {', '.join(SOURCES)}") from None
    return fetcher(path, run)
