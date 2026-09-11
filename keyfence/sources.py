from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable

SOURCES = ("op", "vault", "doppler", "aws")
OP_CATEGORIES = "API Credential,Login,Password,Secure Note,Database,Server"
Pair = tuple[str, str]


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


def _json(text: str, what: str):
    try:
        return json.loads(text or "null")
    except ValueError:
        raise SourceError(f"{what} did not return JSON; check that the CLI is logged in and up to date") from None


def _pairs(obj, key: str = "") -> list[Pair]:
    if isinstance(obj, str):
        return [(key, obj)] if obj else []
    if isinstance(obj, dict):
        return [p for k, v in obj.items() for p in _pairs(v, str(k))]
    if isinstance(obj, list):
        return [p for v in obj for p in _pairs(v, key)]
    return []


def from_op(path: str | None, run: Callable = _run) -> list[Pair]:
    command = ["op", "item", "list", "--format", "json", "--categories", OP_CATEGORIES]
    if path:
        command += ["--vault", path]
    items = _json(run(command), "op item list") or []
    pairs: list[Pair] = []
    for item in items:
        detail = _json(run(["op", "item", "get", item["id"], "--format", "json", "--reveal"]), "op item get") or {}
        for field in detail.get("fields", []):
            if field.get("type") == "CONCEALED" and field.get("value"):
                pairs.append(("password", field["value"]))
    return pairs


def from_vault(path: str | None, run: Callable = _run) -> list[Pair]:
    if not path:
        raise SourceError("--path is required for vault, e.g. --path secret/myapp")
    data = (_json(run(["vault", "kv", "get", "-format=json", path]), "vault kv get") or {}).get("data", {})
    if isinstance(data.get("data"), dict):
        data = data["data"]
    return _pairs(data)


def from_doppler(path: str | None, run: Callable = _run) -> list[Pair]:
    command = ["doppler", "secrets", "download", "--no-file", "--format", "json"]
    if path:
        project, _, config = path.partition("/")
        command += ["--project", project]
        if config:
            command += ["--config", config]
    return _pairs(_json(run(command), "doppler secrets download") or {})


def from_aws(path: str | None, run: Callable = _run) -> list[Pair]:
    if not path:
        raise SourceError("--path is required for aws, e.g. --path prod/db")
    raw = run(["aws", "secretsmanager", "get-secret-value", "--secret-id", path,
               "--query", "SecretString", "--output", "text"]).strip()
    try:
        parsed = json.loads(raw)
    except ValueError:
        return [("secret", raw)] if raw else []
    return _pairs(parsed, "secret") if isinstance(parsed, (dict, list)) else [("secret", raw)]


FETCHERS = {"op": from_op, "vault": from_vault, "doppler": from_doppler, "aws": from_aws}


def fetch(source: str, path: str | None, run: Callable = _run) -> list[Pair]:
    try:
        fetcher = FETCHERS[source]
    except KeyError:
        raise SourceError(f"unknown source {source!r}; choose from {', '.join(SOURCES)}") from None
    return fetcher(path, run)
