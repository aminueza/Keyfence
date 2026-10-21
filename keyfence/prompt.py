from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

from .config import Config
from .detectors import Finding, ScanReport, scan_report
from .vault import Vault, VaultError

AUDIT_PREVIEW_LIMIT = 50


def _audit_finding(f: Finding, canary_label: str | None) -> dict:
    entry = {"kind": f.kind, "preview": f.masked, "key": f.key}
    if f.kind == "canary" and canary_label:
        entry["label"] = canary_label
    return entry


def _write_audit_entry(
    config: Config,
    vault: Vault,
    findings: list[Finding],
    suppressed: int = 0,
    stderr=None,
) -> None:
    try:
        path = Path(config.audit_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "host": "claude-code:prompt",
            "path": "",
            "mode": config.mode,
            "count": len(findings),
            "findings": [
                _audit_finding(f, vault.canary_label(f.value))
                for f in findings[:AUDIT_PREVIEW_LIMIT]
            ],
        }
        if suppressed:
            entry["suppressed"] = suppressed
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a") as fh:
            os.chmod(path, 0o600)
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        if stderr:
            print(f"keyfence: could not write audit log: {exc}", file=stderr)


def _block_reply(findings: list[Finding]) -> str:
    reason_parts = [f"[{f.kind}] {f.masked}" for f in findings]
    reason = (
        f"keyfence blocked this prompt: {', '.join(reason_parts)}. "
        "The prompt was not sent to the model. "
        "The text is still on disk in Claude Code's transcript and prompt history, "
        "so the secret(s) should be rotated now."
    )
    return json.dumps(
        {
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "suppressOriginalPrompt": True,
            },
        },
        ensure_ascii=False,
    )


def run(stdin=None, stderr=None) -> int:
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    try:
        text = stdin.read()
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            print("keyfence blocked this prompt because it could not read the input: stdin must hold one JSON object.", file=stderr)
            return 2

        prompt = payload.get("prompt", "")
        if not prompt:
            return 0

        try:
            cfg = Config.load()
            vault = Vault()
        except (ValueError, VaultError) as exc:
            reason = f"keyfence blocked this prompt because its configuration failed to load: {exc}"
            print(json.dumps({"decision": "block", "reason": reason, "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}, ensure_ascii=False))
            return 0

        ignore = cfg.ignore_list(vault)
        report: ScanReport = scan_report(prompt, vault=vault, config=cfg.scan, ignore=ignore)
        findings = report.findings

        if not findings:
            return 0

        if cfg.mode == "audit":
            _write_audit_entry(cfg, vault, findings, report.suppressed, stderr)
            return 0

        if cfg.mode in ("redact", "placeholder", "block"):
            print(_block_reply(findings))
            return 0

        return 0
    except BaseException as exc:
        reason = f"keyfence blocked this prompt because its guard crashed: {type(exc).__name__}"
        print(json.dumps({"decision": "block", "reason": reason, "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(run())