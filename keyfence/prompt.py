from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from .config import Config
from .detectors import Finding, scan_report
from .vault import Vault, VaultError

AUDIT_PREVIEW_LIMIT = 50
REASON_FINDING_LIMIT = 5


def _block(reason: str) -> int:
    print(json.dumps({"decision": "block", "reason": reason,
                      "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                             "suppressOriginalPrompt": True}}))
    return 0


def _audit_finding(f: Finding, canary_label: str | None) -> dict:
    entry = {"kind": f.kind, "preview": f.masked, "key": f.key}
    if f.kind == "canary" and canary_label:
        entry["label"] = canary_label
    return entry


def _write_audit_entry(config: Config, vault: Vault, findings: list[Finding],
                       suppressed: int, stderr) -> None:
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
        print(f"keyfence: could not write audit log: {exc}", file=stderr)


def _block_reason(findings: list[Finding]) -> str:
    shown = findings[:REASON_FINDING_LIMIT]
    listed = ", ".join(f"[{f.kind}] {f.masked}" for f in shown)
    if len(findings) > len(shown):
        listed += f", and {len(findings) - len(shown)} more"
    return (f"keyfence blocked this prompt: it carries what looks like a secret ({listed}). "
            "The prompt was not sent to the model. "
            "The text is still on disk in Claude Code's transcript and prompt history, "
            "so the secret(s) should be rotated now. "
            "If this is a false positive, register the value in ignore_values in the keyfence config.")


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
            return _block(f"keyfence blocked this prompt because its configuration failed to load: {exc}")

        ignore = cfg.ignore_list(vault)
        report = scan_report(prompt, vault=vault, config=cfg.scan, ignore=ignore)
        findings = report.findings

        if not findings:
            return 0

        # the proxy logs findings in every mode; a blocked prompt leaves the
        # same trace, so a canary pasted into a prompt is visible in status
        _write_audit_entry(cfg, vault, findings, report.suppressed, stderr)
        if cfg.mode == "audit":
            return 0

        return _block(_block_reason(findings))
    except BaseException as exc:
        return _block(f"keyfence blocked this prompt because its guard crashed: {type(exc).__name__}")


if __name__ == "__main__":
    sys.exit(run())
