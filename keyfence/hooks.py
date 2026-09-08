from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path, PurePosixPath

SENSITIVE_NAMES = (
    ".env", ".env.*", "*.env", ".envrc", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "*.keystore", "*.ppk", "*.kdbx", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials",
    "credentials.*", "*credentials.json", "*-credentials.*", "secrets.*", "*.secret",
    "*.secrets", "*.tfvars", "service-account*.json", "kubeconfig", "*.kubeconfig",
)
SENSITIVE_PATHS = (
    "*/.aws/credentials", "*/.docker/config.json", "*/.ssh/*", "*/.kube/config",
    "*/.config/gcloud/*credentials*", "*/.gnupg/*",
)
SAFE_NAMES = (".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub")
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
_PATH_TOKEN = re.compile(r"""(?<![\w-])(?:~|\.{0,2}/)?[\w.~/@-]*(?:\.env(?:\.\w+)?|\.pem|\.key|\.p12|\.pfx|\.jks|\.ppk|\.kdbx|\.tfvars|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials(?:\.\w+)?|id_rsa|id_ed25519|id_ecdsa|\.ssh/[\w.-]+|\.aws/credentials|\.docker/config\.json|\.kube/config)(?![\w-])""")
HOOK_COMMAND = "keyfence hook claude-code"
HOOK_MATCHER = "Read|Edit|Write|MultiEdit|NotebookEdit|Bash"


def is_sensitive(path: str) -> bool:
    posix = PurePosixPath(path.replace("\\", "/"))
    name = posix.name
    if any(fnmatch.fnmatch(name, pattern) for pattern in SAFE_NAMES):
        return False
    if any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_NAMES):
        return True
    return any(fnmatch.fnmatch(str(posix), pattern) for pattern in SENSITIVE_PATHS)


def paths_in_command(command: str) -> list[str]:
    return [m.group() for m in _PATH_TOKEN.finditer(command)]


def decide(payload: dict) -> str | None:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if path and is_sensitive(path):
            return _reason(path)
        return None
    if tool == "Bash":
        for path in paths_in_command(tool_input.get("command") or ""):
            if is_sensitive(path):
                return _reason(path)
    return None


def _reason(path: str) -> str:
    return (f"keyfence blocked access to {path}: files like this hold secrets and must not "
            "enter the model context. If you need a value from it, ask the user to run the "
            "command themselves, or have them register it with `keyfence import` so it is "
            "protected in transit.")


def run_hook(stdin=None, stderr=None) -> int:
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    try:
        payload = json.loads(stdin.read() or "{}")
    except ValueError:
        return 0
    reason = decide(payload if isinstance(payload, dict) else {})
    if reason:
        print(reason, file=stderr)
        return 2
    return 0


def settings_path(project: bool, cwd: Path | None = None) -> Path:
    base = (cwd or Path.cwd()) / ".claude" if project else Path.home() / ".claude"
    return base / "settings.json"


def _is_ours(entry: dict) -> bool:
    return any(HOOK_COMMAND in str(h.get("command", "")) for h in entry.get("hooks", []))


def install(path: Path) -> bool:
    data = json.loads(path.read_text()) if path.exists() else {}
    pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if any(_is_ours(e) for e in pre):
        return False
    pre.append({
        "matcher": HOOK_MATCHER,
        "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 10}],
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return True


def uninstall(path: Path) -> bool:
    if not path.exists():
        return False
    data = json.loads(path.read_text())
    pre = data.get("hooks", {}).get("PreToolUse", [])
    kept = [e for e in pre if not _is_ours(e)]
    if len(kept) == len(pre):
        return False
    data["hooks"]["PreToolUse"] = kept
    if not kept:
        del data["hooks"]["PreToolUse"]
    if not data["hooks"]:
        del data["hooks"]
    path.write_text(json.dumps(data, indent=2) + "\n")
    return True
