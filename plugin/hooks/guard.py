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
_PATH_TOKEN = re.compile(r"""(?<![\w-])(?:~|\.{0,2}/)?[\w.~/@-]*(?:\.env(?:\.\w+)?|\.pem|\.key|\.p12|\.pfx|\.jks|\.ppk|\.kdbx|\.tfvars|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials(?:\.\w+)?|id_rsa|id_ed25519|id_ecdsa|\.ssh/[\w.-]+|\.aws/credentials|\.docker/config\.json|\.kube/config)(?![\w-])""", re.IGNORECASE)
_START = r"(?:^|[;&|(`])\s*"
_DUMP_COMMANDS = re.compile(
    _START + r"(?:env|printenv|export(?:\s+-p)?|set|declare\s+-x|typeset\s+-x)\s*(?:$|[;&|)>`])",
    re.MULTILINE)
_SECRET_VAR = r"[A-Za-z_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z_]*"
_NAMED_DUMP = re.compile(
    _START + r"printenv\s+" + _SECRET_VAR + r"\b|/proc/(?:self|\d+)/environ", re.IGNORECASE | re.MULTILINE)
_SECRET_COMMANDS = re.compile(
    _START + r"(?:"
    r"aws\s+secretsmanager\s+get-secret-value|aws\s+ssm\s+get-parameters?\b.*--with-decryption|"
    r"aws\s+configure\s+get\s+\S*(?:secret|token|key)|"
    r"op\s+read|op\s+item\s+get\b(?=.*(?:--reveal|--format[= ]json|--fields))|"
    r"vault\s+(?:kv\s+get|read)|doppler\s+secrets(?:\s+(?:download|get))?|"
    r"kubectl\s+get\s+secrets?\b(?=.*(?:-o|--output)[\s=]*(?:yaml|json|jsonpath|go-template))|"
    r"kubectl\s+config\s+view\b(?=.*--raw)|"
    r"gcloud\s+secrets\s+versions\s+access|gcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token|"
    r"az\s+keyvault\s+secret\s+show|az\s+account\s+get-access-token|"
    r"gh\s+auth\s+token|heroku\s+config(?::get)?|infisical\s+(?:secrets|export)|bw\s+get"
    r")\b", re.IGNORECASE | re.MULTILINE)
HOOK_COMMAND = "keyfence hook claude-code"
HOOK_MATCHER = "Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Bash"
DENY_RULES = (
    "Read(./.env)", "Read(./.env.*)", "Read(./**/.env)", "Read(./**/.env.*)", "Read(./**/*.pem)",
    "Read(./**/*.key)", "Read(./**/credentials*)", "Read(./**/secrets.*)", "Read(./**/*.tfvars)",
    "Read(~/.aws/credentials)", "Read(~/.ssh/**)", "Read(~/.netrc)", "Read(~/.npmrc)",
    "Read(~/.pypirc)", "Read(~/.git-credentials)", "Read(~/.docker/config.json)", "Read(~/.kube/config)",
)


def is_sensitive(path: str) -> bool:
    posix = PurePosixPath(path.replace("\\", "/").lower())
    name = posix.name
    if any(fnmatch.fnmatch(name, pattern) for pattern in SAFE_NAMES):
        return False
    if any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_NAMES):
        return True
    return any(fnmatch.fnmatch(str(posix), pattern) for pattern in SENSITIVE_PATHS)


def paths_in_command(command: str) -> list[str]:
    return [m.group() for m in _PATH_TOKEN.finditer(command)]


def dumps_secrets(command: str) -> str | None:
    if _DUMP_COMMANDS.search(command) or _NAMED_DUMP.search(command):
        return "it prints environment variables that hold the secrets keyfence protects"
    m = _SECRET_COMMANDS.search(command)
    if m:
        return f"`{m.group().strip(' ;&|(`')}` prints secret values"
    return None


def decide(payload: dict) -> str | None:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if path and is_sensitive(path):
            return _reason(path)
        return None
    if tool == "Grep":
        for value in (tool_input.get("path") or "", tool_input.get("glob") or ""):
            if value and is_sensitive(value):
                return _reason(value)
        return None
    if tool == "Bash":
        command = tool_input.get("command") or ""
        for path in paths_in_command(command):
            if is_sensitive(path):
                return _reason(path)
        why = dumps_secrets(command)
        if why:
            return (f"keyfence blocked this command: {why}. Secrets must not enter the model "
                    "context. Ask the user to run it themselves if the output is needed.")
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


def _added_rules_path(path: Path) -> Path:
    return path.with_name("keyfence-deny-rules.json")


def _added_rules(path: Path) -> list[str]:
    record = _added_rules_path(path)
    if not record.exists():
        return list(DENY_RULES)
    try:
        return list(json.loads(record.read_text()))
    except ValueError:
        return list(DENY_RULES)


def install(path: Path) -> bool:
    data = json.loads(path.read_text()) if path.exists() else {}
    pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    deny = data.setdefault("permissions", {}).setdefault("deny", [])
    changed = False
    if not any(_is_ours(e) for e in pre):
        pre.append({
            "matcher": HOOK_MATCHER,
            "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 10}],
        })
        changed = True
    missing = [rule for rule in DENY_RULES if rule not in deny]
    if missing:
        deny.extend(missing)
        changed = True
        path.parent.mkdir(parents=True, exist_ok=True)
        record = _added_rules_path(path)
        previous = _added_rules(path) if record.exists() else []
        record.write_text(json.dumps(sorted(set(previous) | set(missing)), indent=2) + "\n")
    if not changed:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return True


def uninstall(path: Path) -> bool:
    if not path.exists():
        return False
    data = json.loads(path.read_text())
    pre = data.get("hooks", {}).get("PreToolUse", [])
    kept = [e for e in pre if not _is_ours(e)]
    deny = data.get("permissions", {}).get("deny", [])
    ours = set(_added_rules(path))
    kept_deny = [rule for rule in deny if rule not in ours]
    _added_rules_path(path).unlink(missing_ok=True)
    if len(kept) == len(pre) and len(kept_deny) == len(deny):
        return False
    if "hooks" in data:
        data["hooks"]["PreToolUse"] = kept
        if not kept:
            del data["hooks"]["PreToolUse"]
        if not data["hooks"]:
            del data["hooks"]
    if "permissions" in data:
        data["permissions"]["deny"] = kept_deny
        if not kept_deny:
            del data["permissions"]["deny"]
        if not data["permissions"]:
            del data["permissions"]
    path.write_text(json.dumps(data, indent=2) + "\n")
    return True


if __name__ == "__main__":
    sys.exit(run_hook())
