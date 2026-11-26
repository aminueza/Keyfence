from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detectors import ScanConfig
from .ignore import IgnoreList
from .rules import DEFAULT_DISABLED, load_rules
from .vault import DEFAULT_DIR, Vault

DEFAULT_AI_HOSTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.cohere.com",
    "api.together.xyz",
    "api.deepseek.com",
    "api.x.ai",
    "openrouter.ai",
    "api.perplexity.ai",
    "api.fireworks.ai",
    "bedrock-runtime.*.amazonaws.com",
    "*.openai.azure.com",
    "*.services.ai.azure.com",
    "*.cognitiveservices.azure.com",
    "models.inference.ai.azure.com",
    "api.githubcopilot.com",
    "aiplatform.googleapis.com",
    "*-aiplatform.googleapis.com",
]

MODES = ("audit", "block", "redact", "placeholder")


def _string_list(data: dict, name: str, label: str | None = None) -> list[str]:
    raw = data.get(name)
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(v, str) and v.strip() for v in raw):
        raise ValueError(f"{label or name} must be a list of non-empty strings")
    return [v.strip() for v in raw]


def _bool(data: dict, name: str, default: bool, label: str | None = None) -> bool:
    if name not in data:
        return default
    val = data[name]
    if not isinstance(val, bool):
        raise ValueError(f"{label or name} must be a boolean, got {val!r}")
    return val


def _int(data: dict, name: str, default: int, label: str | None = None) -> int:
    if name not in data:
        return default
    val = data[name]
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"{label or name} must be an integer, got {val!r}")
    return val


def _number(data: dict, name: str, default: float, label: str | None = None) -> int | float:
    if name not in data:
        return default
    val = data[name]
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{label or name} must be a number, got {val!r}")
    return val


@dataclass
class Config:
    mode: str = "redact"
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_AI_HOSTS))
    intercept_all_hosts: bool = False
    proxy_tcp_timeout: int = 3600
    notice: bool = True
    scan: ScanConfig = field(default_factory=ScanConfig)
    audit_log: Path = field(default_factory=lambda: DEFAULT_DIR / "audit.log")
    ignore_keys: list[str] = field(default_factory=list)
    ignore_values: list[str] = field(default_factory=list)

    @staticmethod
    def path(path: str | os.PathLike | None = None) -> Path:
        selected = path or os.environ.get("KEYFENCE_CONFIG", "").strip()
        return Path(selected) if selected else DEFAULT_DIR / "config.yaml"

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        cfg_path = cls.path(path)
        cfg = cls()
        if cfg_path.exists():
            try:
                raw_data = yaml.safe_load(cfg_path.read_text())
            except yaml.YAMLError as exc:
                raise ValueError(f"{cfg_path} is not valid YAML: {exc}") from None
            if raw_data is None:
                data = {}
            elif not isinstance(raw_data, dict):
                raise ValueError(
                    f"{cfg_path} must be a YAML mapping, got {type(raw_data).__name__}"
                )
            else:
                data = raw_data
            cfg.mode = data.get("mode", cfg.mode)
            # A single string here used to be iterated into one-character
            # "hosts", which silently stopped monitoring (issue #175).
            hosts = _string_list(data, "hosts")
            if hosts:
                cfg.hosts = hosts
            extra_hosts = _string_list(data, "extra_hosts")
            if extra_hosts:
                cfg.hosts.extend(extra_hosts)
            cfg.intercept_all_hosts = _bool(data, "intercept_all_hosts", cfg.intercept_all_hosts)
            raw_timeout = data.get("proxy_tcp_timeout")
            if raw_timeout is not None:
                if (isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int)
                        or raw_timeout <= 0):
                    raise ValueError(
                        f"proxy_tcp_timeout must be a positive integer, got {raw_timeout!r}")
                cfg.proxy_tcp_timeout = raw_timeout
            cfg.notice = _bool(data, "notice", cfg.notice)
            raw_scan = data.get("scan")
            if raw_scan is None:
                scan = {}
            elif not isinstance(raw_scan, dict):
                raise ValueError(f"scan must be a mapping, got {raw_scan!r}")
            else:
                scan = raw_scan
            raw_gitleaks_rules = scan.get("gitleaks_rules")
            if raw_gitleaks_rules is not None and (
                not isinstance(raw_gitleaks_rules, str) or not raw_gitleaks_rules.strip()
            ):
                raise ValueError(
                    f"scan.gitleaks_rules must be a non-empty string path, got {raw_gitleaks_rules!r}"
                )
            if raw_gitleaks_rules is not None:
                rules_path = Path(raw_gitleaks_rules).expanduser()
                if not rules_path.is_absolute():
                    rules_path = cfg_path.parent / rules_path
                raw_gitleaks_rules = str(rules_path)
            gitleaks_disabled = (
                _string_list(scan, "gitleaks_disabled", label="scan.gitleaks_disabled")
                if "gitleaks_disabled" in scan
                else list(DEFAULT_DISABLED)
            )
            cfg.scan = ScanConfig(
                patterns_enabled=_bool(scan, "patterns", True, "scan.patterns"),
                entropy_enabled=_bool(scan, "entropy", True, "scan.entropy"),
                entropy_min_length=_int(scan, "entropy_min_length", 24, "scan.entropy_min_length"),
                entropy_threshold=_number(scan, "entropy_threshold", 4.5, "scan.entropy_threshold"),
                entropy_max_length=_int(scan, "entropy_max_length", 512, "scan.entropy_max_length"),
                allowlist=_string_list(scan, "allowlist", label="scan.allowlist"),
                gitleaks=_bool(scan, "gitleaks", True, "scan.gitleaks"),
                gitleaks_rules=raw_gitleaks_rules,
                gitleaks_disabled=gitleaks_disabled,
            )
            raw_audit_log = data.get("audit_log")
            if raw_audit_log is not None:
                if not isinstance(raw_audit_log, str) or not raw_audit_log.strip():
                    raise ValueError(f"audit_log must be a non-empty string path, got {raw_audit_log!r}")
                cfg.audit_log = Path(raw_audit_log).expanduser()
            cfg.ignore_keys = _string_list(data, "ignore_keys")
            cfg.ignore_values = _string_list(data, "ignore_values")
        if cfg.mode not in MODES:
            raise ValueError(f"invalid mode: {cfg.mode!r} (expected one of {', '.join(MODES)})")
        if cfg.scan.gitleaks:
            try:
                cfg.scan.rules = load_rules(cfg.scan.gitleaks_rules, cfg.scan.gitleaks_disabled)
            except OSError as exc:
                if cfg.scan.gitleaks_rules is None:
                    raise
                raise ValueError(
                    f"scan.gitleaks_rules: cannot read {cfg.scan.gitleaks_rules}: "
                    f"{exc.strerror or exc}") from None
            except tomllib.TOMLDecodeError as exc:
                if cfg.scan.gitleaks_rules is None:
                    raise
                raise ValueError(
                    f"scan.gitleaks_rules: {cfg.scan.gitleaks_rules} is not valid TOML: "
                    f"{exc}") from None
        return cfg

    def ignore_list(self, vault: Vault) -> IgnoreList:
        return IgnoreList(vault.salt, self.ignore_keys, self.ignore_values)

    def host_matches(self, host: str) -> bool:
        if self.intercept_all_hosts:
            return True
        host = host.lower()
        for pattern in self.hosts:
            p = pattern.lower()
            if "*" in p:
                if fnmatch.fnmatch(host, p):
                    return True
            elif host == p or host.endswith("." + p):
                return True
        return False
