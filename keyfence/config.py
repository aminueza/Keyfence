from __future__ import annotations

import fnmatch
import os
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


def _string_list(data: dict, name: str) -> list[str]:
    raw = data.get(name)
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(v, str) and v.strip() for v in raw):
        raise ValueError(f"{name} must be a list of non-empty strings")
    return [v.strip() for v in raw]


@dataclass
class Config:
    mode: str = "redact"
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_AI_HOSTS))
    intercept_all_hosts: bool = False
    notice: bool = True
    scan: ScanConfig = field(default_factory=ScanConfig)
    audit_log: Path = field(default_factory=lambda: DEFAULT_DIR / "audit.log")
    ignore_keys: list[str] = field(default_factory=list)
    ignore_values: list[str] = field(default_factory=list)

    @staticmethod
    def path(path: str | os.PathLike | None = None) -> Path:
        return Path(path or os.environ.get("KEYFENCE_CONFIG", DEFAULT_DIR / "config.yaml"))

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        cfg_path = cls.path(path)
        cfg = cls()
        if cfg_path.exists():
            try:
                data = yaml.safe_load(cfg_path.read_text()) or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"{cfg_path} is not valid YAML: {exc}") from None
            cfg.mode = data.get("mode", cfg.mode)
            if data.get("hosts"):
                cfg.hosts = list(data["hosts"])
            if data.get("extra_hosts"):
                cfg.hosts.extend(data["extra_hosts"])
            cfg.intercept_all_hosts = bool(
                data.get("intercept_all_hosts", cfg.intercept_all_hosts))
            cfg.notice = bool(data.get("notice", cfg.notice))
            scan = data.get("scan") or {}
            cfg.scan = ScanConfig(
                patterns_enabled=scan.get("patterns", True),
                entropy_enabled=scan.get("entropy", True),
                entropy_min_length=scan.get("entropy_min_length", 24),
                entropy_threshold=scan.get("entropy_threshold", 4.5),
                entropy_max_length=scan.get("entropy_max_length", 512),
                allowlist=scan.get("allowlist") or [],
                gitleaks=scan.get("gitleaks", True),
                gitleaks_rules=scan.get("gitleaks_rules"),
                gitleaks_disabled=list(scan.get("gitleaks_disabled", DEFAULT_DISABLED)),
            )
            if data.get("audit_log"):
                cfg.audit_log = Path(data["audit_log"]).expanduser()
            cfg.ignore_keys = _string_list(data, "ignore_keys")
            cfg.ignore_values = _string_list(data, "ignore_values")
        if cfg.mode not in MODES:
            raise ValueError(f"invalid mode: {cfg.mode!r} (expected one of {', '.join(MODES)})")
        if cfg.scan.gitleaks:
            cfg.scan.rules = load_rules(cfg.scan.gitleaks_rules, cfg.scan.gitleaks_disabled)
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
