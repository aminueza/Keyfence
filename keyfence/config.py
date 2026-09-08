from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detectors import ScanConfig
from .rules import load_rules
from .vault import DEFAULT_DIR

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
]

MODES = ("block", "redact", "placeholder")


@dataclass
class Config:
    mode: str = "redact"
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_AI_HOSTS))
    intercept_all_hosts: bool = False
    scan: ScanConfig = field(default_factory=ScanConfig)
    audit_log: Path = field(default_factory=lambda: DEFAULT_DIR / "audit.log")

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        cfg_path = Path(
            path
            or os.environ.get("KEYFENCE_CONFIG", DEFAULT_DIR / "config.yaml"))
        cfg = cls()
        if cfg_path.exists():
            data = yaml.safe_load(cfg_path.read_text()) or {}
            cfg.mode = data.get("mode", cfg.mode)
            if data.get("hosts"):
                cfg.hosts = list(data["hosts"])
            if data.get("extra_hosts"):
                cfg.hosts.extend(data["extra_hosts"])
            cfg.intercept_all_hosts = bool(
                data.get("intercept_all_hosts", cfg.intercept_all_hosts))
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
            )
            if data.get("audit_log"):
                cfg.audit_log = Path(data["audit_log"]).expanduser()
        if cfg.mode not in MODES:
            raise ValueError(f"invalid mode: {cfg.mode!r} (expected one of {', '.join(MODES)})")
        if cfg.scan.gitleaks:
            cfg.scan.rules = load_rules(cfg.scan.gitleaks_rules)
        return cfg

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
