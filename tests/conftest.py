import os
import sys
import tempfile
from types import SimpleNamespace

os.environ["KEYFENCE_HOME"] = tempfile.mkdtemp(prefix="keyfence-test-home-")
os.environ.pop("KEYFENCE_CONFIG", None)
os.environ.pop("KEYFENCE_ENV_VAULT", None)

import pytest  # noqa: E402
from keyfence import doctor  # noqa: E402

CLAUDE_DOCTOR = doctor.claude_doctor
CLAUDE_DOCTOR_CLEAN = "Claude Code doctor\n\nRunning: package-manager (2.1.311)\n\nNo installation issues found.\n"


@pytest.fixture(autouse=True)
def no_real_claude(monkeypatch):
    monkeypatch.setattr(doctor, "claude_doctor", lambda cwd=None: (0, CLAUDE_DOCTOR_CLEAN))


@pytest.fixture
def claude_doctor():
    return CLAUDE_DOCTOR


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr("keyfence.vault.DEFAULT_DIR", tmp_path)
    monkeypatch.setattr("keyfence.config.DEFAULT_DIR", tmp_path)
    monkeypatch.setattr("keyfence.cli.DEFAULT_DIR", tmp_path)
    monkeypatch.setattr("keyfence.runner.DEFAULT_DIR", tmp_path)
    monkeypatch.setenv("KEYFENCE_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("KEYFENCE_ENV_VAULT", raising=False)
    return tmp_path


@pytest.fixture
def write_config(home):
    def _write(text: str):
        (home / "config.yaml").write_text(text)
        return home / "config.yaml"
    return _write


@pytest.fixture
def only_roots(monkeypatch):
    def _only(cafile=None, paths=()):
        monkeypatch.setitem(sys.modules, "certifi", None)
        monkeypatch.setattr("keyfence.runner.ssl.get_default_verify_paths",
                            lambda: SimpleNamespace(cafile=str(cafile) if cafile else None, capath=None))
        monkeypatch.setattr("keyfence.runner.SYSTEM_CA_PATHS", tuple(paths))
    return _only
