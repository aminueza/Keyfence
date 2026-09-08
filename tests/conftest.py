import os
import tempfile

os.environ["KEYFENCE_HOME"] = tempfile.mkdtemp(prefix="keyfence-test-home-")
os.environ.pop("KEYFENCE_CONFIG", None)
os.environ.pop("KEYFENCE_ENV_VAULT", None)

import pytest  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr("keyfence.vault.DEFAULT_DIR", tmp_path)
    monkeypatch.setattr("keyfence.config.DEFAULT_DIR", tmp_path)
    monkeypatch.setattr("keyfence.cli.DEFAULT_DIR", tmp_path)
    monkeypatch.setenv("KEYFENCE_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("KEYFENCE_ENV_VAULT", raising=False)
    return tmp_path


@pytest.fixture
def write_config(home):
    def _write(text: str):
        (home / "config.yaml").write_text(text)
        return home / "config.yaml"
    return _write
