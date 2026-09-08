import io
import json

import pytest

from keyfence import hooks


@pytest.mark.parametrize("path", [
    "/work/.env", ".env.local", "/work/prod.env", "/home/u/.envrc", "/etc/ssl/server.pem",
    "/home/u/.ssh/id_ed25519", "/home/u/.ssh/known_hosts", "/home/u/.aws/credentials",
    "/home/u/.docker/config.json", "/work/credentials.json", "/work/gcp-credentials.json",
    "/work/secrets.yaml", "/work/terraform.tfvars", "C:\\Users\\u\\.netrc", "/work/service-account-prod.json",
])
def test_sensitive_paths(path):
    assert hooks.is_sensitive(path)


@pytest.mark.parametrize("path", [
    "/work/.env.example", "/work/README.md", "/work/src/main.py", "/home/u/.ssh/id_rsa.pub",
    "/work/environment.md", "/work/keys/index.ts", "/work/config.json",
])
def test_safe_paths(path):
    assert not hooks.is_sensitive(path)


def test_paths_in_command():
    cmd = "cat .env && cp ~/.aws/credentials /tmp/x && grep TOKEN ../secrets/prod.env | head; ls ~/.ssh/id_rsa"
    found = hooks.paths_in_command(cmd)
    assert ".env" in found and "~/.aws/credentials" in found and "../secrets/prod.env" in found
    assert "~/.ssh/id_rsa" in found


def test_decide_file_tools_and_bash():
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": "/w/.env"}})
    assert hooks.decide({"tool_name": "Edit", "tool_input": {"file_path": "/w/server.key"}})
    assert hooks.decide({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/w/analysis.ipynb"}}) is None
    assert hooks.decide({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/w/secrets.ipynb"}})
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": "/w/app.py"}}) is None
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": "cat .env"}})
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}) is None
    assert hooks.decide({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": ".env"}}) is None
    assert hooks.decide({"tool_name": "Read"}) is None


def test_run_hook_exit_codes():
    err = io.StringIO()
    blocked = hooks.run_hook(io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": ".env"}})), err)
    assert blocked == 2 and "keyfence blocked" in err.getvalue()
    assert hooks.run_hook(io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "a.py"}})), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO("not json"), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO("[1]"), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO(""), io.StringIO()) == 0


def test_install_and_uninstall_merge_with_existing_settings(tmp_path):
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}}))
    assert hooks.install(path)
    assert not hooks.install(path)
    data = json.loads(path.read_text())
    assert data["model"] == "opus"
    assert len(data["hooks"]["PreToolUse"]) == 2
    assert data["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == hooks.HOOK_COMMAND
    assert hooks.uninstall(path)
    assert not hooks.uninstall(path)
    data = json.loads(path.read_text())
    assert len(data["hooks"]["PreToolUse"]) == 1


def test_install_creates_file_and_uninstall_cleans_empty_sections(tmp_path):
    path = tmp_path / "settings.json"
    assert hooks.install(path)
    assert hooks.uninstall(path)
    assert json.loads(path.read_text()) == {}
    assert not hooks.uninstall(tmp_path / "missing.json")


def test_settings_path(tmp_path, monkeypatch):
    monkeypatch.setattr(hooks.Path, "home", classmethod(lambda cls: tmp_path))
    assert hooks.settings_path(project=False) == tmp_path / ".claude" / "settings.json"
    assert hooks.settings_path(project=True, cwd=tmp_path / "proj") == tmp_path / "proj" / ".claude" / "settings.json"
