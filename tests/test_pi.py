import json
import subprocess
import sys

import pytest

from keyfence import cli, hooks, pi


@pytest.mark.parametrize("payload", [
    {"tool_name": "read", "tool_input": {"path": "/w/.env"}},
    {"tool_name": "write", "tool_input": {"path": "/w/.env.local", "content": "x"}},
    {"tool_name": "edit", "tool_input": {"path": "/w/server.key", "edits": []}},
    {"tool_name": "grep", "tool_input": {"pattern": "TOKEN", "path": "/w/.env"}},
    {"tool_name": "grep", "tool_input": {"pattern": "x", "glob": "*.pem"}},
    {"tool_name": "bash", "tool_input": {"command": "cat .env"}},
    {"tool_name": "bash", "tool_input": {"command": "printenv AWS_SECRET_ACCESS_KEY"}},
    {"tool_name": "powershell", "tool_input": {"command": "gh auth token"}},
])
def test_pi_tool_calls_that_expose_secrets_are_blocked(payload):
    assert "keyfence blocked" in hooks.decide(payload)


@pytest.mark.parametrize("payload", [
    {"tool_name": "read", "tool_input": {"path": "/w/app.py"}},
    {"tool_name": "read", "tool_input": {"path": "/w/.env.example"}},
    {"tool_name": "grep", "tool_input": {"pattern": "x", "path": "/w/src"}},
    {"tool_name": "bash", "tool_input": {"command": "pytest -q"}},
    {"tool_name": "ls", "tool_input": {"path": "/home/u/.ssh"}},
    {"tool_name": "find", "tool_input": {"pattern": "**/*.pem"}},
])
def test_ordinary_pi_tool_calls_pass(payload):
    assert hooks.decide(payload) is None


def test_extension_path(tmp_path, monkeypatch):
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    assert pi.extension_path(project=False) == tmp_path / ".pi" / "agent" / "extensions" / "keyfence.ts"
    assert pi.extension_path(project=True, cwd=tmp_path / "proj") == tmp_path / "proj" / ".pi" / "extensions" / "keyfence.ts"


def test_render_embeds_the_resolved_command_and_the_guarded_tools():
    source = pi.render("/opt/venv/bin/keyfence")
    assert '"/opt/venv/bin/keyfence"' in source
    assert json.dumps(list(pi.GUARDED_TOOLS)) in source
    assert '["hook", "pi"]' in source
    assert pi.MARKER in source


def test_render_escapes_a_command_with_quotes():
    source = pi.render('C:\\Program Files\\key"fence.exe')
    assert '"C:\\\\Program Files\\\\key\\"fence.exe"' in source


def test_install_is_idempotent_and_uninstall_removes_it(tmp_path):
    path = tmp_path / "extensions" / "keyfence.ts"
    assert pi.install(path, "/bin/keyfence")
    assert not pi.install(path, "/bin/keyfence")
    assert pi.is_ours(path)
    assert pi.install(path, "/other/keyfence")
    assert "/other/keyfence" in path.read_text()
    assert pi.uninstall(path)
    assert not path.exists()
    assert not pi.uninstall(path)


def test_install_refuses_to_overwrite_a_foreign_extension(tmp_path):
    path = tmp_path / "keyfence.ts"
    path.write_text("export default function () {}\n")
    with pytest.raises(FileExistsError):
        pi.install(path, "/bin/keyfence")
    assert path.read_text() == "export default function () {}\n"


def test_is_ours_on_a_directory(tmp_path):
    assert not pi.is_ours(tmp_path)


def test_keyfence_path_prefers_the_current_interpreters_bindir(tmp_path, monkeypatch):
    binary = tmp_path / "keyfence"
    binary.write_text("")
    monkeypatch.setattr(pi.sys, "executable", str(tmp_path / "python"))
    assert pi.keyfence_path() == str(binary)
    binary.unlink()
    monkeypatch.setattr(pi.shutil, "which", lambda name: None)
    assert pi.keyfence_path() == "keyfence"


def test_cli_installs_and_removes_the_extension(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    assert cli.main(["install-hooks", "pi"]) == 0
    path = tmp_path / ".pi" / "agent" / "extensions" / "keyfence.ts"
    assert pi.is_ours(path)
    assert "Extension installed" in capsys.readouterr().out
    assert cli.main(["install-hooks", "pi"]) == 0
    assert "already up to date" in capsys.readouterr().out
    assert cli.main(["install-hooks", "pi", "--remove"]) == 0
    assert not path.exists()
    assert cli.main(["install-hooks", "pi", "--remove"]) == 0
    assert "No keyfence extension" in capsys.readouterr().out


def test_cli_reports_a_foreign_extension(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    path = tmp_path / ".pi" / "agent" / "extensions" / "keyfence.ts"
    path.parent.mkdir(parents=True)
    path.write_text("mine\n")
    assert cli.main(["install-hooks", "pi"]) == 1
    assert "not written by keyfence" in capsys.readouterr().err


def test_cli_install_project_scope_mentions_trust(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["install-hooks", "pi", "--project"]) == 0
    assert pi.is_ours(tmp_path / ".pi" / "extensions" / "keyfence.ts")
    assert "trust the project" in capsys.readouterr().out


def test_hook_pi_blocks_a_pi_payload_through_the_entry_point():
    payload = json.dumps({"tool_name": "read", "tool_input": {"path": ".env"}})
    done = subprocess.run([sys.executable, "-c", "import keyfence.entry as e; raise SystemExit(e.main(['hook','pi']))"],
                          input=payload, capture_output=True, text=True)
    assert done.returncode == 2 and "keyfence blocked" in done.stderr


def test_every_guarded_tool_is_one_the_rules_actually_inspect():
    inspected = hooks.FILE_TOOLS | hooks.GREP_TOOLS | hooks.SHELL_TOOLS
    assert set(pi.GUARDED_TOOLS) <= inspected
    assert hooks.SHELL_TOOLS <= set(pi.GUARDED_TOOLS)
    assert hooks.GREP_TOOLS <= set(pi.GUARDED_TOOLS)
    source = pi.render("/bin/keyfence")
    assert "code === 2" in source and "code === 0" in source
