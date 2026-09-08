import io
import json
import runpy

import pytest

from keyfence import cli
from keyfence.vault import Vault

KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def test_scan_text_reports_findings(home, capsys):
    assert cli.main(["scan", f"token: {KEY}"]) == 2
    out = capsys.readouterr().out
    assert "github-token" in out
    assert KEY not in out


def test_scan_reports_json_key(home, capsys):
    assert cli.main(["scan", json.dumps({"content": f"token: {KEY}"})]) == 2
    assert 'in "content"' in capsys.readouterr().out


def test_scan_clean_text(home, capsys):
    assert cli.main(["scan", "nothing here"]) == 0
    assert "No secrets" in capsys.readouterr().out


def test_scan_file_and_stdin(home, tmp_path, capsys, monkeypatch):
    path = tmp_path / "in.txt"
    path.write_text(f"x={KEY}")
    assert cli.main(["scan", "-f", str(path)]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO(f"y={KEY}"))
    assert cli.main(["scan"]) == 2


def test_add_secret(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "senha-longa-o-suficiente")
    assert cli.main(["add-secret"]) == 0
    assert Vault().contains("senha-longa-o-suficiente")
    assert "1 secret(s)" in capsys.readouterr().out


def test_add_secret_empty_and_short(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "   ")
    assert cli.main(["add-secret"]) == 1
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "abc")
    assert cli.main(["add-secret"]) == 1
    assert "too short" in capsys.readouterr().out


def test_import_paths(home, tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(f"GITHUB_TOKEN={KEY}\n")
    assert cli.main(["import", str(env), str(tmp_path / "missing")]) == 0
    out = capsys.readouterr().out
    assert "1 new secret(s)" in out
    assert "skip:" in out
    assert Vault().contains(KEY)


def test_import_env(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "environ", {"MY_API_TOKEN": "envTokenValue12345", "HOME": "/x"})
    assert cli.main(["import", "--env", str(home / "nope")]) == 0
    assert Vault().contains("envTokenValue12345")
    assert "environment: 1" in capsys.readouterr().out


def test_import_nothing_found(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "default_paths", lambda: [])
    assert cli.main(["import"]) == 1
    assert "Nothing to import" in capsys.readouterr().out


def test_import_all_flag(home, tmp_path):
    env = tmp_path / ".env"
    env.write_text("NODE_ENV=production\n")
    assert cli.main(["import", "--all", str(env)]) == 0
    assert Vault().contains("production")


def test_status(home, write_config, capsys):
    write_config("mode: block\n")
    audit = home / "audit.log"
    audit.write_text(
        json.dumps({"ts": "t", "host": "h", "mode": "block",
                    "findings": [{"kind": "jwt", "preview": "x"}]}) + "\nnot json\n"
        + json.dumps({"ts": "t2", "host": "h", "mode": "redact", "count": 800,
                      "findings": [{"kind": "entropy", "preview": "a"},
                                   {"kind": "entropy", "preview": "b"},
                                   {"kind": "vault", "preview": "c"}]}) + "\n")
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "Mode:            block" in out
    assert "[jwt]" in out
    assert "[entropy x2, vault]  800 total" in out
    assert "gitleaks rules" in out


def test_status_without_audit_log(home, capsys):
    assert cli.main(["status"]) == 0
    assert "Recent detections" not in capsys.readouterr().out


def test_run_invokes_mitmdump(home, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: seen.update(cmd=cmd) or 0)
    assert cli.main(["run", "-p", "9001"]) == 0
    assert "9001" in seen["cmd"]
    assert "keyfence exec" in capsys.readouterr().out


def test_run_without_mitmdump(home, monkeypatch, capsys):
    def missing(_cmd):
        raise FileNotFoundError

    monkeypatch.setattr(cli.subprocess, "call", missing)
    assert cli.main(["run"]) == 1
    assert "mitmdump not found" in capsys.readouterr().out


def test_exec_delegates_to_runner(home, monkeypatch):
    seen = {}

    def fake_run(command, port, everything):
        seen.update(command=command, port=port, everything=everything)
        return 3

    monkeypatch.setattr(cli.runner, "run", fake_run)
    assert cli.main(["exec", "-p", "9002", "--all-env", "--", "claude", "--verbose"]) == 3
    assert seen == {"command": ["claude", "--verbose"], "port": 9002, "everything": True}


def test_exec_without_command(home, capsys):
    assert cli.main(["exec"]) == 1
    assert "usage" in capsys.readouterr().out


def test_missing_command_errors():
    with pytest.raises(SystemExit):
        cli.main([])


def test_module_entrypoint(home, monkeypatch):
    monkeypatch.setattr("sys.argv", ["keyfence", "scan", "clean"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("keyfence", run_name="__main__")
    assert exc.value.code == 0
