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


def test_canary_creates_and_appends(home, tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("PORT=3000")
    assert cli.main(["canary", str(env)]) == 0
    lines = env.read_text().splitlines()
    assert lines[0] == "PORT=3000"
    name, value = lines[1].split("=", 1)
    assert name == "INTERNAL_API_TOKEN" and len(value) >= 24
    assert env.read_text().endswith("\n")
    assert Vault().canary_label(value) == str(env.resolve())
    assert value not in capsys.readouterr().out


def test_canary_refuses_duplicate_name_and_accepts_custom(home, tmp_path, capsys):
    env = tmp_path / ".env"
    assert cli.main(["canary", str(env)]) == 0
    assert cli.main(["canary", str(env)]) == 1
    assert "already defines" in capsys.readouterr().out
    assert cli.main(["canary", str(env), "--name", "BILLING_KEY"]) == 0
    assert env.read_text().count("=") == 2
    assert Vault().canary_count() == 2


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
    assert "0 canary(ies)" in out
    assert "[jwt]" in out
    assert "[entropy x2, vault]  800 total" in out
    assert "gitleaks rules" in out


def test_status_without_audit_log(home, capsys):
    assert cli.main(["status"]) == 0
    assert "Recent detections" not in capsys.readouterr().out


def test_run_replaces_the_process_with_mitmdump(home, monkeypatch, capsys):
    seen = {}

    def fake_exec(program, argv):
        seen.update(program=program, argv=argv)
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execvp", fake_exec)
    with pytest.raises(SystemExit):
        cli.main(["run", "-p", "9001"])
    assert seen["program"].endswith("mitmdump") and "9001" in seen["argv"]
    assert "keyfence exec" in capsys.readouterr().out


def test_run_without_mitmdump(home, monkeypatch, capsys):
    def missing(_program, _argv):
        raise FileNotFoundError

    monkeypatch.setattr(cli.os, "execvp", missing)
    assert cli.main(["run"]) == 1
    assert "mitmdump not found" in capsys.readouterr().out


def test_exec_delegates_to_runner(home, monkeypatch):
    seen = {}

    def fake_run(command, port, everything, local):
        seen.update(command=command, port=port, everything=everything)
        return 3

    monkeypatch.setattr(cli.runner, "run", fake_run)
    assert cli.main(["exec", "-p", "9002", "--all-env", "--", "claude", "--verbose"]) == 3
    assert seen == {"command": ["claude", "--verbose"], "port": 9002, "everything": True}


def test_exec_passes_local_flag(home, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.runner, "run", lambda command, port, everything, local: seen.update(local=local) or 0)
    assert cli.main(["exec", "--local", "--", "claude"]) == 0
    assert seen["local"] == ""
    assert cli.main(["exec", "--local", "claude,node", "--", "claude"]) == 0
    assert seen["local"] == "claude,node"
    assert cli.main(["exec", "--", "claude"]) == 0
    assert seen["local"] is None


def test_run_with_local_mode(home, monkeypatch, capsys):
    seen = {}

    def fake_exec(program, argv):
        seen.update(cmd=argv)
        raise FileNotFoundError

    monkeypatch.setattr(cli.os, "execvp", fake_exec)
    assert cli.main(["run", "--local"]) == 1
    assert "--mode" in seen["cmd"] and "local" in seen["cmd"]
    assert "all processes" in capsys.readouterr().out
    assert cli.main(["run", "--local", "claude"]) == 1
    assert "local:claude" in seen["cmd"]


def test_hook_command_blocks_via_stdin(home, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/w/.env"}})))
    assert cli.main(["hook", "claude-code"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err


def test_install_hooks_project_and_remove(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    settings = tmp_path / ".claude" / "settings.json"
    assert settings.exists()
    assert "Hook installed" in capsys.readouterr().out
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    assert "already present" in capsys.readouterr().out
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove"]) == 0
    assert "Hook removed" in capsys.readouterr().out
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove"]) == 0
    assert "No keyfence hook" in capsys.readouterr().out


def test_install_hooks_global_uses_home(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.hooks.Path, "home", classmethod(lambda cls: tmp_path))
    assert cli.main(["install-hooks", "claude-code"]) == 0
    assert (tmp_path / ".claude" / "settings.json").exists()
    assert "all projects" in capsys.readouterr().out


def test_export_jsonl_and_otlp(home, write_config, monkeypatch, capsys):
    write_config("mode: redact\n")
    (home / "audit.log").write_text(
        json.dumps({"ts": "2026-09-08T10:00:00-0300", "host": "h", "path": "/p", "mode": "redact", "count": 1,
                    "findings": [{"kind": "vault", "preview": "x", "key": None}]}) + "\n"
        + json.dumps({"ts": "2026-09-08T11:00:00-0300", "host": "h2", "path": "/p", "mode": "redact", "count": 1,
                      "findings": [{"kind": "jwt", "preview": "y", "key": None}]}) + "\n")
    assert cli.main(["export"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2 and json.loads(lines[1])["host"] == "h2"
    assert cli.main(["export", "--since", "2026-09-08T10:00:00-0300"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1

    sent = []
    monkeypatch.setattr(cli.export, "send_otlp", lambda url, entries, headers: sent.append((url, len(entries), headers)) or len(entries))
    assert cli.main(["export", "--otlp", "http://c:4318", "--header", "Authorization=Bearer t"]) == 0
    assert sent[-1] == ("http://c:4318", 2, {"Authorization": "Bearer t"})
    assert (home / "export.cursor").read_text().strip() == "2026-09-08T11:00:00-0300"
    assert cli.main(["export", "--otlp", "http://c:4318"]) == 0
    assert sent[-1][1] == 0
    assert cli.main(["export", "--otlp", "http://c:4318", "--all"]) == 0
    assert sent[-1][1] == 2
    assert "Sent 2 entries" in capsys.readouterr().out


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
