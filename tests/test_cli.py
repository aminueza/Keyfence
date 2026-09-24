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


def test_import_from_secret_manager(home, monkeypatch, capsys):
    pairs = [("DB_PASSWORD", "manager-secret-value-1"), ("REGION", "us-east-1"), ("USERNAME", "app"), ("TOKEN", "tiny")]
    monkeypatch.setattr(cli.sources, "fetch", lambda source, path: pairs)
    assert cli.main(["import", "--from", "doppler", "--path", "app/prd"]) == 0
    out = capsys.readouterr().out
    assert "doppler: 4 value(s) read, 1 looked like secrets, 1 new" in out
    assert Vault().contains("manager-secret-value-1") and not Vault().contains("us-east-1")
    assert cli.main(["import", "--from", "doppler", "--all"]) == 0
    assert Vault().contains("us-east-1")
    assert cli.main(["import", "--from", "doppler", "some.env"]) == 2
    assert "cannot be combined" in capsys.readouterr().err

    def failing(source, path):
        raise cli.sources.SourceError("op is not installed")

    monkeypatch.setattr(cli.sources, "fetch", failing)
    assert cli.main(["import", "--from", "op"]) == 1
    assert "op is not installed" in capsys.readouterr().err


def test_doctor_and_demo_commands(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.runner, "port_open", lambda port: False)
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "keyfence:" in out and "audit log:" in out
    monkeypatch.setattr(cli.doctor, "check_mitmdump", lambda: cli.doctor.Check(cli.doctor.FAIL, "mitmdump", "gone"))
    assert cli.main(["doctor"]) == 1
    capsys.readouterr()
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "mode: audit" in out and "mode: block" in out and "HTTP 403" in out
    from keyfence import demo
    assert demo.DEMO_PASSWORD not in out.split("mode: redact")[1].split("mode: placeholder")[0]


def test_demo_ignores_a_broken_home(home, write_config, capsys):
    write_config("mode: bogus\n")
    (home / "vault.json").write_text("x")
    assert cli.main(["demo"]) == 0
    assert "mode: block" in capsys.readouterr().out
    assert (home / "vault.json").read_text() == "x"


def test_cli_import_does_not_load_mitmproxy():
    import subprocess, sys
    code = "import sys, keyfence.cli; print('mitmproxy' in sys.modules)"
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "False"


def test_entry_hook_fast_path_loads_only_hooks(home, monkeypatch, capsys):
    import subprocess, sys
    from keyfence import entry
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/w/.env"}})))
    assert entry.main(["hook", "claude-code"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "read", "tool_input": {"path": "/w/.env"}})))
    assert entry.main(["hook", "pi"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err
    assert entry.main(["hook", "other"]) == 1
    assert entry.main(["hook"]) == 1
    assert entry.main(["hook", "pi", "extra"]) == 1
    assert entry.main(["scan", "clean text"]) == 0
    code = ("import sys, json, io; sys.stdin = io.StringIO(json.dumps({'tool_name':'Read','tool_input':{'file_path':'a.py'}}));"
            "import keyfence.entry as e; rc = e.main(['hook','claude-code']);"
            "print(rc, any(m in sys.modules for m in ('yaml','keyfence.cli','keyfence.config','mitmproxy')))")
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "0 False"


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
    assert "Ignore lists:    0 key(s), 0 value(s)" in out


HOST = "db.internal.example.com"
ISSUE_ENV = (
    "DB_PASSWORD=hunter2hunter2!\n"
    "API_KEY=sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv\n"
    f"DB_HOST={HOST}\n"
    "OWNER=platform-team\n"
)


def test_status_reports_ignore_list_sizes(home, write_config, capsys):
    write_config(f"ignore_keys: [DB_HOST, SERVICE_NAME]\nignore_values: [{HOST}]\n")
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "Ignore lists:    2 key(s), 1 value(s)" in out and HOST not in out


def test_import_without_ignore_lists_registers_the_hostname(home, tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(ISSUE_ENV)
    assert cli.main(["import", str(env)]) == 0
    assert "Ignore lists" not in capsys.readouterr().out
    assert Vault().contains(HOST)


def test_import_honours_ignore_lists(home, write_config, tmp_path, capsys, monkeypatch):
    write_config(f"ignore_keys: [DB_HOST]\nignore_values: [{HOST}]\n")
    env = tmp_path / ".env"
    env.write_text(ISSUE_ENV)
    assert cli.main(["import", "--all", str(env)]) == 0
    out = capsys.readouterr().out
    assert f"Ignore lists: 1 key(s), 1 value(s) from {home / 'config.yaml'}" in out
    assert f"{env}: 3 new secret(s)" in out
    vault = Vault()
    assert vault.contains("platform-team") and vault.contains("hunter2hunter2!") and not vault.contains(HOST)
    assert HOST not in (home / "vault.json").read_text()
    monkeypatch.setattr(cli.os, "environ", {"DB_HOST": "internal-host-value-2026", "SERVICE_HOST": HOST,
                                            "MY_API_TOKEN": "envTokenValue12345"})
    assert cli.main(["import", "--env", "--all", str(home / "nope")]) == 0
    assert "environment: 1 new secret(s)" in capsys.readouterr().out
    assert Vault().contains("envTokenValue12345") and not Vault().contains("internal-host-value-2026")
    pairs = [("DB_HOST", "internal-host-value-2026"), ("DB_PASSWORD", "manager-secret-value-1"), ("OTHER", HOST)]
    monkeypatch.setattr(cli.sources, "fetch", lambda source, path: pairs)
    assert cli.main(["import", "--from", "doppler", "--all"]) == 0
    assert "doppler: 3 value(s) read, 1 looked like secrets, 1 new" in capsys.readouterr().out
    assert Vault().contains("manager-secret-value-1") and not Vault().contains(HOST)
    assert "internal-host-value-2026" not in (home / "vault.json").read_text()


def test_scan_honours_ignore_lists(home, write_config, capsys):
    Vault().add(HOST)
    assert cli.main(["scan", f"connect to {HOST}"]) == 2
    assert "[vault]" in capsys.readouterr().out
    write_config(f"ignore_values: [{HOST}]\n")
    assert cli.main(["scan", f"connect to {HOST}"]) == 0
    out = capsys.readouterr().out
    assert f"1 finding(s) ignored by the ignore lists in {home / 'config.yaml'}" in out
    assert "No secrets detected." in out and HOST not in out
    assert cli.main(["scan", f"connect to {HOST} with {KEY}"]) == 2
    out = capsys.readouterr().out
    assert "1 finding(s) ignored" in out and "1 secret(s) detected" in out and "[github-token]" in out


def test_status_without_audit_log(home, capsys):
    assert cli.main(["status"]) == 0
    assert "Recent detections" not in capsys.readouterr().out


def test_corrupted_vault_gives_one_line_error(home, capsys):
    (home / "vault.json").write_text("x")
    assert cli.main(["status"]) == 1
    err = capsys.readouterr().err
    assert "not a valid keyfence vault" in err and "Traceback" not in err
    assert cli.main(["scan", "anything"]) == 1


def test_run_refuses_busy_port(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.runner, "port_open", lambda port: True)
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("must not exec"))
    assert cli.main(["run", "-p", "9001"]) == 1
    assert "already in use" in capsys.readouterr().out


def test_run_replaces_the_process_with_mitmdump(home, monkeypatch, capsys):
    seen = {}

    def fake_exec(program, argv):
        seen.update(program=program, argv=argv)
        raise SystemExit(0)

    monkeypatch.setattr(cli.runner, "port_open", lambda port: False)
    monkeypatch.setattr(cli.os, "execvp", fake_exec)
    with pytest.raises(SystemExit):
        cli.main(["run", "-p", "9001"])
    assert seen["program"].lower().rstrip(".exe").endswith("mitmdump") and "9001" in seen["argv"]
    assert "keyfence exec" in capsys.readouterr().out


def test_run_without_mitmdump(home, monkeypatch, capsys):
    def missing(_program, _argv):
        raise FileNotFoundError

    monkeypatch.setattr(cli.runner, "port_open", lambda port: False)
    monkeypatch.setattr(cli.os, "execvp", missing)
    assert cli.main(["run"]) == 1
    assert "mitmdump not found" in capsys.readouterr().out


def test_exec_delegates_to_runner(home, monkeypatch):
    seen = {}

    def fake_run(command, port, everything, local, record, linger):
        seen.update(command=command, port=port, everything=everything)
        return 3

    monkeypatch.setattr(cli.runner, "run", fake_run)
    assert cli.main(["exec", "-p", "9002", "--all-env", "--", "claude", "--verbose"]) == 3
    assert seen == {"command": ["claude", "--verbose"], "port": 9002, "everything": True}


def test_exec_passes_record_and_linger(home, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.runner, "run", lambda command, port, everything, local, record, linger: seen.update(record=record, linger=linger) or 0)
    assert cli.main(["exec", "--record", "s.flows", "--linger", "30", "--", "claude"]) == 0
    assert seen["record"] == cli.Path("s.flows") and seen["linger"] == 30.0
    assert cli.main(["exec", "--", "claude"]) == 0
    assert seen["record"] is None and seen["linger"] == 0.0


def test_exec_help_says_what_record_holds(home, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["exec", "--help"])
    assert exc.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "secrets unredacted in audit and block mode" in text


def test_exec_passes_local_flag(home, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.runner, "run", lambda command, port, everything, local, record, linger: seen.update(local=local) or 0)
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

    monkeypatch.setattr(cli.runner, "port_open", lambda port: False)
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
    out = capsys.readouterr().out
    assert "Hook removed" in out and f"{len(cli.hooks.DENY_RULES)} deny rule(s) removed" in out
    assert "left in place" not in out
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove"]) == 0
    out = capsys.readouterr().out
    assert "No keyfence hook" in out and "removed." not in out


def test_install_hooks_remove_without_record_keeps_user_rules_until_forced(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"deny": ["Read(./.env)", "Bash(rm -rf *)"]}}))
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    (tmp_path / ".claude" / "keyfence-deny-rules.json").unlink()
    capsys.readouterr()
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove"]) == 0
    out = capsys.readouterr().out
    assert "Hook removed" in out and "no record of which ones keyfence added" in out
    assert "  Read(./.env)\n" in out and "Bash(rm -rf *)" not in out
    assert "--remove --force" in out and "rule(s) removed" not in out
    deny = json.loads(settings.read_text())["permissions"]["deny"]
    assert deny[:2] == ["Read(./.env)", "Bash(rm -rf *)"] and set(cli.hooks.DENY_RULES) <= set(deny)
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove", "--force"]) == 0
    out = capsys.readouterr().out
    assert "No keyfence hook" in out and f"{len(cli.hooks.DENY_RULES)} deny rule(s) removed" in out
    assert "left in place" not in out
    assert json.loads(settings.read_text()) == {"permissions": {"deny": ["Bash(rm -rf *)"]}}


def test_install_hooks_force_requires_claude_code_remove(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for argv in (["install-hooks", "claude-code", "--project", "--force"],
                 ["install-hooks", "pi", "--project", "--remove", "--force"]):
        assert cli.main(argv) == 2
        captured = capsys.readouterr()
        assert "error: --force only applies to `install-hooks claude-code --remove`" in captured.err
        assert captured.out == ""
    assert not (tmp_path / ".claude").exists() and not (tmp_path / ".pi").exists()


def test_install_hooks_global_uses_home(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.hooks.Path, "home", classmethod(lambda cls: tmp_path))
    assert cli.main(["install-hooks", "claude-code"]) == 0
    assert (tmp_path / ".claude" / "settings.json").exists()
    assert "all projects" in capsys.readouterr().out


def test_install_hooks_list_reports_each_agent_and_scope(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.hooks.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    assert cli.main(["install-hooks", "--list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "claude-code" and lines[3] == "pi" and len(lines) == 6
    assert all("not installed" in line for line in lines[1:3] + lines[4:6])
    assert str(tmp_path / "home" / ".claude" / "settings.json") in lines[1]
    assert str(project / ".claude" / "settings.json") in lines[2]
    assert str(tmp_path / "home" / ".pi" / "agent" / "extensions" / "keyfence.ts") in lines[4]
    assert str(project / ".pi" / "extensions" / "keyfence.ts") in lines[5]
    assert cli.main(["install-hooks", "claude-code"]) == 0
    assert cli.main(["install-hooks", "pi", "--project"]) == 0
    capsys.readouterr()
    assert cli.main(["install-hooks", "--list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1].startswith("  global   installed ") and "not installed" in lines[2]
    assert "not installed" in lines[4] and lines[5].startswith("  project  installed ")


def test_install_hooks_list_rejects_an_agent_and_the_other_flags(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for argv in (["install-hooks", "--list", "pi"], ["install-hooks", "--list", "--project"],
                 ["install-hooks", "--list", "--remove"], ["install-hooks", "--list", "--force"]):
        assert cli.main(argv) == 2
        captured = capsys.readouterr()
        assert "error: --list takes no agent" in captured.err and captured.out == ""
    assert cli.main(["install-hooks"]) == 2
    captured = capsys.readouterr()
    assert "error: install-hooks needs an agent" in captured.err and captured.out == ""
    with pytest.raises(SystemExit):
        cli.main(["install-hooks", "cursor"])
    assert not (tmp_path / ".claude").exists() and not (tmp_path / ".pi").exists()


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
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("keyfence", run_name="__main__")
    assert exc.value.code == 0
