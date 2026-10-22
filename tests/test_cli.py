import io
import json
import os
import runpy
import sys
import threading
from pathlib import Path

import pytest

from keyfence import cli
from keyfence.vault import Vault

KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
ROOT = Path(__file__).resolve().parent.parent


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
    out = capsys.readouterr().out
    assert "  - [github-token] gh…89 (40 chars) (offset 2-42)\n" in out
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
    monkeypatch.setattr(cli.runner, "port_open", lambda port, host: False)
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "keyfence:" in out and "audit log:" in out
    monkeypatch.setattr(cli.doctor, "check_mitmdump", lambda: cli.doctor.Check(cli.doctor.FAIL, "mitmdump", "gone"))
    assert cli.main(["doctor"]) == 1
    capsys.readouterr()
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("keyfence demo\n") and "HTTP 403" in out
    from keyfence import demo
    assert demo.DEMO_PASSWORD not in out.split("\nredact ")[1].split("\nplaceholder ")[0]


def test_demo_ignores_a_broken_home(home, write_config, capsys):
    write_config("mode: bogus\n")
    (home / "vault.json").write_text("x")
    assert cli.main(["demo"]) == 0
    assert "\nblock " in capsys.readouterr().out
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


def test_entry_hook_decodes_a_utf8_prompt_under_a_foreign_locale(home, monkeypatch):
    # Claude Code always sends UTF-8, but sys.stdin decodes with the locale
    # codec; on Windows that is an ANSI code page whose strict decoder raises
    # on the bytes of U+1F44D, which must not refuse a clean prompt.
    from keyfence import entry
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "ship it 👍"},
                         ensure_ascii=False).encode("utf-8")
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="cp1252", errors="strict"))
    assert entry.main(["hook", "claude-code"]) == 0


def test_entry_hook_refuses_undecodable_stdin_fail_closed(home, monkeypatch):
    from keyfence import entry
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"\xff\xfe not json"), encoding="utf-8", errors="strict"))
    assert entry.main(["hook", "claude-code"]) == 2


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_hook_help_prints_usage_instead_of_reading_the_flag_as_an_agent(capsys, flag):
    from keyfence import entry

    with pytest.raises(SystemExit) as exc:
        entry.main(["hook", flag])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: keyfence hook") and "claude-code" in out


def test_hook_help_after_the_agent_also_reaches_the_parser(capsys):
    from keyfence import entry

    with pytest.raises(SystemExit) as exc:
        entry.main(["hook", "claude-code", "--help"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("usage: keyfence hook")


def test_an_agent_named_like_a_flag_is_still_refused(capsys):
    from keyfence import entry

    assert entry.main(["hook", "--agent"]) == 1
    assert "unknown agent: --agent" in capsys.readouterr().err


def test_the_fast_path_still_skips_the_cli_when_a_hook_runs():
    import subprocess, sys

    code = ("import sys, json, io; sys.stdin = io.StringIO(json.dumps({'tool_name':'Read','tool_input':{'file_path':'a.py'}}));"
            "import keyfence.entry as e; rc = e.main(['hook','claude-code']);"
            "print(rc, any(m in sys.modules for m in ('argparse','keyfence.cli','mitmproxy')))")
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
    assert "(registered secret)" not in out


def test_status_without_audit_log(home, capsys):
    assert cli.main(["status"]) == 0
    assert "Recent detections" not in capsys.readouterr().out


def test_status_exits_1_on_a_bad_tcp_timeout_without_a_traceback(home, write_config, capsys):
    write_config("proxy_tcp_timeout: 0\n")
    assert cli.main(["status"]) == 1
    err = capsys.readouterr().err
    assert "proxy_tcp_timeout" in err and "Traceback" not in err


def test_status_shows_the_tcp_timeout(home, write_config, capsys):
    write_config("mode: block\n")
    assert cli.main(["status"]) == 0
    assert "TCP timeout:     3600 s" in capsys.readouterr().out
    write_config("proxy_tcp_timeout: 7200\n")
    assert cli.main(["status"]) == 0
    assert "TCP timeout:     7200 s" in capsys.readouterr().out


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
    out = capsys.readouterr().out
    assert out == "Port 9001 is already in use. Pick another one with -p.\n"
    assert "Starting keyfence" not in out and "export HTTPS_PROXY" not in out


def test_run_keeps_8888_and_says_why(home, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["run", "--help"])
    assert exc.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "port for the proxy (default: 8888, never a free one" in text
    assert "run prints the port to export" in text
    assert "keyfence exec picks a free port" in text


def test_exec_refuses_a_busy_port_it_was_asked_for(home, monkeypatch, capsys):
    monkeypatch.setattr(cli.runner, "port_open", lambda port: True)
    monkeypatch.setattr(cli.runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start"))
    assert cli.main(["exec", "-p", "9001", "--", "echo"]) == 1
    out, err = capsys.readouterr()
    assert out == "Port 9001 is already in use. Pick another one with -p.\n" and err == ""


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


def test_run_tells_mitmdump_the_tcp_timeout_from_the_config(home, write_config, monkeypatch, capsys):
    seen = {}
    write_config("proxy_tcp_timeout: 7200\n")

    def fake_exec(program, argv):
        seen.update(program=program, argv=argv)
        raise SystemExit(0)

    monkeypatch.setattr(cli.runner, "port_open", lambda port: False)
    monkeypatch.setattr(cli.os, "execvp", fake_exec)
    with pytest.raises(SystemExit):
        cli.main(["run", "-p", "9001"])
    assert ["--set", "tcp_timeout=7200"] in [seen["argv"][i:i + 2] for i in range(len(seen["argv"]) - 1)]


def test_run_rejects_an_invalid_tcp_timeout(home, write_config, monkeypatch, capsys):
    write_config("proxy_tcp_timeout: 0\n")
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("must not exec"))
    assert cli.main(["run", "-p", "9001"]) == 1
    assert "proxy_tcp_timeout" in capsys.readouterr().err


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


def test_exec_without_port_lets_the_runner_pick_one(home, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.runner, "run",
                        lambda command, port, everything, local, record, linger: seen.update(port=port) or 0)
    assert cli.main(["exec", "--", "claude"]) == 0
    assert seen["port"] is None
    assert cli.main(["exec", "-p", "9002", "--", "claude"]) == 0
    assert seen["port"] == 9002
    assert cli.build_parser().parse_args(["run"]).port == 8888
    assert cli.build_parser().parse_args(["doctor"]).port == 8888


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


def test_install_hooks_names_the_hook_the_deny_block_and_the_record_it_writes(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    record = tmp_path / ".claude" / "keyfence-deny-rules.json"
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    out = capsys.readouterr().out
    assert str(settings) in out and "permissions.deny" in out and str(record) in out
    assert json.loads(record.read_text()) == sorted(cli.hooks.DENY_RULES)


def test_install_hooks_prints_the_claude_code_versions_the_deny_rules_need_below_the_rule_count(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    lines = capsys.readouterr().out.splitlines()
    after_count = lines[lines.index(next(line for line in lines if "permissions.deny block" in line)) + 1]
    assert "Edit" in after_count and "Write" in after_count
    assert all(version in after_count for version in cli.DENY_RULE_MIN_CLAUDE_CODE.values())


def test_install_hooks_prints_the_claude_code_versions_when_the_hook_is_already_there(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    capsys.readouterr()
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    out = capsys.readouterr().out
    assert "Hook already present" in out
    assert all(version in out for version in cli.DENY_RULE_MIN_CLAUDE_CODE.values())


def test_install_hooks_remove_does_not_print_the_claude_code_versions(home, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["install-hooks", "claude-code", "--project"]) == 0
    capsys.readouterr()
    assert cli.main(["install-hooks", "claude-code", "--project", "--remove"]) == 0
    out = capsys.readouterr().out
    assert "Hook removed" in out
    assert not any(version in out for version in cli.DENY_RULE_MIN_CLAUDE_CODE.values())


def test_setup_md_names_the_same_claude_code_versions_the_deny_rules_need():
    setup = (ROOT / "docs" / "setup.md").read_text()
    assert all(version in setup for version in cli.DENY_RULE_MIN_CLAUDE_CODE.values())


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
    # claude-code: agent name, tool-call hook (2 scopes), prompt hook (2 scopes), pi: agent name, 2 scopes
    assert lines[0] == "claude-code"
    assert lines[1] == "  tool-call hook"
    assert all("not installed" in line for line in lines[2:4])
    assert lines[4] == "  prompt hook"
    assert all("not installed" in line for line in lines[5:7])
    assert lines[7] == "pi"
    assert all("not installed" in line for line in lines[8:10])
    assert len(lines) == 10
    assert str(tmp_path / "home" / ".claude" / "settings.json") in lines[2]
    assert str(project / ".claude" / "settings.json") in lines[3]
    assert str(tmp_path / "home" / ".claude" / "settings.json") in lines[5]
    assert str(project / ".claude" / "settings.json") in lines[6]
    assert str(tmp_path / "home" / ".pi" / "agent" / "extensions" / "keyfence.ts") in lines[8]
    assert str(project / ".pi" / "extensions" / "keyfence.ts") in lines[9]
    assert cli.main(["install-hooks", "claude-code"]) == 0
    assert cli.main(["install-hooks", "pi", "--project"]) == 0
    capsys.readouterr()
    assert cli.main(["install-hooks", "--list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1].startswith("  tool-call hook")
    assert lines[2].startswith("    global   installed ") and "not installed" in lines[3]
    assert lines[4].startswith("  prompt hook")
    assert lines[5].startswith("    global   installed ") and "not installed" in lines[6]
    assert "not installed" in lines[8] and lines[9].startswith("  project  installed ")


def test_install_hooks_list_shows_a_prompt_hook_missing_on_an_old_install(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.hooks.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    settings = tmp_path / "home" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Read", "hooks": [{"type": "command", "command": "keyfence hook claude-code"}]}]}}))
    assert cli.main(["install-hooks", "--list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == "  tool-call hook" and lines[2].startswith("    global   installed ")
    assert lines[4] == "  prompt hook" and "not installed" in lines[5]


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


def test_scan_directory_finds_secrets(home, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    (tmp_path / "transcript.jsonl").write_text(f'{{"msg": "token: {secret}"}}\n')
    (tmp_path / "clean.txt").write_text("nothing here\n")
    binary = tmp_path / "binary.bin"
    binary.write_bytes(b"hello\x00world")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "found.jsonl").write_text(f'key={secret}\n')
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    out = captured.out
    assert "2 secret(s) detected:" in out
    assert f'  - {tmp_path / "transcript.jsonl"}:1: [openai-api-key] sk…Uv (40 chars) in "msg"\n' in out
    assert "transcript.jsonl:1:" in out
    assert "nested/found.jsonl:1:" in out or "nested\\found.jsonl:1:" in out
    assert "openai-api-key" in out
    assert "clean.txt" not in out
    assert "binary.bin" not in out
    assert "(registered secret)" not in out
    assert secret not in out


def test_scan_directory_clean(home, tmp_path, capsys):
    (tmp_path / "a.txt").write_text("hello\n")
    (tmp_path / "b.txt").write_text("world\n")
    assert cli.main(["scan", "-f", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "No secrets detected." in out


def test_scan_directory_binary_skipped(home, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    binary = tmp_path / "bad.bin"
    binary.write_bytes(f"token: {secret}\x00".encode())
    assert cli.main(["scan", "-f", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "No secrets detected." in out


def test_scan_directory_missing_path(home, capsys):
    missing = Path("does_not_exist_xyz")
    assert cli.main(["scan", "-f", str(missing)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "does_not_exist_xyz" in err


def test_scan_directory_vault_registered_secret(home, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    vault = Vault()
    vault.add(secret)
    (tmp_path / "file.txt").write_text(f"token: {secret}\n")
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "(registered secret)" in out
    assert secret not in out


def test_scan_directory_ignore_list(home, write_config, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    write_config(f"ignore_values: [{secret}]\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "one.txt").write_text(f"token: {secret}\n")
    (sub / "two.txt").write_text(f"key={secret}\n")
    assert cli.main(["scan", "-f", str(sub)]) == 0
    out = capsys.readouterr().out
    assert out.count("finding(s) ignored") == 1
    assert "2 finding(s) ignored by the ignore lists in" in out
    assert "No secrets detected." in out


def test_scan_directory_unreadable_file(home, tmp_path, capsys, monkeypatch):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    readable = tmp_path / "readable.txt"
    readable.write_text(f"token: {secret}\n")
    unreadable = tmp_path / "unreadable.txt"
    unreadable.write_text("should not matter\n")
    unreadable_str = str(unreadable.resolve())
    original_open = Path.open

    def patched_open(self, *args, **kwargs):
        if str(self.resolve()) == unreadable_str:
            raise PermissionError("Permission denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", patched_open)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert f"skipped: {unreadable}" in captured.err
    assert "readable.txt:1:" in captured.out


def test_scan_directory_text_open_failure(home, tmp_path, capsys, monkeypatch):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    (tmp_path / "race.txt").write_text(f"token: {secret}\n")
    race_str = str((tmp_path / "race.txt").resolve())
    original_open = Path.open

    def patched_open(self, mode="r", *args, **kwargs):
        # the binary pre-check passes; the text open afterwards fails, as a
        # file that loses its read permission between the two opens would
        if str(self.resolve()) == race_str and mode == "r":
            raise PermissionError(13, "Permission denied", str(self))
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", patched_open)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "skipped:" in captured.err and "race.txt" in captured.err
    assert "No secrets detected." in captured.out


def test_scan_directory_unreadable_root_is_an_error(home, tmp_path, capsys, monkeypatch):
    root = tmp_path / "locked"
    root.mkdir()
    root_str = str(root)
    original_scandir = os.scandir

    def patched_scandir(path):
        if str(path) == root_str:
            raise PermissionError(13, "Permission denied", str(path))
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", patched_scandir)
    assert cli.main(["scan", "-f", str(root)]) == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error:")
    assert "No secrets detected." not in captured.out


def test_scan_directory_dangling_symlink_skipped(home, tmp_path, capsys):
    if os.name == "nt":
        pytest.skip("symlinks need privileges on Windows")
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    (tmp_path / "ok.txt").write_text(f"token: {secret}\n")
    (tmp_path / "dangling").symlink_to(tmp_path / "does-not-exist")
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "skipped:" in captured.err and "dangling" in captured.err
    assert "ok.txt:1:" in captured.out


def test_scan_directory_binary_check_boundary_at_8k(home, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    line1 = f"token: {secret}\n"
    # a NUL at byte 8191 is inside the 8 KiB head (binary, skipped); at
    # byte 8192 it is past it (scanned as text), pinning the constant
    (tmp_path / "in.bin").write_bytes((line1 + "x" * (8191 - len(line1))).encode() + b"\x00" + b"y" * 10)
    (tmp_path / "out.bin").write_bytes((line1 + "x" * (8192 - len(line1))).encode() + b"\x00" + b"y" * 10)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "out.bin:1:" in out
    assert "in.bin" not in out


def test_scan_directory_unreadable_subdirectory(home, tmp_path, capsys, monkeypatch):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    readable = tmp_path / "readable.txt"
    readable.write_text(f"token: {secret}\n")
    bad_dir = tmp_path / "bad_dir"
    bad_dir.mkdir()
    (bad_dir / "secret.txt").write_text(f"key={secret}\n")
    bad_dir_str = str(bad_dir.resolve())
    original_scandir = os.scandir

    def patched_scandir(path):
        if str(Path(path).resolve()) == bad_dir_str:
            raise PermissionError(13, "Permission denied", str(bad_dir))
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", patched_scandir)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert f"skipped: {bad_dir}" in captured.err
    assert "readable.txt:1:" in captured.out


def test_scan_single_file_pem_multiline(home, tmp_path, capsys):
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = tmp_path / "key.pem"
    path.write_text(pem)
    assert cli.main(["scan", "-f", str(path)]) == 2
    out = capsys.readouterr().out
    assert "pem-private-key" in out
    assert "offset" in out


def test_scan_single_file_unreadable_is_an_error(home, tmp_path, capsys, monkeypatch):
    path = tmp_path / "secret.txt"
    path.write_text("token: sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv\n")
    path_str = str(path.resolve())
    original_open = Path.open

    def patched_open(self, *args, **kwargs):
        if str(self.resolve()) == path_str:
            raise PermissionError(13, "Permission denied", str(path))
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", patched_open)
    assert cli.main(["scan", "-f", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error:")
    assert "No secrets detected." not in captured.out
    assert "ignored" not in captured.out


def test_scan_directory_non_regular_file_skipped(home, tmp_path, capsys):
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is not available on this platform")
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    (tmp_path / "readable.txt").write_text(f"token: {secret}\n")
    os.mkfifo(tmp_path / "pipe")
    result = {}

    def run():
        result["rc"] = cli.main(["scan", "-f", str(tmp_path)])

    # a regression in the regular-file check blocks in open() forever;
    # run in a thread so that failure is a failure, not a hung CI job
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=30)
    assert not t.is_alive(), "scan hung on the FIFO: the regular-file check regressed"
    assert result["rc"] == 2
    captured = capsys.readouterr()
    assert "skipped:" in captured.err and "pipe" in captured.err
    assert "readable.txt:1:" in captured.out


def test_scan_directory_sorted_order(home, tmp_path, capsys, monkeypatch):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    sub_a = tmp_path / "adir"
    sub_b = tmp_path / "bdir"
    sub_a.mkdir()
    sub_b.mkdir()
    (tmp_path / "b.txt").write_text(f"token: {secret}\n")
    (tmp_path / "a.txt").write_text(f"token: {secret}\n")
    (sub_b / "z.txt").write_text(f"token: {secret}\n")
    (sub_a / "y.txt").write_text(f"token: {secret}\n")
    real_walk = os.walk

    def reversed_walk(top, **kwargs):
        # hand the walk the opposite of the OS order, so a deleted
        # dirs.sort()/files.sort() shows up as reversed output
        for root, dirs, files in real_walk(top, **kwargs):
            dirs[:] = sorted(dirs, reverse=True)
            files[:] = sorted(files, reverse=True)
            yield root, dirs, files

    monkeypatch.setattr(os, "walk", reversed_walk)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    names = ("a.txt", "b.txt", os.path.join("adir", "y.txt"), os.path.join("bdir", "z.txt"))
    positions = [out.index(name) for name in names]
    assert positions == sorted(positions)


def test_scan_directory_binary_check_reads_at_most_8k(home, tmp_path, capsys):
    secret = "sk-proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    payload = f"token: {secret}\n" + "x" * 9000 + "\x00"
    (tmp_path / "big.txt").write_text(payload)
    assert cli.main(["scan", "-f", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "big.txt:1:" in out


def _secret() -> str:
    return "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"


def test_entry_dispatch_prompt_hook_blocks(home, write_config, capsys, monkeypatch):
    from keyfence import entry
    write_config("mode: redact\n")
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": f"token: {_secret()}"})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert entry.main(["hook", "claude-code"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["decision"] == "block"
    assert "openai-api-key" in data["reason"]
    assert _secret() not in data["reason"]


def test_entry_dispatch_tool_call_still_uses_hooks(home, monkeypatch, capsys):
    from keyfence import entry
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/w/.env"}})))
    assert entry.main(["hook", "claude-code"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err


def test_entry_hook_pi_unaffected(home, write_config, monkeypatch, capsys):
    from keyfence import entry
    write_config("mode: redact\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"hook_event_name": "UserPromptSubmit", "prompt": f"token: {_secret()}"})))
    assert entry.main(["hook", "pi"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


@pytest.mark.parametrize("raw", ["", "not json", "[]",
                                 pytest.param("[" * 100000, id="deep-json")])
def test_entry_unreadable_or_odd_input_still_exits_2(home, monkeypatch, capsys, raw):
    from keyfence import entry
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    assert entry.main(["hook", "claude-code"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err


def test_entry_unreadable_stdin_bytes_exits_2(home, monkeypatch, capsys):
    from keyfence import entry
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"\xff\xfe"), encoding="utf-8"))
    assert entry.main(["hook", "claude-code"]) == 2
    assert "keyfence blocked" in capsys.readouterr().err


def test_entry_prompt_import_failure_blocks(home, write_config, monkeypatch, capsys):
    from keyfence import entry
    write_config("mode: redact\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"hook_event_name": "UserPromptSubmit", "prompt": f"token: {_secret()}"})))
    monkeypatch.setitem(sys.modules, "keyfence.prompt", None)
    assert entry.main(["hook", "claude-code"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["decision"] == "block"
    assert data["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit",
                                          "suppressOriginalPrompt": True}
    assert "guard crashed" in data["reason"]
