import os

import pytest

from keyfence import cli, doctor, hooks, pi, runner


@pytest.fixture
def missing_scripts(home, monkeypatch):
    folders = [home / "interpreter", home / "Scripts", home / "user Scripts"]
    for folder in folders:
        folder.mkdir()
    monkeypatch.setattr(hooks.sys, "executable", str(folders[0] / "python"))
    monkeypatch.setattr(hooks.sysconfig, "get_paths", lambda scheme=None: {
        "scripts": str(folders[1] if scheme is None else folders[2])})
    monkeypatch.setenv("PATH", os.curdir)
    monkeypatch.chdir(home)
    return folders


@pytest.mark.parametrize("agent", ["claude-code", "pi"])
@pytest.mark.parametrize("existing", [False, True])
def test_missing_keyfence_leaves_hook_files_untouched(home, missing_scripts, agent, existing, capsys):
    module = hooks if agent == "claude-code" else pi
    path = hooks.settings_path(True) if agent == "claude-code" else pi.extension_path(True)
    paths = [path, hooks.added_rules_path(path)] if agent == "claude-code" else [path]
    if existing:
        module.install(path, "old-keyfence")
    before = {p: p.read_bytes() if p.exists() else None for p in paths}

    assert cli.main(["install-hooks", agent, "--project"]) == 1
    assert {p: p.read_bytes() if p.exists() else None for p in paths} == before
    if not existing:
        assert not path.parent.exists()
    err = capsys.readouterr().err
    assert "keyfence not found" in err and "PATH" in err
    assert all(str(folder) in err for folder in missing_scripts)
    assert "install-hooks pi --command PATH" in err


def test_automatic_keyfence_must_be_absolute(home, missing_scripts, monkeypatch):
    (home / "keyfence").write_text("")
    monkeypatch.setattr(hooks.sys, "executable", "python")
    with pytest.raises(ValueError, match="keyfence not found"):
        hooks.keyfence_path()


def test_pi_explicit_command_still_installs_without_keyfence(home, missing_scripts, capsys):
    command = str(home / "not-installed" / "keyfence")
    assert cli.main(["install-hooks", "pi", "--project", "--command", command]) == 0
    assert pi.baked_command(pi.extension_path(True)) == command
    assert "does not exist" in capsys.readouterr().out


@pytest.mark.parametrize("agent", ["claude-code", "pi"])
def test_missing_keyfence_does_not_block_listing_or_removal(missing_scripts, agent, capsys):
    module = hooks if agent == "claude-code" else pi
    path = hooks.settings_path(True) if agent == "claude-code" else pi.extension_path(True)
    module.install(path, os.path.join("old", "keyfence"))
    before = path.read_bytes()
    assert cli.main(["install-hooks", "--list"]) == 0
    assert "installed" in capsys.readouterr().out
    assert path.read_bytes() == before
    assert cli.main(["install-hooks", agent, "--project", "--remove"]) == 0
    assert not (doctor.hook_installed(path) if agent == "claude-code" else pi.is_ours(path))


@pytest.mark.parametrize("consumer", ["run", "exec", "doctor"])
def test_missing_mitmdump_reports_searched_folders(home, missing_scripts, monkeypatch, capsys, consumer):
    (home / "mitmdump").write_text("")
    (home / "mitmdump.exe").write_text("")
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("must not execute an unresolved script"))
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start a process"))
    if consumer == "doctor":
        check = doctor.check_mitmdump()
        assert check.status == doctor.FAIL
        detail = check.detail
    else:
        argv = ["run"] if consumer == "run" else ["exec", "-p", "9001", "--", "unused-command"]
        assert cli.main(argv) == 1
        detail = capsys.readouterr().out
    assert "mitmdump not found" in detail and "PATH" in detail
    assert all(str(folder) in detail for folder in missing_scripts)
    assert str(hooks.sys.executable) in detail
