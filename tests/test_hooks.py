import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from keyfence import hooks

ROOT = Path(__file__).resolve().parent.parent


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
    assert "cat" not in found and "TOKEN" not in found and "head" not in found
    assert hooks.paths_in_command("ls -la --color=auto") == []


SAME_FILE_KINDS = [
    "secrets.yaml", "secrets.json", "db.secret", "db.secrets", "service-account.json",
    "service-account-prod.json", "kubeconfig", "prod.kubeconfig", ".envrc", "id_dsa", "_netrc",
    "store.keystore", ".gnupg/secring.gpg", ".env", "id_rsa", "credentials.json", "terraform.tfvars",
    "app.p12", "cert.pfx", "trust.jks", "key.ppk", "passwords.kdbx", ".npmrc", ".pypirc",
    ".git-credentials", "gcp-credentials.json", ".aws/credentials", ".docker/config.json",
    ".kube/config", ".ssh/known_hosts",
]


@pytest.mark.parametrize("name", SAME_FILE_KINDS)
def test_bash_refuses_every_file_kind_the_read_tool_refuses(name):
    path = f"/proj/{name}"
    read = hooks.decide({"tool_name": "Read", "tool_input": {"file_path": path}})
    bash = hooks.decide({"tool_name": "Bash", "tool_input": {"command": f"cat {path}"}})
    assert read and bash and path in bash
    assert hooks.decide({"tool_name": "bash", "tool_input": {"command": f"cat {path}"}})


@pytest.mark.parametrize("command", [
    "cat .kube/config", "cat .ssh/known_hosts", "cat .docker/config.json", "cat .gnupg/secring.gpg",
    'cat "/proj/secrets.yaml"', "cat '/proj/secrets.yaml'", "sops -d --input=/proj/secrets.yaml",
    "KUBECONFIG=/proj/kubeconfig kubectl get pods", "docker run -v /proj/secrets.yaml:/run/s img",
    "cp $HOME/.aws/credentials /tmp/x", "cat C:\\Users\\u\\_netrc", "head -c 100 <~/.pypirc",
    "tar czf out.tgz src/,service-account-prod.json",
])
def test_paths_inside_options_quotes_and_assignments_are_still_refused(command):
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": command}})


@pytest.mark.parametrize("command", [
    "ls -la", "npm test", "git status", "echo hello", "cat README.md", "cat package.json",
    "cat requirements.txt", "cat .env.example", "cat key.pub", "pytest tests/test_hooks.py",
    "python3 manage.py migrate", "grep -rn TODO src/", "docker compose up -d",
    "git commit -m 'fix: config.yaml parsing'", "node dist/index.js", "make build",
    "curl https://api.example.com/v1/users", "kubectl get secrets", "gh secret list",
    "rg credentials src/", "ls --env-file=x.txt", "cd .. && ls ./", "cat .env.sample",
])
def test_commands_mentioning_no_secret_file_pass(command):
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": command}}) is None


@pytest.mark.parametrize("path", [".ssh/known_hosts", ".kube/config", ".docker/config.json", ".gnupg/pubring.kbx"])
def test_relative_paths_under_secret_directories_are_sensitive(path):
    assert hooks.is_sensitive(path)
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": path}})


def test_decide_file_tools_and_bash():
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": "/w/.env"}})
    assert hooks.decide({"tool_name": "Edit", "tool_input": {"file_path": "/w/server.key"}})
    assert hooks.decide({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/w/analysis.ipynb"}}) is None
    assert hooks.decide({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/w/secrets.ipynb"}})
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": "/w/app.py"}}) is None
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": "cat .env"}})
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}) is None
    assert hooks.decide({"tool_name": "Read"}) is None


def test_decide_grep():
    assert hooks.decide({"tool_name": "Grep", "tool_input": {"pattern": "TOKEN", "path": "/w/.env"}})
    assert hooks.decide({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/w", "glob": "*.pem"}})
    assert hooks.decide({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/w/src"}}) is None
    assert hooks.decide({"tool_name": "Grep", "tool_input": {"pattern": "x"}}) is None


@pytest.mark.parametrize("command", [
    "env", "printenv", "env | grep TOKEN", "printenv > out.txt", "export -p", "export", "export | grep AWS",
    "set", "set | sort", "declare -x", "cd app && env", "printenv AWS_SECRET_ACCESS_KEY",
    "printenv github_token", "cat /proc/self/environ", "tr '\\0' '\\n' < /proc/1234/environ",
    "aws secretsmanager get-secret-value --secret-id prod/db",
    "aws ssm get-parameter --name /x --with-decryption", "aws configure get aws_secret_access_key",
    "op read op://vault/item/password", "op item get abc --reveal", "op item get abc --format json",
    "op item get abc --fields label=password", "vault kv get secret/app", "vault read secret/app",
    "doppler secrets download --no-file", "doppler secrets", "kubectl get secret db -o yaml",
    "kubectl get secrets -o json", "kubectl get secret db --output=jsonpath='{.data}'",
    "kubectl config view --raw", "gcloud secrets versions access latest --secret=x",
    "gcloud auth print-access-token", "gcloud auth application-default print-access-token",
    "az keyvault secret show --name x", "az account get-access-token", "gh auth token",
    "heroku config", "heroku config:get DATABASE_URL", "bw get password github",
    "{ env; }", "if true; then env; fi", "for i in 1 2; do env; done", "LC_ALL=C env", "FOO=1 BAR=2 printenv",
    "sudo env", "sudo -E env", "sudo -u root env", "/usr/bin/env", "sudo /usr/bin/env", "eval env", "command env",
    "echo x | xargs env", "xargs -0 env", "nohup env", "time env", "exec env", "bash -c env", "sh -c 'env'",
    "bash -lc 'env'", 'zsh -c "env | grep X"', "sudo aws secretsmanager get-secret-value --secret-id x",
    "/usr/local/bin/op read op://vault/item/password", "if x; then vault kv get secret/app; fi",
    "sudo gh auth status --show-token", "aws sts get-session-token", "aws sts get-federation-token",
    "aws sts assume-role --role-arn arn:x --role-session-name s", "aws ecr get-login-password",
    "aws configure export-credentials", "gh auth status --show-token", "bw list items",
    "kubectl get secret app -o custom-columns=DATA:.data", "doppler secrets get X", "doppler secrets -p proj -c dev",
    "echo $GITHUB_TOKEN", "echo ${GITHUB_TOKEN}", "echo ${GITHUB_TOKEN:-unset}", 'echo "token=$API_TOKEN"',
    "echo $github_token", 'printf "%s" "$AWS_SECRET_ACCESS_KEY"', "printf '%s\\n' \"$DB_PASSWORD\"",
])
def test_bash_commands_that_print_secrets_are_blocked(command):
    reason = hooks.decide({"tool_name": "Bash", "tool_input": {"command": command}})
    assert reason and "keyfence blocked" in reason


@pytest.mark.parametrize("command", [
    "env FOO=1 python app.py", "printenv HOME", "printenv PATH", "set -e; pytest", "set -o pipefail && make",
    "export PATH=/x:$PATH", "export FOO=bar", "aws s3 ls", "kubectl get pods", "kubectl get secrets",
    "kubectl describe secret db", "kubectl config view", "vault status", "op --version", "op item get abc",
    "op item list", "git status", "echo environment", "heroku logs --tail", "doppler --version",
    "gh secret list", "gh auth status", "gcloud auth list", "az account show", "aws configure get region",
    "doppler secrets --only-names", "doppler secrets -p proj --only-names", "sudo apt install x", "sudo -u root apt install x",
    "time make", "time -p make", "LC_ALL=C sort file", "KUBECONFIG=x kubectl get pods", "xargs rm", "nohup python server.py &",
    "command -v env", "command -v git", "eval \"$(direnv hook zsh)\"", "exec python app.py", "bash -c 'make test'",
    "python -c 'print(1)'", "ssh -c aes256-ctr host", "/usr/bin/python3 app.py", "cat /etc/env", "{ make; }",
    "if [ -f x ]; then make; fi", "for i in 1 2; do echo $i; done", "todo env", "echo done", "echo $HOME", 'echo "$PATH"',
    "echo ${HOME}/bin", "echo token", 'echo "$USER has key"', "echo cost: $5 tokens", "printf '%s\\n' hello",
    "aws sts get-caller-identity", "aws ecr describe-repositories", "bw list folders", "kubectl get secret db",
])
def test_ordinary_commands_pass(command):
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": command}}) is None


def test_prefixed_secret_command_is_named_without_its_prefix():
    reason = hooks.decide({"tool_name": "Bash", "tool_input": {"command": "sudo -E /usr/local/bin/aws secretsmanager get-secret-value --secret-id x"}})
    assert "`aws secretsmanager get-secret-value` prints secret values" in reason
    reason = hooks.decide({"tool_name": "Bash", "tool_input": {"command": "if true; then env; fi"}})
    assert "prints environment variables" in reason


@pytest.mark.parametrize("command", [
    "cd /tmp\nenv", " env", "\tprintenv", "ls\ngh auth token", "x=$(printenv)", "echo `env`",
    "make test\n\nexport", "true &&\n  vault kv get secret/app", "cat .ENV", "cat ./Config/.Env.Local",
    "ssh -i ~/.SSH/ID_RSA host", "cp /etc/ssl/server.PEM .", "\n\n aws secretsmanager get-secret-value --secret-id x",
])
def test_multiline_leading_space_substitution_and_case_are_still_blocked(command):
    assert hooks.decide({"tool_name": "Bash", "tool_input": {"command": command}})


@pytest.mark.parametrize("path", ["/p/.ENV", "/p/Server.PEM", "/home/u/.ssh/ID_RSA", "C:\\Users\\u\\.NETRC", "/p/Credentials.JSON"])
def test_file_tools_ignore_case(path):
    assert hooks.decide({"tool_name": "Read", "tool_input": {"file_path": path}})
    assert not hooks.is_sensitive("/p/.ENV.EXAMPLE")


def test_run_hook_exit_codes():
    err = io.StringIO()
    blocked = hooks.run_hook(io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": ".env"}})), err)
    assert blocked == 2 and "keyfence blocked" in err.getvalue()
    assert hooks.run_hook(io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "a.py"}})), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO("not json"), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO("[1]"), io.StringIO()) == 0
    assert hooks.run_hook(io.StringIO(""), io.StringIO()) == 0


def test_plugin_guard_is_the_same_file_and_runs_standalone():
    guard = ROOT / "plugin" / "hooks" / "guard.py"
    assert guard.read_text() == (ROOT / "keyfence" / "hooks.py").read_text()
    hook = json.loads((ROOT / "plugin" / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]
    assert hook["matcher"] == hooks.HOOK_MATCHER
    assert "guard.py" in hook["hooks"][0]["command"] and "CLAUDE_PLUGIN_ROOT" in hook["hooks"][0]["command"]
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "printenv"}})
    done = subprocess.run([sys.executable, str(guard)], input=payload, capture_output=True, text=True)
    assert done.returncode == 2 and "keyfence blocked" in done.stderr
    done = subprocess.run([sys.executable, str(guard)], input='{"tool_name":"Read","tool_input":{"file_path":"a.py"}}',
                          capture_output=True, text=True)
    assert done.returncode == 0


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
    assert data["hooks"]["PreToolUse"][1]["matcher"] == hooks.HOOK_MATCHER
    assert set(hooks.DENY_RULES) <= set(data["permissions"]["deny"])
    result = hooks.uninstall(path)
    assert result.changed and result.hook and result.rules == len(hooks.DENY_RULES) and result.unrecorded == []
    assert not hooks.uninstall(path).changed
    data = json.loads(path.read_text())
    assert len(data["hooks"]["PreToolUse"]) == 1
    assert "permissions" not in data


def test_install_keeps_foreign_deny_rules_and_fills_missing_ones(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"permissions": {"deny": ["Bash(rm -rf *)", hooks.DENY_RULES[0]]}}))
    assert hooks.install(path)
    deny = json.loads(path.read_text())["permissions"]["deny"]
    assert deny[0] == "Bash(rm -rf *)" and deny.count(hooks.DENY_RULES[0]) == 1
    assert set(hooks.DENY_RULES) <= set(deny)
    record = tmp_path / "keyfence-deny-rules.json"
    assert hooks.DENY_RULES[0] not in json.loads(record.read_text())
    assert hooks.uninstall(path).changed
    assert json.loads(path.read_text())["permissions"]["deny"] == ["Bash(rm -rf *)", hooks.DENY_RULES[0]]
    assert not record.exists()


def test_uninstall_without_record_removes_the_hook_but_keeps_every_deny_rule(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"permissions": {"deny": ["Read(./.env)", "Bash(rm -rf *)"]}}))
    assert hooks.install(path)
    (tmp_path / "keyfence-deny-rules.json").unlink()
    before = json.loads(path.read_text())["permissions"]["deny"]
    result = hooks.uninstall(path)
    assert result.hook and result.rules == 0 and result.changed
    assert result.unrecorded == [rule for rule in before if rule in hooks.DENY_RULES]
    assert "Read(./.env)" in result.unrecorded and "Bash(rm -rf *)" not in result.unrecorded
    data = json.loads(path.read_text())
    assert "hooks" not in data and data["permissions"]["deny"] == before
    again = hooks.uninstall(path)
    assert not again.changed and again.unrecorded == result.unrecorded
    assert json.loads(path.read_text())["permissions"]["deny"] == before


def test_uninstall_force_removes_every_keyfence_shaped_rule_and_any_recorded_one(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"permissions": {"deny": ["Read(./.env)", "Bash(rm -rf *)"]}}))
    assert hooks.install(path)
    (tmp_path / "keyfence-deny-rules.json").unlink()
    result = hooks.uninstall(path, force=True)
    assert result.hook and result.rules == len(hooks.DENY_RULES) and result.unrecorded == []
    assert json.loads(path.read_text()) == {"permissions": {"deny": ["Bash(rm -rf *)"]}}
    assert not hooks.uninstall(path, force=True).changed
    record = tmp_path / "keyfence-deny-rules.json"
    path.write_text(json.dumps({"permissions": {"deny": ["Read(./old-rule)", "Bash(rm -rf *)", hooks.DENY_RULES[3]]}}))
    record.write_text(json.dumps(["Read(./old-rule)"]))
    result = hooks.uninstall(path, force=True)
    assert result.rules == 2 and not result.hook
    assert json.loads(path.read_text()) == {"permissions": {"deny": ["Bash(rm -rf *)"]}}
    assert not record.exists()


def test_added_rules_record_is_none_when_missing_or_unreadable(tmp_path):
    path = tmp_path / "settings.json"
    record = tmp_path / "keyfence-deny-rules.json"
    assert hooks._added_rules(path) is None
    for content in ("garbage", "[1, 2]", '{"a": 1}', '"text"'):
        record.write_text(content)
        assert hooks._added_rules(path) is None
    record.write_text('["Read(./x)"]')
    assert hooks._added_rules(path) == ["Read(./x)"]
    record.write_text("garbage")
    path.write_text(json.dumps({"permissions": {"deny": [hooks.DENY_RULES[0], "Bash(rm -rf *)"]}}))
    result = hooks.uninstall(path)
    assert not result.changed and result.unrecorded == [hooks.DENY_RULES[0]]
    assert json.loads(path.read_text())["permissions"]["deny"] == [hooks.DENY_RULES[0], "Bash(rm -rf *)"]
    assert record.read_text() == "garbage"
    assert hooks.install(path)
    assert json.loads(record.read_text()) == sorted(hooks.DENY_RULES[1:])


def test_install_merges_new_rules_into_an_existing_record(tmp_path):
    path = tmp_path / "settings.json"
    record = tmp_path / "keyfence-deny-rules.json"
    assert hooks.install(path)
    data = json.loads(path.read_text())
    data["permissions"]["deny"].remove(hooks.DENY_RULES[2])
    path.write_text(json.dumps(data))
    assert hooks.install(path)
    assert json.loads(record.read_text()) == sorted(hooks.DENY_RULES)
    assert hooks.uninstall(path).rules == len(hooks.DENY_RULES)
    assert json.loads(path.read_text()) == {}


def test_install_creates_file_and_uninstall_cleans_empty_sections(tmp_path):
    path = tmp_path / "settings.json"
    assert hooks.install(path)
    assert hooks.uninstall(path).changed
    assert json.loads(path.read_text()) == {}
    missing = hooks.uninstall(tmp_path / "missing.json")
    assert not missing.changed and missing.unrecorded == []


def test_settings_path(tmp_path, monkeypatch):
    monkeypatch.setattr(hooks.Path, "home", classmethod(lambda cls: tmp_path))
    assert hooks.settings_path(project=False) == tmp_path / ".claude" / "settings.json"
    assert hooks.settings_path(project=True, cwd=tmp_path / "proj") == tmp_path / "proj" / ".claude" / "settings.json"
