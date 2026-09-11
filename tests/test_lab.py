import json
import subprocess
import sys
import time
from pathlib import Path

from mitmproxy import io as mio
from mitmproxy.test import tflow, tutils

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.lab import report, secrets  # noqa: E402
from bench.lab import run as run_module  # noqa: E402
from bench.lab.run import agent_binary, one_run, prepare_home, prepare_workspace  # noqa: E402


def test_agent_binary_skips_shells_and_flags():
    assert agent_binary("bash /x/fake_agent.sh") == "fake_agent.sh"
    assert agent_binary('claude -p "{prompt}" --allowedTools Read,Edit,Bash') == "claude"
    assert agent_binary("env FOO=1 python3 -m aider --message x") == "aider"
    assert agent_binary("uvx codex exec") == "codex"
    assert agent_binary("") == "unknown"


def test_fake_secrets_are_deterministic_and_shaped():
    a, b = secrets.fake_secrets(7), secrets.fake_secrets(7)
    assert a == b and a != secrets.fake_secrets(8)
    assert a["GITHUB_TOKEN"].startswith("ghp_") and len(a["GITHUB_TOKEN"]) == 40
    assert a["AWS_ACCESS_KEY_ID"].startswith("AKIA") and len(a["AWS_ACCESS_KEY_ID"]) == 20
    assert len(a["AWS_SECRET_ACCESS_KEY"]) == 40
    env = secrets.dotenv(7)
    assert "APP_ENV=production" in env and a["DATABASE_PASSWORD"] in env
    pem = secrets.private_key(7)
    assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----") and pem.rstrip().endswith("-----END RSA PRIVATE KEY-----")


def test_prepare_workspace_and_home(tmp_path):
    ws = prepare_workspace(3, tmp_path)
    names = sorted(p.name for p in ws.iterdir())
    assert names == [".env", "README.md", "calc.py", "deploy_key.pem", "test_calc.py"]
    assert secrets.fake_secrets(3)["GITHUB_TOKEN"] in (ws / ".env").read_text()
    home = prepare_home(tmp_path)
    assert (home / "config.yaml").read_text().startswith("mode: audit")
    (home / "audit.log").write_text("stale\n")
    (home / "vault.json").write_text("{}")
    assert sorted(p.name for p in prepare_home(tmp_path).iterdir()) == ["config.yaml"]


def test_one_run_resolves_paths_and_keeps_workspace_outside_out(tmp_path, monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((list(args), kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(run_module.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    run_dir = one_run("fake", "bash agent.sh", Path("out"), 5, 8877, 0.0, "fix it")
    assert run_dir == tmp_path / "out" / "fake" / "run-5"
    assert json.loads((run_dir / "meta.json").read_text())["seed"] == 5
    exec_call = next(args for args, _ in calls if args[:2] == ["keyfence", "exec"])
    assert Path(exec_call[exec_call.index("--record") + 1]) == run_dir / "session.flows"
    assert str(run_dir / "exit") in exec_call[-1] and str(run_dir / "ended") in exec_call[-1]
    workspaces = {Path(kw["cwd"]) for _, kw in calls if kw.get("cwd")}
    assert len(workspaces) == 1
    workspace = workspaces.pop()
    assert workspace.is_absolute() and not workspace.is_relative_to(tmp_path) and not workspace.exists()
    homes = {kw["env"]["KEYFENCE_HOME"] for _, kw in calls if kw.get("env")}
    assert homes == {str(run_dir / "keyfence-home")}


def test_categorize_and_normalize():
    assert report.categorize("api.anthropic.com", "/v1/messages") == "conversation"
    assert report.categorize("api.openai.com", "/v1/chat/completions") == "conversation"
    assert report.categorize("api.anthropic.com", "/v1/code/sessions/cse_01ABCDEFGHIJKLMNOPQRSTUV/worker/events") == "session events"
    assert report.categorize("api.anthropic.com", "/api/event_logging/v2/batch") == "telemetry"
    assert report.categorize("o123.ingest.sentry.io", "/api/1/envelope/") == "telemetry"
    assert report.categorize("api.anthropic.com", "/v1/models") == "other"
    assert report.normalize("/v1/code/sessions/cse_01ABCDEFGHIJKLMNOPQRSTUV/worker/events?x=1") == "/v1/code/sessions/<id>/worker/events"


def make_run(root: Path, label: str, seed: int, ended_offset: float) -> Path:
    run_dir = root / label / f"run-{seed}"
    run_dir.mkdir(parents=True)
    started = 1_000_000.0
    with (run_dir / "session.flows").open("wb") as fh:
        writer = mio.FlowWriter(fh)
        for i, (host, path, size, at) in enumerate([
            ("api.anthropic.com", b"/v1/messages", 5000, 1.0),
            ("api.anthropic.com", b"/v1/code/sessions/cse_01ABCDEFGHIJKLMNOPQRSTUV/worker/events", 3000, 2.0),
            ("api.anthropic.com", b"/api/event_logging/v2/batch", 40000, 3.0),
            ("api.anthropic.com", b"/api/event_logging/v2/batch", 40000, ended_offset + 5.0),
        ]):
            flow = tflow.tflow(req=tutils.treq(host=host, path=path, method=b"POST", content=b"x" * size), resp=True)
            flow.request.timestamp_start = started + at
            writer.add(flow)
    (run_dir / "audit.log").write_text(
        json.dumps({"ts": "t", "host": "api.anthropic.com", "path": "/v1/messages", "mode": "audit", "count": 2,
                    "findings": [{"kind": "vault", "preview": "a", "key": "content"},
                                 {"kind": "canary", "preview": "b", "key": "content", "label": "/w/.env"}]}) + "\n"
        + json.dumps({"ts": "t", "host": "api.anthropic.com", "path": "/v1/code/sessions/x/worker/events", "mode": "audit", "count": 1,
                      "findings": [{"kind": "canary", "preview": "b", "key": "stdout", "label": "/w/.env"}]}) + "\n")
    (run_dir / "meta.json").write_text(json.dumps({
        "label": label, "agent": "fake", "agent_version": "fake 1.0", "keyfence_version": "0.4.0", "seed": seed,
        "started": started, "agent_ended": started + ended_offset, "proxy_ended": started + ended_offset + 10}))
    return run_dir


def test_report_builds_matrix_json_and_chart(tmp_path):
    make_run(tmp_path, "fake", 1, 4.0)
    make_run(tmp_path, "fake", 2, 4.0)
    agents = report.build(tmp_path)
    assert len(agents) == 1
    a = agents[0]
    assert a["runs"] == 2 and a["hosts"] == ["api.anthropic.com"]
    assert a["env_read_runs"] == 2 and a["canary_via"] == ["content", "stdout"]
    assert a["requests_with_canary"]["min"] == 2
    assert a["telemetry_separate"] is True
    assert a["after_exit_requests"]["min"] == 1 and a["after_exit_bytes"]["min"] > 40000
    assert a["bytes_by_category"]["telemetry"]["mean"] > a["bytes_by_category"]["conversation"]["mean"]
    md = (tmp_path / "report.md").read_text()
    assert "| fake | fake 1.0 | 2 |" in md and "content, stdout" in md
    svg = (tmp_path / "bytes.svg").read_text()
    assert svg.count("<rect") >= 3 and "telemetry" in svg and 'fill="#1baf7a"' in svg
    assert json.loads((tmp_path / "report.json").read_text())[0]["label"] == "fake"


def test_report_without_flows_or_audit(tmp_path):
    run_dir = tmp_path / "empty" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({"label": "empty", "seed": 1, "started": time.time(), "agent_ended": time.time()}))
    agents = report.build(tmp_path)
    assert agents[0]["requests"]["max"] == 0 and agents[0]["env_read_runs"] == 0
    assert "| empty |" in (tmp_path / "report.md").read_text()
