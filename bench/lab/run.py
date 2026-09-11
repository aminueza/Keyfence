from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB.parent.parent))
from bench.lab.secrets import dotenv, private_key  # noqa: E402

DEFAULT_PORT = 8877


def prepare_workspace(seed: int, base: Path | None = None) -> Path:
    workspace = Path(tempfile.mkdtemp(prefix="keyfence-lab-", dir=base))
    for item in (LAB / "app").iterdir():
        target = workspace / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy(item, target)
    (workspace / ".env").write_text(dotenv(seed))
    (workspace / "deploy_key.pem").write_text(private_key(seed))
    return workspace


def prepare_home(base: Path) -> Path:
    home = base / "keyfence-home"
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("mode: audit\nnotice: false\n")
    return home


def keyfence(home: Path, *args: str, cwd: Path | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, KEYFENCE_HOME=str(home), KEYFENCE_CONFIG=str(home / "config.yaml"))
    return subprocess.run(["keyfence", *args], cwd=cwd, env=env, capture_output=capture, text=True)


def keyfence_version() -> str:
    try:
        from importlib.metadata import version
        return version("keyfence")
    except Exception:
        return "unknown"


def agent_binary(agent: str) -> str:
    words = agent.split()
    shells = {"bash", "sh", "zsh", "python", "python3", "node", "npx", "uvx", "env"}
    for word in words:
        if word not in shells and not word.startswith("-") and "=" not in word:
            return Path(word).name
    return words[0] if words else "unknown"


def version_of(command: str) -> str:
    try:
        done = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=20)
        return (done.stdout or done.stderr).strip().splitlines()[0] if (done.stdout or done.stderr).strip() else "unknown"
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return "unknown"


def one_run(label: str, agent: str, out: Path, seed: int, port: int, linger: float, prompt: str) -> Path:
    run_dir = out.resolve() / label / f"run-{seed}"
    run_dir.mkdir(parents=True, exist_ok=True)
    workspace = prepare_workspace(seed)
    home = prepare_home(run_dir)
    keyfence(home, "import", str(workspace / ".env"), cwd=workspace)
    canary = keyfence(home, "canary", str(workspace / ".env"), cwd=workspace)
    command = agent.replace("{prompt}", prompt)
    ended_cmd = "python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s"
    wrapper = f"{command}; echo $? > {run_dir / 'exit'}; ({ended_cmd}) > {run_dir / 'ended'}"
    started = time.time()
    with (run_dir / "terminal.txt").open("w") as terminal:
        env = dict(os.environ, KEYFENCE_HOME=str(home), KEYFENCE_CONFIG=str(home / "config.yaml"))
        proc = subprocess.run(
            ["keyfence", "exec", "-p", str(port), "--record", str(run_dir / "session.flows"),
             "--linger", str(linger), "--", "bash", "-c", wrapper],
            cwd=workspace, env=env, stdout=terminal, stderr=subprocess.STDOUT, text=True)
    finished = time.time()
    ended_file = run_dir / "ended"
    ended = float(ended_file.read_text().strip()) if ended_file.exists() else finished
    audit = home / "audit.log"
    if audit.exists():
        shutil.copy(audit, run_dir / "audit.log")
    meta = {
        "label": label,
        "agent": agent,
        "agent_binary": agent_binary(agent),
        "agent_version": version_of(agent_binary(agent)),
        "keyfence_version": keyfence_version(),
        "seed": seed,
        "prompt": prompt,
        "started": started,
        "agent_ended": ended,
        "proxy_ended": finished,
        "linger": linger,
        "exec_exit": proc.returncode,
        "canary": canary.stdout.strip(),
        "workspace_files": sorted(p.name for p in workspace.iterdir()),
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    shutil.rmtree(workspace, ignore_errors=True)
    shutil.rmtree(home / "env", ignore_errors=True)
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an agent inside keyfence and keep the evidence.")
    parser.add_argument("--label", required=True, help="agent name used for the output directory, e.g. claude-code")
    parser.add_argument("--agent", required=True,
                        help="shell command to run in the workspace; {prompt} is replaced by the lab prompt")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", default="lab-out")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--linger", type=float, default=60.0, help="seconds to keep capturing after the agent exits")
    args = parser.parse_args(argv)
    prompt = (LAB / "prompt.txt").read_text().strip()
    out = Path(args.out)
    for i in range(args.runs):
        run_dir = one_run(args.label, args.agent, out, args.seed + i, args.port, args.linger, prompt)
        print(f"{args.label} run {i + 1}/{args.runs}: {run_dir}")
    print(f"Now: python bench/lab/report.py {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
