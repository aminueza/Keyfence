import os
import re
import socket
import subprocess
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
ENTRYPOINT = ROOT / "docker-entrypoint.sh"
PYPROJECT = ROOT / "pyproject.toml"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="every test here runs the image entrypoint with a POSIX shell")


def instructions():
    joined = []
    buffer = ""
    for line in DOCKERFILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        joined.append(buffer)
        buffer = ""
    return joined


def instruction(name):
    for line in instructions():
        if line.startswith(name):
            return line
    raise AssertionError(f"the Dockerfile has no {name} instruction")


def healthcheck():
    return instruction("HEALTHCHECK").split(" CMD ", 1)[1]


def environment():
    return " ".join(line for line in instructions() if line.startswith("ENV "))


def build_args():
    return dict(re.findall(r"^ARG ([A-Z0-9_]+)=(\S+)$", DOCKERFILE.read_text(), re.M))


def serve(status, body):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def host_path():
    return f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}"


def run_healthcheck(port, timeout=60):
    command = healthcheck().replace("8888", str(port))
    return subprocess.run(
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": host_path(), "HOME": str(ROOT)},
    )


def run_entrypoint(args, data_dir, config_example=None, extra_env=None):
    env = {
        "PATH": host_path(),
        "HOME": str(data_dir),
        "KEYFENCE_HOME": str(data_dir),
        "KEYFENCE_CONFIG_EXAMPLE": str(config_example or ROOT / "config.example.yaml"),
    }
    env.update(extra_env or {})
    return subprocess.run(
        ["/bin/sh", str(ENTRYPOINT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def as_root_user():
    return os.name == "posix" and os.geteuid() == 0


@pytest.mark.parametrize(("status", "body", "answer"), [
    (502, "<html>bad gateway</html>", "a bad gateway"),
    (200, '{"upstream_received": {}}', "a plain proxy"),
    (200, "<html>hello</html>", "a proxy that answers in html"),
    (403, '{"error": {"type": "keyfence_blocked"}}', "a blocked request"),
])
def test_healthcheck_fails_when_the_addon_answers_with_something_else(status, body, answer):
    server = serve(status, body)
    try:
        done = run_healthcheck(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
    assert done.returncode != 0, f"the healthcheck passed against {answer}"
    assert not done.stderr, done.stderr


def test_healthcheck_passes_when_the_addon_answers():
    server = serve(200, '{"keyfence": "0.8.0.dev0", "mode": "redact", "hosts": 9}')
    try:
        done = run_healthcheck(server.server_port)
        assert done.returncode == 0, done.stderr
    finally:
        server.shutdown()
        server.server_close()


def test_healthcheck_fails_when_nothing_is_listening():
    done = run_healthcheck(free_port())
    assert done.returncode != 0
    assert not done.stderr, done.stderr


def test_healthcheck_asks_the_proxy_for_the_addon_and_not_only_for_the_port():
    command = healthcheck()
    assert "probe" in command
    assert "create_connection" not in command


def test_image_runs_as_a_non_root_user():
    users = [line.split()[1] for line in instructions() if line.startswith("USER ")]
    assert users, "the Dockerfile never switches away from root"
    assert users[-1] not in ("root", "0")
    assert re.fullmatch(r"[a-z_][a-z0-9_-]*", users[-1]), f"{users[-1]} is not a user name"
    created = " ".join(line for line in instructions() if "useradd" in line)
    uid = re.search(r"--uid (\S+)", created)
    assert uid, "the image creates the user without a uid"
    if uid.group(1).startswith("${"):
        uid = build_args()[uid.group(1)[2:-1]]
    assert int(uid) != 0, "the image user is root"


def test_image_installs_pinned_dependencies():
    installs = [line for line in instructions() if "pip install" in line]
    assert installs
    pins = build_args()
    for requirement, argument in (("mitmproxy", "MITMPROXY_VERSION"), ("PyYAML", "PYYAML_VERSION")):
        assert f"{requirement}==${{{argument}}}" in " ".join(installs)
        assert re.fullmatch(r"[0-9][0-9.]*", pins.get(argument, "")), f"{argument} has no version"
    assert not [line for line in installs if re.search(r"[><~]=[0-9]", line)]


def test_the_image_pins_every_dependency_the_project_declares():
    declared = tomllib.loads(PYPROJECT.read_text())["project"]["dependencies"]
    names = {re.match(r"[A-Za-z0-9_.-]+", requirement).group().lower() for requirement in declared}
    pins = set(re.findall(r'"([A-Za-z0-9_.-]+)==', " ".join(instructions())))
    assert {name.lower() for name in pins} == names


def test_the_image_installs_the_project_without_resolving_dependencies_again():
    installs = [line for line in instructions() if "pip install" in line and line.endswith("/app")]
    assert installs, "the image never installs the project itself"
    assert "--no-deps" in installs[0], "pip resolves the pins again and the image drifts"


def test_the_image_and_the_entrypoint_agree_on_where_the_ca_lives():
    home = re.search(r"KEYFENCE_HOME=(\S+)", environment())
    confdir = re.search(r"MITMPROXY_CONFDIR=(\S+)", environment())
    assert home and confdir, "the image leaves MITMPROXY_CONFDIR unset, so every keyfence command falls back to a home that does not exist"
    assert confdir.group(1) == f"{home.group(1)}/certs"


def test_entrypoint_refuses_to_start_when_the_data_directory_is_not_writable(tmp_path):
    if as_root_user():
        pytest.skip("root can write to any directory")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o500)
    try:
        done = run_entrypoint(["status"], data_dir)
    finally:
        data_dir.chmod(0o700)
    assert done.returncode != 0
    assert "sudo chown" in done.stderr
    assert str(data_dir) in done.stderr
    assert not (data_dir / "certs").exists()


def test_entrypoint_refuses_to_start_when_a_state_file_is_not_writable(tmp_path):
    if as_root_user():
        pytest.skip("root can write to any file")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    audit_log = data_dir / "audit.log"
    audit_log.write_text("{}\n")
    audit_log.chmod(0o400)
    try:
        done = run_entrypoint(["status"], data_dir)
    finally:
        audit_log.chmod(0o600)
    assert done.returncode != 0
    assert str(audit_log) in done.stderr, done.stderr
    assert "sudo chown -R" in done.stderr


def test_entrypoint_creates_the_config_and_the_certs_directory(tmp_path):
    data_dir = tmp_path / "data"
    done = run_entrypoint(["status"], data_dir)
    assert done.returncode == 0, done.stderr
    assert (data_dir / "certs").is_dir()
    assert (data_dir / "config.yaml").read_text() == (ROOT / "config.example.yaml").read_text()


def test_entrypoint_keeps_a_config_that_is_already_there(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.yaml").write_text("mode: placeholder\n")
    done = run_entrypoint(["status"], data_dir)
    assert done.returncode == 0, done.stderr
    assert (data_dir / "config.yaml").read_text() == "mode: placeholder\n"


def test_entrypoint_starts_mitmdump_with_the_certs_of_the_data_directory(tmp_path):
    data_dir = tmp_path / "data"
    args_file = tmp_path / "mitmdump.args"
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "mitmdump"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$MITMDUMP_ARGS"\n')
    stub.chmod(0o755)
    extra_env = {"PATH": f"{stub_dir}{os.pathsep}{host_path()}", "MITMDUMP_ARGS": str(args_file)}
    done = run_entrypoint(["proxy"], data_dir, extra_env=extra_env)
    assert done.returncode == 0, done.stderr
    args = args_file.read_text().split()
    assert "/app/keyfence/addon.py" in args
    assert f"confdir={data_dir / 'certs'}" in args
    assert "--listen-port" in args and "8888" in args


def test_entrypoint_defaults_to_the_data_directory_of_the_image():
    assert "KEYFENCE_HOME=/data" in environment()
    assert "${KEYFENCE_HOME:-/data}" in ENTRYPOINT.read_text()
