import os
import re
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
ENTRYPOINT = ROOT / "docker-entrypoint.sh"


def _instructions():
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


def _instruction(name):
    for instruction in _instructions():
        if instruction.startswith(name):
            return instruction
    raise AssertionError(f"the Dockerfile has no {name} instruction")


def _healthcheck():
    return _instruction("HEALTHCHECK").split(" CMD ", 1)[1]


def _serve(status, body):
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


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _path():
    return f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}"


def _run_healthcheck(port, timeout=60):
    command = _healthcheck().replace("8888", str(port))
    return subprocess.run(
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": _path(), "HOME": str(ROOT)},
    )


def _run_entrypoint(args, data_dir, config_example=None, extra_env=None):
    env = {
        "PATH": _path(),
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


def test_healthcheck_fails_when_the_addon_answers_with_something_else():
    bodies = {
        "bad_gateway": _serve(502, "<html>bad gateway</html>"),
        "plain_proxy": _serve(200, '{"upstream_received": {}}'),
        "not_json": _serve(200, "<html>hello</html>"),
        "keyfence_blocked": _serve(403, '{"error": {"type": "keyfence_blocked"}}'),
    }
    try:
        for name, server in bodies.items():
            done = _run_healthcheck(server.server_port)
            assert done.returncode != 0, f"the healthcheck passed against a {name} response"
    finally:
        for server in bodies.values():
            server.shutdown()
            server.server_close()


def test_healthcheck_passes_when_the_addon_answers():
    server = _serve(200, '{"keyfence": "0.8.0.dev0", "mode": "redact", "hosts": 9}')
    try:
        done = _run_healthcheck(server.server_port)
        assert done.returncode == 0, done.stderr
    finally:
        server.shutdown()
        server.server_close()


def test_healthcheck_fails_when_nothing_is_listening():
    assert _run_healthcheck(_free_port()).returncode != 0


def test_healthcheck_asks_the_proxy_for_the_addon_and_not_only_for_the_port():
    command = _healthcheck()
    assert "probe" in command
    assert "create_connection" not in command


def test_image_runs_as_a_non_root_user():
    users = [instruction.split()[1] for instruction in _instructions() if instruction.startswith("USER ")]
    assert users, "the Dockerfile never switches away from root"
    assert users[-1] not in ("root", "0")
    assert re.fullmatch(r"[a-z_][a-z0-9_-]*", users[-1]), f"{users[-1]} is not a user name"


def test_image_installs_pinned_dependencies():
    installs = [instruction for instruction in _instructions() if "pip install" in instruction]
    assert installs
    pins = dict(re.findall(r"^ARG ([A-Z0-9_]+)=([0-9][0-9.]*)$", DOCKERFILE.read_text(), re.M))
    for requirement, argument in (("mitmproxy", "MITMPROXY_VERSION"), ("PyYAML", "PYYAML_VERSION")):
        assert f"{requirement}==${{{argument}}}" in " ".join(installs)
        assert pins.get(argument), f"{argument} has no version"
    assert not [instruction for instruction in installs if re.search(r"[><~]=[0-9]", instruction)]


def test_entrypoint_refuses_to_start_when_the_data_directory_is_not_writable(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o500)
    try:
        done = _run_entrypoint(["status"], data_dir)
    finally:
        data_dir.chmod(0o700)
    assert done.returncode != 0
    assert "sudo chown" in done.stderr
    assert str(data_dir) in done.stderr
    assert not (data_dir / "certs").exists()


def test_entrypoint_creates_the_config_and_the_certs_directory(tmp_path):
    data_dir = tmp_path / "data"
    done = _run_entrypoint(["status"], data_dir)
    assert done.returncode == 0, done.stderr
    assert (data_dir / "certs").is_dir()
    assert (data_dir / "config.yaml").read_text() == (ROOT / "config.example.yaml").read_text()


def test_entrypoint_keeps_a_config_that_is_already_there(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.yaml").write_text("mode: placeholder\n")
    done = _run_entrypoint(["status"], data_dir)
    assert done.returncode == 0, done.stderr
    assert (data_dir / "config.yaml").read_text() == "mode: placeholder\n"


def test_entrypoint_defaults_to_the_data_directory_of_the_image():
    env = " ".join(instruction for instruction in _instructions() if instruction.startswith("ENV "))
    assert "KEYFENCE_HOME=/data" in env
    assert "${KEYFENCE_HOME:-/data}" in ENTRYPOINT.read_text()
