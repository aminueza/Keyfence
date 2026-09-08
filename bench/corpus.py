from __future__ import annotations

import base64
import json
import random
import string
import sysconfig
from dataclasses import dataclass
from pathlib import Path

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
B64URL = ALNUM + "-_"
WORDS = ("correct", "horse", "battery", "staple", "purple", "monkey", "dish", "washer",
         "river", "stone", "cloud", "apple", "tiger", "piano", "silver", "maple")
REPO = Path(__file__).resolve().parent.parent


@dataclass
class Sample:
    label: str
    category: str
    text: str
    secret: str | None = None


def _rand(r: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def _pem(r: random.Random) -> str:
    body = "\n".join(_rand(r, 64, ALNUM + "+/") for _ in range(6))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


BASE32 = string.ascii_uppercase + "234567"

FORMATS = {
    "aws-access-key-id": lambda r: "AKIA" + _rand(r, 16, BASE32),
    "github-pat": lambda r: "ghp_" + _rand(r, 36),
    "github-fine-grained": lambda r: "github_pat_" + _rand(r, 82, ALNUM + "_"),
    "gitlab-pat": lambda r: "glpat-" + _rand(r, 20),
    "openai": lambda r: "sk-proj-" + _rand(r, 74, B64URL) + "T3BlbkFJ" + _rand(r, 74, B64URL),
    "anthropic": lambda r: "sk-ant-api03-" + _rand(r, 93, B64URL) + "AA",
    "slack-bot-token": lambda r: "xoxb-" + _rand(r, 12, string.digits) + "-" + _rand(r, 13, string.digits) + "-" + _rand(r, 24),
    "slack-webhook": lambda r: "https://hooks.slack.com/services/T" + _rand(r, 8, UPPER_DIGITS) + "/B" + _rand(r, 8, UPPER_DIGITS) + "/" + _rand(r, 24),
    "google-api-key": lambda r: "AIza" + _rand(r, 35, B64URL),
    "stripe-live": lambda r: "sk_live_" + _rand(r, 24),
    "twilio": lambda r: "SK" + _rand(r, 32, HEX),
    "sendgrid": lambda r: "SG." + _rand(r, 22, B64URL) + "." + _rand(r, 43, B64URL),
    "npm": lambda r: "npm_" + _rand(r, 36),
    "pypi": lambda r: "pypi-AgEIcHlwaS5vcmc" + _rand(r, 60, B64URL),
    "huggingface": lambda r: "hf_" + _rand(r, 34, string.ascii_letters),
    "doppler": lambda r: "dp.pt." + _rand(r, 43),
    "jwt": lambda r: "eyJ" + _rand(r, 20, B64URL) + ".eyJ" + _rand(r, 40, B64URL) + "." + _rand(r, 43, B64URL),
    "pem-private-key": _pem,
    "random-password": lambda r: _rand(r, 20, ALNUM + "!#%&*+-_"),
    "passphrase": lambda r: "-".join(r.choice(WORDS) for _ in range(4)) + str(r.randint(10, 99)),
}

FORMATLESS = {"random-password", "passphrase"}

CONTEXTS = {
    "env-line": lambda s, r: f"API_TOKEN={s}\n",
    "json-message": lambda s, r: json.dumps({"model": "gpt", "messages": [{"role": "user", "content": f"here is the config I use: token {s} and nothing else"}]}),
    "prose": lambda s, r: f"I pasted the credential by accident, it is {s}, please ignore it.",
    "code": lambda s, r: f'import os\n\nclient = Client(api_key="{s}")\nclient.run()\n',
    "yaml": lambda s, r: f"service:\n  name: billing\n  secret: {s}\n  region: us-east-1\n",
    "curl": lambda s, r: f'curl -H "Authorization: Bearer {s}" https://api.example.com/v1/me',
    "tool-result": lambda s, r: json.dumps({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01" + _rand(r, 24), "content": f"     1→DB_PASSWORD={s}\n     2→PORT=5432\n"}]}]}),
}

BLOCK_CONTEXTS = {"pem-private-key": ("prose", "json-message", "tool-result", "code")}


def positives(seed: int = 7, per_format: int = 3) -> list[Sample]:
    r = random.Random(seed)
    out = []
    for name, make in FORMATS.items():
        contexts = BLOCK_CONTEXTS.get(name, tuple(CONTEXTS))
        for i in range(per_format):
            for ctx in contexts:
                secret = make(r)
                out.append(Sample(f"{name}/{ctx}/{i}", name, CONTEXTS[ctx](secret, r), secret))
    return out


def _chunks(path: Path, size: int = 60) -> list[str]:
    lines = path.read_text(errors="replace").splitlines()
    return ["\n".join(lines[i:i + size]) for i in range(0, len(lines), size) if lines[i:i + size]]


def _code_samples() -> list[Sample]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    files = [
        *sorted((REPO / "keyfence").glob("*.py")),
        stdlib / "json" / "__init__.py",
        stdlib / "argparse.py",
        stdlib / "http" / "client.py",
        stdlib / "pathlib" / "__init__.py",
        stdlib / "dataclasses.py",
    ]
    out = []
    for f in files:
        if not f.exists():
            continue
        for i, chunk in enumerate(_chunks(f)):
            out.append(Sample(f"code/{f.name}/{i}", "code", chunk))
    return out


def _prose_samples() -> list[Sample]:
    out = []
    for f in sorted((REPO / "docs").glob("*.md")) + [REPO / "README.md"]:
        for i, chunk in enumerate(_chunks(f, 40)):
            out.append(Sample(f"prose/{f.name}/{i}", "prose", chunk))
    return out


def _claude_code_bodies(r: random.Random, n: int) -> list[Sample]:
    out = []
    for i in range(n):
        signature = base64.b64encode(r.randbytes(r.randint(150, 400))).decode()
        image = base64.b64encode(r.randbytes(r.randint(300, 900))).decode()
        tool_id = "toolu_01" + _rand(r, 24)
        body = {
            "model": "claude-fable-5-1",
            "max_tokens": 8000,
            "system": [{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": "refactor the parser and run the tests"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "Read the file first.", "signature": signature},
                    {"type": "tool_use", "id": tool_id, "name": "Bash", "input": {"command": f"git log --oneline -3 && sha256sum parser.py"}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": tool_id, "content": f"{_rand(r, 7, HEX)} fix parser\n{_rand(r, 64, HEX)}  parser.py\n"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image}},
                ]},
            ],
            "metadata": {"user_id": json.dumps({"device_id": _rand(r, 64, HEX), "session_id": f"{_rand(r, 8, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 12, HEX)}"})},
        }
        out.append(Sample(f"claude-code/{i}", "claude-code-body", json.dumps(body)))
    return out


def _telemetry(r: random.Random, n: int) -> list[Sample]:
    out = []
    for i in range(n):
        events = [base64.b64encode(json.dumps({"user": _rand(r, 40, HEX), "session": _rand(r, 24), "n": k}).encode()).decode() for k in range(r.randint(5, 30))]
        out.append(Sample(f"telemetry/{i}", "telemetry", json.dumps({"events": events})))
    return out


def _logs(r: random.Random, n: int) -> list[Sample]:
    out = []
    for i in range(n):
        lines = []
        for _ in range(25):
            lines.append(
                f"2026-09-08T15:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}Z INFO req_{_rand(r, 16)} "
                f"trace={_rand(r, 32, HEX)} user={_rand(r, 8, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 4, HEX)}-{_rand(r, 12, HEX)} "
                f"ip=10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)} commit={_rand(r, 40, HEX)} took={r.randint(1, 900)}ms")
        out.append(Sample(f"logs/{i}", "logs", "\n".join(lines)))
    return out


def _lockfiles(r: random.Random, n: int) -> list[Sample]:
    out = []
    for i in range(n):
        entries = {}
        for k in range(12):
            name = f"pkg-{_rand(r, 6, string.ascii_lowercase)}"
            integrity = "sha512-" + base64.b64encode(r.randbytes(64)).decode()
            entries[f"node_modules/{name}"] = {
                "version": f"{r.randint(0, 9)}.{r.randint(0, 20)}.{r.randint(0, 9)}",
                "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
                "integrity": integrity,
            }
        gosum = "\n".join(
            f"github.com/{_rand(r, 6, string.ascii_lowercase)}/{_rand(r, 5, string.ascii_lowercase)} v1.{r.randint(0, 9)}.{r.randint(0, 9)} h1:{base64.b64encode(r.randbytes(32)).decode()}"
            for _ in range(10))
        out.append(Sample(f"lockfile/npm/{i}", "lockfile", json.dumps({"packages": entries}, indent=2)))
        out.append(Sample(f"lockfile/gosum/{i}", "lockfile", gosum))
    return out


def negatives(seed: int = 7) -> list[Sample]:
    r = random.Random(seed)
    return [
        *_code_samples(),
        *_prose_samples(),
        *_claude_code_bodies(r, 40),
        *_telemetry(r, 20),
        *_logs(r, 20),
        *_lockfiles(r, 10),
    ]


def materialize(samples: list[Sample], root: Path) -> dict[str, Path]:
    paths = {}
    for i, s in enumerate(samples):
        path = root / s.category / f"{i:04d}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(s.text)
        paths[s.label] = path
    return paths
