import io
import re

import pytest

from keyfence import demo

ANSI = re.compile(r"\033\[[0-9;]*m")


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(scope="module")
def items():
    return demo.lines()


def test_demo_names_no_provider_or_agent(items):
    text = "\n".join(t for _, t in items).lower()
    for word in ("claude", "anthropic", "openai", "gpt", "gemini", "copilot"):
        assert word not in text


def test_demo_walks_through_every_mode_in_order(items):
    headers = [t.split("\t")[0] for k, t in items if k == "mode"]
    assert headers == ["audit", "redact", "placeholder", "block"]


def sections(items):
    out, current = {}, None
    for kind, text in items:
        if kind == "mode":
            current = text.split("\t")[0]
            out[current] = []
        elif current:
            out[current].append(text)
    return {k: "\n".join(v) for k, v in out.items()}


def test_each_mode_shows_the_promised_outcome(items):
    by_mode = sections(items)
    assert demo.DEMO_TOKEN in by_mode["audit"] and demo.DEMO_PASSWORD in by_mode["audit"]
    assert "[REDACTED:github-token]" in by_mode["redact"] and "[REDACTED:vault]" in by_mode["redact"]
    assert demo.DEMO_TOKEN not in by_mode["redact"] and demo.DEMO_PASSWORD not in by_mode["redact"]
    assert re.search(r"GITHUB_TOKEN=<<SECRET_[0-9a-f]+>>", by_mode["placeholder"])
    assert f"git push https://{demo.DEMO_TOKEN}@github.com/you/repo" in by_mode["placeholder"]
    assert "HTTP 403" in by_mode["block"] and "2 secret(s) detected" in by_mode["block"]
    assert demo.DEMO_TOKEN not in by_mode["block"]


def test_demo_ends_with_the_audit_summary_and_next_steps(items):
    text = "\n".join(t for _, t in items)
    assert "4 entries, kinds" in text and "github-token and vault" in text
    assert "keyfence exec -- <agent>" in text and "keyfence selftest" in text


def test_render_is_plain_without_a_tty_and_coloured_with_one(items):
    plain = demo.render(items, styled=False)
    assert not ANSI.search(plain)
    assert plain.splitlines()[0] == "keyfence demo"
    assert re.search(r"^audit        watch first", plain, re.M)
    coloured = demo.render(items, styled=True)
    assert ANSI.search(coloured)
    assert ANSI.sub("", coloured) == plain
    assert f"\033[31m{demo.DEMO_TOKEN}\033[0m" in coloured
    assert "\033[32m[REDACTED:github-token]\033[0m" in coloured
    assert re.search(r"\033\[2m    the model answers with the token: git push https://\033\[0m\033\[32m<<SECRET_", coloured)


def test_run_decides_colour_from_the_stream_and_environment(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    tty = Tty()
    assert demo.run(tty) == 0
    assert ANSI.search(tty.getvalue())
    plain = io.StringIO()
    demo.run(plain)
    assert not ANSI.search(plain.getvalue())
    monkeypatch.setenv("NO_COLOR", "1")
    assert demo.wants_colour(Tty()) is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert demo.wants_colour(Tty()) is False


def test_demo_touches_no_real_home(home, items):
    assert not (home / "vault.json").exists() and not (home / "audit.log").exists()
