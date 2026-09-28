# Development

```bash
git clone git@github.com:aminueza/keyfence.git
cd keyfence
pip install -e '.[dev]'
```

## Tests

```bash
pytest                            # unit tests
bash tests/integration_test.sh    # end-to-end against a real mitmproxy
```

`pytest` always measures coverage (`addopts` in `pyproject.toml`) and fails
below 90%. The
integration script starts an echo server, a WebSocket echo server and a
real `mitmdump` with the keyfence addon, then checks redact, placeholder,
streaming, block, WebSocket frames, `keyfence exec` and
`keyfence selftest` in every mode end to end.

Fake keys used in tests are assembled at runtime in `tests/fakes.py` so
that secret scanners, including GitHub push protection, do not flag them.

### Checking a leak from inside `keyfence exec`

`keyfence exec` sets the proxy and CA variables for the child and runs it
with `subprocess.call`, so the child's stdout is never touched
(`keyfence/runner.py`). A shell, and a person at the terminal, see
everything the child printed, in clear, a leaked value included. The
response side is the same: the addon scans the request body and the frames
a client sends, and its response hooks only put placeholders back
(`keyfence/addon.py`, `keyfence/streaming.py`). A secret in a response body
passes unchanged.

The blind spot belongs to the model. The output an agent read is not the
terminal: it reaches the provider inside the next request, and that request
is a request, so keyfence scans it and rewrites it. In `redact` mode the
model reads `[REDACTED:kind]` where the leak was; in `placeholder` mode,
`<<SECRET_...>>`. A probe that carries that marker literally is not a
finding, so it arrives unchanged and the model reads the same text in both
cases. Judging the output by eye, a model cannot tell a leaking run from a
clean one. That is what produced a false positive while the WebSocket frame
scanning was under development
([PR #69](https://github.com/aminueza/keyfence/pull/69)).

Decide in code instead:

- Build the value in the test client at run time, from fragments, so a
  real-shaped secret reaches the detector and nothing secret-shaped is
  committed. `tests/fakes.py` serves the opposite purpose: it keeps
  committed test keys out of secret scanners and push protection, and only
  `tests/test_detectors.py` imports it.
- Assert on what the provider received. The listener the test starts is the
  only honest view: `tests/integration_test.sh` logs every body to
  `upstream_received.log` and echoes it back inside
  `{"upstream_received": ...}`, and each check greps that log or parses the
  echoed body in Python.
- Trust the exit status. The script runs under `set -euo pipefail` and
  exits on the first failed check, so the verdict sits in the exit code,
  which no redaction touches.

## Layout

| path | role |
|---|---|
| `keyfence/addon.py` | mitmproxy addon: request and WebSocket frame scanning, response restoration, audit log |
| `keyfence/detectors.py` | vault, pattern and entropy detection, JSON key tracking |
| `keyfence/rules.py` | gitleaks TOML loader |
| `keyfence/rules/gitleaks.toml` | bundled ruleset (MIT, see `GITLEAKS-LICENSE`) |
| `keyfence/streaming.py` | placeholder restoration inside SSE streams |
| `keyfence/notice.py` | system prompt notice for changed requests |
| `keyfence/importer.py` | secret extraction from `.env`, credential files and the environment |
| `keyfence/runner.py` | `keyfence exec`: proxy lifecycle, child environment, local capture mode |
| `keyfence/selftest.py` | `keyfence selftest`: temporary home, local listener, one request per mode and the verdict |
| `keyfence/hooks.py` | agent hook: sensitive path rules and Claude Code settings.json install |
| `keyfence/pi.py` | pi extension: source template and install/remove |
| `keyfence/export.py` | audit log export as JSONL and OTLP/HTTP log records |
| `keyfence/vault.py` | salted hash store |
| `keyfence/ignore.py` | `ignore_keys` and `ignore_values` matching, hashed with the vault salt |
| `keyfence/config.py` | YAML config |
| `keyfence/entry.py` | console script entry; serves `hook` without loading the rest |
| `keyfence/cli.py` | command line |

## Conventions

- No comments or docstrings in code. Rationale goes in the commit message.
- Every change ships with tests.
- Commit messages describe the problem and the fix in plain English.

## CI

GitHub Actions runs the unit tests on Linux (Python 3.12 to 3.14) and macOS,
the integration script on both, and builds the wheel to check that the
bundled rules ship in the package.

## Benchmark

```bash
python bench/run.py            # keyfence configurations, plus gitleaks if installed
python bench/run.py --json     # machine-readable
```

The corpus is generated from a fixed seed, so nothing secret-looking is
committed. Results are kept in `docs/benchmark.md`.

## Images

`docs/keyfence-flow.svg` is the source of the README diagram; render it
with resvg (`pip install resvg-py`) at 2x to `docs/keyfence-flow.png`.
`docs/keyfence-demo.gif` is rendered from the real `keyfence demo` output
by `tools/demo_gif.py` (needs Pillow and the macOS Menlo and Helvetica Neue
fonts):

```bash
python tools/demo_gif.py docs/keyfence-demo.gif
```

## Releasing

Releases are published to PyPI by the `Release` workflow through PyPI
trusted publishing, so no token is stored anywhere. One-time setup on PyPI:
add a pending publisher for project `keyfence` with owner `aminueza`,
repository `keyfence`, workflow `release.yml` and environment `pypi`, and
create the `pypi` environment in the GitHub repository settings.

To release:

1. Set `__version__` in `keyfence/__init__.py` to `X.Y.Z`, set `version`
   in `plugin/.claude-plugin/plugin.json` to the same `X.Y.Z` so the
   Claude Code marketplace picks up the new `guard.py`, and rename the
   `Unreleased` section of `CHANGELOG.md` to `X.Y.Z (date)`.
2. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Right after, set `__version__` to the next dev version (`X.Y+1.0.dev0`),
   open a new `Unreleased` section in `CHANGELOG.md` and commit.

The workflow builds the sdist and wheel, checks that the tag matches the
package version, and publishes.

Between releases `main` carries a `.dev0` version, so `keyfence doctor`
tells a checkout of `main` apart from the build published on PyPI.
`tests/test_version.py` checks that a release version has its changelog
section, that a dev version has an `Unreleased` one, and that the plugin
manifest carries the last released version.
