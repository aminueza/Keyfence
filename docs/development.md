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

Coverage must stay at or above 90%; `pytest` fails below that. The
integration script starts an echo server and a real `mitmdump` with the
keyfence addon, then checks redact, placeholder, streaming, block and
`keyfence exec` end to end.

Fake keys used in tests are assembled at runtime in `tests/fakes.py` so
that secret scanners, including GitHub push protection, do not flag them.

## Layout

| path | role |
|---|---|
| `keyfence/addon.py` | mitmproxy addon: request scanning, response restoration, audit log |
| `keyfence/detectors.py` | vault, pattern and entropy detection, JSON key tracking |
| `keyfence/rules.py` | gitleaks TOML loader |
| `keyfence/rules/gitleaks.toml` | bundled ruleset (MIT, see `GITLEAKS-LICENSE`) |
| `keyfence/streaming.py` | placeholder restoration inside SSE streams |
| `keyfence/notice.py` | system prompt notice for changed requests |
| `keyfence/importer.py` | secret extraction from `.env`, credential files and the environment |
| `keyfence/runner.py` | `keyfence exec`: proxy lifecycle and child environment |
| `keyfence/vault.py` | salted hash store |
| `keyfence/config.py` | YAML config |
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

## Releasing

Releases are published to PyPI by the `Release` workflow through PyPI
trusted publishing, so no token is stored anywhere. One-time setup on PyPI:
add a pending publisher for project `keyfence` with owner `aminueza`,
repository `keyfence`, workflow `release.yml` and environment `pypi`, and
create the `pypi` environment in the GitHub repository settings.

To release:

1. Bump `__version__` in `keyfence/__init__.py`.
2. Commit, then tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The workflow builds the sdist and wheel, checks that the tag matches the
package version, and publishes.
