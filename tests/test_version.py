import json
import re
import tomllib
from pathlib import Path

from keyfence import __version__, doctor, runner

ROOT = Path(__file__).resolve().parent.parent
RELEASE = re.compile(r"^\d+\.\d+\.\d+$")
DEV = re.compile(r"^\d+\.\d+\.\d+\.dev\d+$")


def changelog_headings() -> list[str]:
    text = (ROOT / "CHANGELOG.md").read_text()
    return re.findall(r"^## (\S+)", text, flags=re.M)


def test_version_is_a_release_or_a_dev_prerelease():
    assert RELEASE.match(__version__) or DEV.match(__version__)


def test_release_version_has_a_changelog_section_and_dev_version_has_unreleased():
    headings = changelog_headings()
    if RELEASE.match(__version__):
        assert __version__ in headings
        assert "Unreleased" not in headings
    else:
        assert headings[0] == "Unreleased"
        assert __version__ not in headings


def test_dev_version_is_ahead_of_the_last_release():
    if not DEV.match(__version__):
        return
    released = [h for h in changelog_headings() if RELEASE.match(h)]
    last = tuple(int(p) for p in released[0].split("."))
    current = tuple(int(p) for p in __version__.split(".dev")[0].split("."))
    assert current > last


def test_certifi_is_declared_as_a_project_dependency():
    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    names = {re.match(r"[A-Za-z0-9_.-]+", requirement).group().lower() for requirement in dependencies}
    assert "certifi" in names


def certifi_floors() -> dict[str, list[str]]:
    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    required = (ROOT / "requirements.txt").read_text().splitlines()
    return {
        "pyproject.toml": [re.match(r"certifi>=(\S+)", d).group(1) for d in dependencies if d.lower().startswith("certifi>=")],
        "requirements.txt": [re.match(r"certifi>=(\S+)", l).group(1) for l in required if l.startswith("certifi>=")],
    }


def certifi_release(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def test_the_certifi_floor_is_a_current_year_trust_store():
    for floors in certifi_floors().values():
        assert floors
        for floor in floors:
            assert certifi_release(floor) >= (2026, 1, 4)


def test_pyproject_and_requirements_declare_the_same_certifi_floor():
    floors = certifi_floors()
    assert floors["pyproject.toml"] == floors["requirements.txt"]


def test_plugin_manifest_carries_the_released_version():
    manifest = json.loads((ROOT / "plugin" / ".claude-plugin" / "plugin.json").read_text())
    released = [h for h in changelog_headings() if RELEASE.match(h)]
    expected = __version__ if RELEASE.match(__version__) else released[0]
    assert manifest["version"] == expected


def test_doctor_reports_the_installed_version(home, monkeypatch):
    monkeypatch.setattr(runner, "port_open", lambda port, host: False)
    checks = doctor.run_checks(8888, cwd=home)
    assert checks[0].label == "keyfence"
    assert checks[0].detail.startswith(f"{__version__} on Python ")


def test_pep639_license_needs_a_setuptools_that_reads_it():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    if not isinstance(project["project"].get("license"), str):
        return
    requires = project["build-system"]["requires"]
    setuptools = [r for r in requires if r.split(">=")[0].strip() == "setuptools"]
    assert setuptools, f"no setuptools in build-system.requires: {requires}"
    assert all(re.match(r"^setuptools>=(\d+)", r) and int(re.match(r"^setuptools>=(\d+)", r).group(1)) >= 77 for r in setuptools), requires


def test_the_declared_mitmproxy_floor_knows_every_option_keyfence_sets():
    """`tcp_timeout` arrives in mitmproxy 12.2.1, and mitmdump defers an option it does not know (#215).

    A deferred option is applied only when an addon registers it, so on 10.0 through 12.2.0 the
    `--set tcp_timeout=` keyfence passes is accepted silently and the built-in 600 s stays. Every
    version the declared range allows has to know the options keyfence sets.
    """
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    mitmproxy = [d for d in declared if d.split(">=")[0].strip() == "mitmproxy"]
    assert mitmproxy, f"no mitmproxy in dependencies: {declared}"
    for spec in mitmproxy:
        floor = re.match(r"^mitmproxy>=(\d+)\.(\d+)\.(\d+)", spec)
        assert floor, f"mitmproxy is declared without a full floor: {spec}"
        assert tuple(int(p) for p in floor.groups()) >= (12, 2, 1), spec

    # The same floor in requirements.txt, since a source install uses that file.
    requirements = (ROOT / "requirements.txt").read_text()
    line = [l for l in requirements.splitlines() if l.strip().startswith("mitmproxy")]
    assert line, "requirements.txt declares no mitmproxy"
    assert re.match(r"^mitmproxy>=12\.2\.1", line[0].strip()), line[0]

    # And the install that runs this suite has to know the option keyfence passes.
    from mitmproxy.options import Options
    assert "tcp_timeout" in Options()
