import json
import re
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
