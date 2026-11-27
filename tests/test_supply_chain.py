import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def requirement_blocks(name):
    return [block for block in re.split(r"\n(?=[A-Za-z])", (ROOT / name).read_text()) if re.match(r"[A-Za-z]", block)]


def pinned(name):
    pins = (re.match(r"([A-Za-z0-9_.-]+)==(\S+)", block) for block in requirement_blocks(name))
    return {pin.group(1).lower(): pin.group(2) for pin in pins}


def test_dependabot_watches_the_actions_the_python_pins_and_the_base_image():
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    entries = {(entry["package-ecosystem"], entry["directory"]) for entry in config["updates"]}
    assert {("github-actions", "/"), ("pip", "/"), ("docker", "/")} <= entries
    docker = next(entry for entry in config["updates"] if entry["package-ecosystem"] == "docker")
    python = next(rule for rule in docker["ignore"] if rule["dependency-name"] == "python")
    assert set(python["update-types"]) == {"version-update:semver-major", "version-update:semver-minor"}


def test_each_compiled_requirements_file_matches_the_pins_of_its_source():
    for name in ("requirements-release", "requirements-docker"):
        compiled = pinned(f"{name}.txt")
        for line in (ROOT / f"{name}.in").read_text().splitlines():
            match = re.match(r"([A-Za-z0-9_.-]+)==(\S+)", line)
            if match:
                assert compiled.get(match.group(1).lower()) == match.group(2), f"{name}.txt is stale for {line}"


def test_every_release_tool_is_pinned_by_version_and_hash():
    blocks = requirement_blocks("requirements-release.txt")
    assert blocks
    for block in blocks:
        assert re.match(r"[A-Za-z0-9_.-]+==\S+ \\", block), block.splitlines()[0]
        assert "--hash=sha256:" in block, block.splitlines()[0]
    assert {"build", "cyclonedx-bom", "setuptools"} <= set(pinned("requirements-release.txt"))


def test_the_pinned_setuptools_can_build_the_project_without_isolation():
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    floor = int(re.match(r"setuptools>=(\d+)", next(r for r in requires if r.startswith("setuptools"))).group(1))
    for name in ("requirements-release.txt", "requirements-docker.txt"):
        assert int(pinned(name)["setuptools"].split(".")[0]) >= floor, name


def test_the_ci_sbom_describes_a_clean_environment_and_not_the_ci_tools():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    runs = [step["run"] for step in workflow["jobs"]["package"]["steps"] if "run" in step]
    sbom = next(run for run in runs if "cyclonedx-py environment" in run)
    assert "python -m venv sbom-env" in sbom and "sbom-env/bin/python" in sbom
    assert any("cyclonedx-bom" in run and "assert" in run for run in runs)
    installs = [run for run in runs if "pip install" in run and "dist/" not in run]
    assert installs and all("--require-hashes -r requirements-release.txt" in run for run in installs), installs
    builds = [run for run in runs if "python -m build" in run]
    assert builds and all("--no-isolation" in run for run in builds), builds


def test_ci_builds_the_docker_image():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    runs = [step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]]
    assert any(run.startswith("docker build") for run in runs)
