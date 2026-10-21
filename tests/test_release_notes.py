import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("release_notes", ROOT / "tools" / "release_notes.py")
release_notes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_notes)

@pytest.fixture(autouse=True)
def no_repository_in_the_environment(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)


SAMPLE = """# Changelog

## Unreleased

- something not released yet

## 0.8.0 (2026-09-28)

- the newest thing
- and another

## 0.7.0 (2026-09-24)

- the older thing
"""


def test_a_tag_and_a_bare_version_both_resolve():
    assert release_notes.section(SAMPLE, "v0.8.0") == "- the newest thing\n- and another"
    assert release_notes.section(SAMPLE, "0.8.0") == "- the newest thing\n- and another"


def test_the_section_stops_at_the_next_heading():
    assert release_notes.section(SAMPLE, "v0.7.0") == "- the older thing"


def test_the_unreleased_section_is_addressable_by_name():
    assert release_notes.section(SAMPLE, "Unreleased") == "- something not released yet"


def test_a_missing_version_names_the_sections_it_found():
    with pytest.raises(SystemExit) as exc:
        release_notes.section(SAMPLE, "v9.9.9")
    assert "no section for 9.9.9" in str(exc.value) and "0.8.0" in str(exc.value)


def test_an_empty_section_is_refused():
    empty = "# Changelog\n\n## 0.8.0 (2026-09-28)\n\n## 0.7.0 (2026-09-24)\n\n- a thing\n"
    with pytest.raises(SystemExit) as exc:
        release_notes.section(empty, "v0.8.0")
    assert "empty" in str(exc.value)


def test_every_released_version_in_the_changelog_yields_notes():
    text = (ROOT / "CHANGELOG.md").read_text()
    versions = [m.group(1) for m in release_notes.HEADING.finditer(text) if m.group(1) != "Unreleased"]
    assert len(versions) > 5
    for version in versions:
        assert release_notes.section(text, f"v{version}").strip()


def test_main_prints_one_line_and_full_prints_the_section(capsys):
    assert release_notes.main(["v0.3.4"]) == 0
    line = capsys.readouterr().out.strip()
    assert line.count("\n") == 0 and "msvcrt" not in line and "CHANGELOG.md" in line
    assert release_notes.main(["v0.3.4", "--full"]) == 0
    assert "msvcrt" in capsys.readouterr().out
    assert release_notes.main([]) == 2
    assert "usage" in capsys.readouterr().err


def release_job():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    return workflow["jobs"]["release"]


def test_the_release_job_runs_after_the_package_is_published():
    assert release_job()["needs"] == "publish"


def test_the_release_job_can_write_releases_and_nothing_else():
    assert release_job()["permissions"] == {"contents": "write"}


def test_the_release_job_builds_its_notes_from_the_changelog_for_the_tag():
    runs = [step["run"] for step in release_job()["steps"] if "run" in step]
    assert any("tools/release_notes.py" in run and "GITHUB_REF_NAME" in run for run in runs)
    create = next(run for run in runs if "gh release create" in run)
    assert "--notes-file" in create and "GITHUB_REF_NAME" in create and "--verify-tag" in create


LOOP = re.compile(r"\b(?:while|for)\b[^;{]*\{")


def check_ci_script():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    steps = workflow["jobs"]["check-ci"]["steps"]
    return next(step["with"]["script"] for step in steps if "github-script" in step["uses"])


def loop_bodies(script):
    bodies = []
    for match in LOOP.finditer(script):
        depth = 0
        for index in range(match.end() - 1, len(script)):
            if script[index] == "{":
                depth += 1
            elif script[index] == "}":
                depth -= 1
                if not depth:
                    bodies.append(script[match.end():index])
                    break
    return bodies


def failure_branches(script):
    branches = {}
    for part in script.split("if (")[1:]:
        condition, _, rest = part.partition(")")
        message = re.search(r"core\.setFailed\(`([^`]*)`\)", rest)
        if message:
            branches[condition.strip()] = message.group(1)
    return branches


def test_the_release_gate_reads_the_run_inside_a_loop_that_waits_for_it_to_complete():
    script = check_ci_script()
    polling = [body for body in loop_bodies(script) if "listWorkflowRunsForRepo" in body]
    assert polling
    assert "".join(polling).count("listWorkflowRunsForRepo") == script.count("listWorkflowRunsForRepo")
    for body in polling:
        assert "status === 'completed'" in body
        assert "setTimeout" in body


def test_the_release_gate_names_each_of_the_three_failures_apart():
    branches = failure_branches(check_ci_script())
    assert len(branches) == 3
    assert len(set(branches.values())) == 3
    no_run = branches["timedOut && !latest"]
    assert "No CI workflow run found for commit ${sha}" in no_run and "minutes of polling" in no_run
    unfinished = branches["timedOut"]
    assert "${latest.id}" in unfinished and "was still ${latest.status}" in unfinished
    assert "minutes" in unfinished
    red = branches["finished.conclusion !== 'success'"]
    assert "${finished.id}" in red and "concluded with ${finished.conclusion}" in red


def test_the_release_gate_only_lets_a_success_conclusion_through():
    script = check_ci_script()
    assert "finished.conclusion !== 'success'" in script
    assert script.count("'success'") == 1
    assert script.rindex("conclusion !== 'success'") < script.rindex("console.log")


def test_the_release_gate_expires_instead_of_waiting_forever():
    script = check_ci_script()
    polling = [body for body in loop_bodies(script) if "listWorkflowRunsForRepo" in body]
    assert len(polling) == 1
    body = polling[0]
    assert "const POLL_INTERVAL_MS = " in script
    assert "const POLL_TIMEOUT_MS = " in script
    assert "const deadline = Date.now() + POLL_TIMEOUT_MS" in script
    assert body.index("Date.now() >= deadline") < body.index("timedOut = true") < body.index("setTimeout")


def test_the_summary_is_one_line_and_names_the_first_entries():
    line = release_notes.summary(SAMPLE, "v0.8.0")
    assert "\n" not in line
    assert line.startswith("the newest thing; and another")
    assert line.endswith("Full notes in CHANGELOG.md.")


def test_the_summary_counts_the_entries_it_left_out():
    body = "## 0.8.0 (2026-09-28)\n\n" + "".join(f"- change {i}\n" for i in range(5))
    line = release_notes.summary("# Changelog\n\n" + body, "v0.8.0")
    assert "and 3 more changes" in line
    body = "## 0.8.0 (2026-09-28)\n\n" + "".join(f"- change {i}\n" for i in range(3))
    assert "and 1 more change." in release_notes.summary("# Changelog\n\n" + body, "v0.8.0")


def test_the_summary_keeps_a_colon_that_sits_inside_backticks():
    body = "# Changelog\n\n## 0.8.0 (2026-09-28)\n\n- `mode: audit`: log what would be caught\n- second\n"
    assert release_notes.summary(body, "v0.8.0").startswith("`mode: audit`; second.")


def test_a_long_entry_is_cut_at_a_clause_and_never_ends_on_a_dangling_word():
    entry = ("The `keyfence exec` environment snapshot lives under `~/.keyfence/env/`, and each "
             "`exec` removes snapshots older than a minute")
    short = release_notes.lead(entry)
    assert len(short) <= release_notes.TOPIC_CHARS + 1 and short.endswith("…")
    assert short.rstrip("…").split()[-1].lower() not in release_notes.DANGLING


def test_the_leading_paragraph_of_a_section_counts_as_an_entry():
    body = "# Changelog\n\n## 0.2.0 (2026-09-08)\n\nFirst release on PyPI.\n\n- a proxy\n- a vault\n"
    assert release_notes.summary(body, "v0.2.0").startswith("First release on PyPI; a proxy; and 1 more change.")


def test_the_link_points_at_the_changelog_section_of_the_tag(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    line = release_notes.summary(SAMPLE, "v0.8.0")
    assert "https://github.com/owner/repo/blob/v0.8.0/CHANGELOG.md#080-2026-09-28" in line


def test_every_released_version_yields_a_single_line():
    text = (ROOT / "CHANGELOG.md").read_text()
    versions = [m.group(1) for m in release_notes.HEADING.finditer(text) if m.group(1) != "Unreleased"]
    for version in versions:
        line = release_notes.summary(text, f"v{version}")
        assert "\n" not in line and line.endswith(".") and len(line) > 20


def test_a_truncated_topic_does_not_collect_a_period_after_its_ellipsis():
    body = "# Changelog\n\n## 0.9.0 (2026-09-28)\n\n- " + "a long single entry that keeps going " * 6 + "\n"
    line = release_notes.summary(body, "v0.9.0")
    assert "…." not in line and "… ." not in line
    assert "… Full notes in" in line


def test_a_release_with_one_entry_gets_the_whole_sentence():
    body = ("# Changelog\n\n## 0.2.2 (2026-09-08)\n\n- During `keyfence exec` the proxy's own output goes to\n"
            "  `~/.keyfence/proxy.log` instead of the wrapped tool's terminal.\n")
    line = release_notes.summary(body, "v0.2.2")
    assert line.startswith("During `keyfence exec` the proxy's own output goes to "
                           "`~/.keyfence/proxy.log` instead of the wrapped tool's terminal.")
    assert "…" not in line


def test_two_entries_keep_the_shorter_budget():
    entry = "a long entry that keeps going and going and going and going and going and going"
    body = f"# Changelog\n\n## 0.9.0 (2026-09-28)\n\n- {entry}\n- {entry}\n"
    line = release_notes.summary(body, "v0.9.0")
    assert line.count("…") == 2 and len(line) < 2 * release_notes.SINGLE_CHARS


def test_no_published_style_defect_in_any_released_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    versions = [m.group(1) for m in release_notes.HEADING.finditer(text) if m.group(1) != "Unreleased"]
    for version in versions:
        line = release_notes.summary(text, f"v{version}")
        assert "…." not in line and ";." not in line and ",." not in line and "  " not in line
