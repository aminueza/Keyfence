import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import run as bench  # noqa: E402
from bench.corpus import (  # noqa: E402
    BODY_CONTEXTS, FORMATLESS, FORMATS, Sample, as_sent, materialize, negatives, positives,
)
from keyfence.detectors import ScanConfig  # noqa: E402


def test_corpus_is_deterministic_and_covers_every_format():
    a = positives(seed=3, per_format=1)
    b = positives(seed=3, per_format=1)
    assert [s.text for s in a] == [s.text for s in b]
    assert {s.category for s in a} == set(FORMATS)
    assert all(s.secret in s.text or json.dumps(s.secret)[1:-1] in s.text for s in a)
    assert positives(seed=4, per_format=1)[0].text != a[0].text


def test_negatives_have_no_secrets_and_several_categories():
    neg = negatives(seed=3)
    assert all(s.secret is None for s in neg)
    assert {"code", "prose", "claude-code-body", "telemetry", "logs", "lockfile"} <= {s.category for s in neg}


def test_materialize_writes_one_file_per_sample(tmp_path):
    samples = [Sample("a", "cat", "one"), Sample("b", "cat", "two")]
    paths = materialize(samples, tmp_path)
    assert sorted(p.read_text() for p in paths.values()) == ["one", "two"]


def test_evaluate_scores_a_perfect_and_a_blind_detector():
    pos = [Sample("p", "github-pat", "x ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 y", "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
           Sample("q", "random-password", "pw Zq8xK2mP9vL4nR7tW3yB", "Zq8xK2mP9vL4nR7tW3yB")]
    neg = [Sample("n", "code", "def f(): return 1")]
    perfect = bench.evaluate("perfect", lambda s: [s.secret] if s.secret else [], pos, neg)
    blind = bench.evaluate("blind", lambda s: [], pos, neg)
    assert perfect["recall"] == 1.0 and perfect["precision"] == 1.0 and perfect["fp_samples"] == 0
    assert blind["recall"] == 0.0 and blind["fp_samples"] == 0
    assert perfect["recall_by_format"]["random-password"] == 1.0
    table = bench.render([perfect, blind], pos, neg)
    assert "| github-pat | 100% | 0% |" in table


def test_keyfence_detector_on_small_corpus():
    det = bench.keyfence_detector(ScanConfig(entropy_enabled=False))
    sample = positives(seed=1, per_format=1)[0]
    assert bench._hit(det(sample), sample.secret)


def test_gitleaks_detector_is_optional(monkeypatch):
    monkeypatch.setattr(bench.shutil, "which", lambda _name: None)
    assert bench.gitleaks_detector([]) is None


def test_main_runs_without_gitleaks(capsys):
    assert bench.main(["--no-gitleaks", "--per-format", "1", "--seed", "2"]) == 0
    out = capsys.readouterr().out
    assert "recall on formatted secrets" in out and "as sent to the provider" in out
    assert "Recall by context" in out
    assert all(fmt in out for fmt in FORMATLESS)


def test_main_json_reports_both_views(capsys):
    assert bench.main(["--no-gitleaks", "--per-format", "1", "--seed", "2", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"as_sent", "raw"}
    assert [r["name"] for r in data["as_sent"]] == [r["name"] for r in data["raw"]]
    assert "code" in data["as_sent"][0]["recall_by_context"]


def test_as_sent_wraps_plain_samples_in_a_tool_result_body():
    raw = positives(seed=3, per_format=1)
    sent = as_sent(raw, seed=3)
    assert [s.label for s in sent] == [s.label for s in raw]
    for before, after in zip(raw, sent):
        assert after.body and after.secret == before.secret and after.context == before.context
        if before.context in BODY_CONTEXTS:
            assert after.text == before.text
        else:
            content = json.loads(after.text)["messages"][0]["content"][0]
            assert content["type"] == "tool_result" and content["content"] == before.text
    assert [s.text for s in as_sent(raw, seed=3)] == [s.text for s in sent]


def test_as_sent_escapes_non_ascii_in_a_share_of_the_samples():
    sent = as_sent([Sample(f"s{i}", "prose", "café") for i in range(30)], seed=5)
    escaped = sum("\\u00e9" in s.text for s in sent)
    assert 0 < escaped < 30
    assert all("café" in s.text for s in sent if "\\u00e9" not in s.text)


def test_body_negatives_are_not_wrapped_again():
    neg = negatives(seed=3)
    sent = {s.label: s for s in as_sent(neg, seed=3)}
    bodies = [s for s in neg if s.body]
    assert {s.category for s in bodies} == {"claude-code-body", "telemetry"}
    assert all(sent[s.label].text == s.text for s in bodies)


def test_context_table_shows_raw_recall_only_where_it_differs():
    pos = [Sample("a", "random-password", 'api_key="Zq8xK2mP9vL4nR7tW3yB"', "Zq8xK2mP9vL4nR7tW3yB", "code"),
           Sample("b", "random-password", "API_TOKEN=Zq8xK2mP9vL4nR7tW3yC", "Zq8xK2mP9vL4nR7tW3yC", "env-line")]
    sent = as_sent(pos, seed=1)

    def blind_after_escaped_quote(s):
        return [] if '\\"' + s.secret in s.text else [s.secret]

    results = [bench.evaluate("d", blind_after_escaped_quote, sent, [])]
    raw = [bench.evaluate("d", blind_after_escaped_quote, pos, [])]
    table = bench.render(results, sent, [], raw)
    assert "| code | 0% (raw 100%) |" in table
    assert "| env-line | 100% |" in table
