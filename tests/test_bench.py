import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import run as bench  # noqa: E402
from bench.corpus import FORMATLESS, FORMATS, Sample, materialize, negatives, positives  # noqa: E402
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
    assert "recall on formatted secrets" in out
    assert all(fmt in out for fmt in FORMATLESS)
