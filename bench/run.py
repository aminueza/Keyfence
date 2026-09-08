from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.corpus import FORMATLESS, Sample, materialize, negatives, positives  # noqa: E402
from keyfence import __version__  # noqa: E402
from keyfence.detectors import ScanConfig, scan  # noqa: E402
from keyfence.rules import load_rules  # noqa: E402
from keyfence.vault import Vault  # noqa: E402

Detector = Callable[[Sample], list[str]]


def _hit(values: list[str], secret: str) -> bool:
    forms = {secret, json.dumps(secret)[1:-1]}
    return any(v == s or (len(v) >= 8 and (v in s or s in v)) for v in values for s in forms)


def keyfence_detector(config: ScanConfig, vault: Vault | None = None) -> Detector:
    def run(sample: Sample) -> list[str]:
        return [f.value for f in scan(sample.text, vault=vault, config=config)]
    return run


def gitleaks_detector(samples: list[Sample]) -> Detector | None:
    binary = shutil.which("gitleaks")
    if not binary:
        return None
    root = Path(tempfile.mkdtemp(prefix="keyfence-bench-"))
    paths = materialize(samples, root)
    report = root / "report.json"
    cmd = [binary, "dir", str(root), "--no-banner", "--exit-code", "0",
           "--report-format", "json", "--report-path", str(report)]
    subprocess.run(cmd, check=True, capture_output=True)
    found: dict[str, list[str]] = defaultdict(list)
    if report.exists() and report.read_text().strip():
        for item in json.loads(report.read_text()):
            found[str(Path(item["File"]).resolve())].append(item.get("Secret") or item.get("Match", ""))
    by_label = {label: found.get(str(path.resolve()), []) for label, path in paths.items()}

    def run(sample: Sample) -> list[str]:
        return by_label.get(sample.label, [])
    return run


def evaluate(name: str, detector: Detector, pos: list[Sample], neg: list[Sample]) -> dict:
    start = time.perf_counter()
    recall_by_format: dict[str, list[bool]] = defaultdict(list)
    for s in pos:
        recall_by_format[s.category].append(_hit(detector(s), s.secret))
    fp_by_category: dict[str, list[bool]] = defaultdict(list)
    fp_findings = 0
    for s in neg:
        values = detector(s)
        fp_by_category[s.category].append(bool(values))
        fp_findings += len(values)
    elapsed = time.perf_counter() - start
    formatted = [s for s in pos if s.category not in FORMATLESS]
    tp = sum(_hit(detector(s), s.secret) for s in formatted)
    fp_samples = sum(sum(v) for v in fp_by_category.values())
    precision = tp / (tp + fp_samples) if tp + fp_samples else 0.0
    recall = tp / len(formatted) if formatted else 0.0
    return {
        "name": name,
        "recall_by_format": {k: sum(v) / len(v) for k, v in recall_by_format.items()},
        "fp_by_category": {k: sum(v) / len(v) for k, v in fp_by_category.items()},
        "fp_samples": fp_samples,
        "fp_findings": fp_findings,
        "precision": precision,
        "recall": recall,
        "seconds": elapsed,
        "bytes": sum(len(s.text) for s in pos + neg),
    }


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def render(results: list[dict], pos: list[Sample], neg: list[Sample]) -> str:
    names = [r["name"] for r in results]
    lines = [f"keyfence {__version__}, {len(pos)} positive and {len(neg)} negative samples, "
             f"{sum(len(s.text) for s in pos + neg) // 1024} KB.", ""]
    lines.append("| | " + " | ".join(names) + " |")
    lines.append("|---|" + "---|" * len(names))
    lines.append("| recall on formatted secrets | " + " | ".join(pct(r["recall"]) for r in results) + " |")
    lines.append("| precision (per sample) | " + " | ".join(pct(r["precision"]) for r in results) + " |")
    lines.append("| negatives with a finding | " + " | ".join(f"{r['fp_samples']} / {len(neg)}" for r in results) + " |")
    lines.append("| total false findings | " + " | ".join(str(r["fp_findings"]) for r in results) + " |")
    lines.append("| time | " + " | ".join(f"{r['seconds']:.1f}s" for r in results) + " |")
    lines += ["", "Recall by format:", "", "| format | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for fmt in sorted({s.category for s in pos}):
        lines.append(f"| {fmt} | " + " | ".join(pct(r["recall_by_format"].get(fmt, 0)) for r in results) + " |")
    lines += ["", "False positive rate by negative category (share of samples with at least one finding):", "",
              "| category | samples | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    counts = defaultdict(int)
    for s in neg:
        counts[s.category] += 1
    for cat in sorted(counts):
        lines.append(f"| {cat} | {counts[cat]} | " + " | ".join(pct(r["fp_by_category"].get(cat, 0)) for r in results) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="keyfence detection benchmark")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--per-format", type=int, default=3)
    parser.add_argument("--no-gitleaks", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    pos = positives(args.seed, args.per_format)
    neg = negatives(args.seed)
    rules = load_rules()
    vault = Vault(path=Path(tempfile.mkdtemp(prefix="keyfence-bench-vault-")) / "vault.json")
    vault.add_many(s.secret for s in pos if s.category in FORMATLESS)

    detectors = [
        ("builtin patterns", keyfence_detector(ScanConfig(entropy_enabled=False))),
        ("+ gitleaks rules", keyfence_detector(ScanConfig(entropy_enabled=False, rules=rules))),
        ("+ entropy (default)", keyfence_detector(ScanConfig(rules=rules))),
        ("default + vault", keyfence_detector(ScanConfig(rules=rules), vault)),
    ]
    if not args.no_gitleaks:
        gl = gitleaks_detector(pos + neg)
        if gl is not None:
            detectors.append(("gitleaks binary", gl))

    results = [evaluate(name, det, pos, neg) for name, det in detectors]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render(results, pos, neg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
