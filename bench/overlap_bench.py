from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keyfence.detectors import ScanConfig, scan_report
from keyfence.rules import load_rules


def make_body_with_findings(count: int, seed: int = 42) -> str:
    r = random.Random(seed)
    parts = []
    for i in range(count):
        secret = f"sk-proj-{r.randbytes(40).hex()}"
        parts.append(f'api_key="{secret}"')
    return "\n".join(parts)


def benchmark_config(name: str, config: ScanConfig, finding_counts: list[int]) -> None:
    print(f"\n## {name}")
    print()
    print("| findings | time (ms) | time per finding (µs) | findings returned |")
    print("|----------|-----------|----------------------|-------------------|")

    for count in finding_counts:
        body = make_body_with_findings(count)

        start = time.perf_counter()
        report = scan_report(body, config=config)
        elapsed_ms = (time.perf_counter() - start) * 1000

        per_finding_us = (elapsed_ms * 1000) / count if count else 0
        actual_findings = len(report.findings)

        print(f"| {count:>8} | {elapsed_ms:>9.2f} | {per_finding_us:>20.2f} | {actual_findings:>17} |")


def main() -> None:
    finding_counts = [10, 100, 1000, 5000]

    print(f"Python {sys.version_info.major}.{sys.version_info.minor}")
    print("Measuring scan_report with varying finding counts")
    print("Body: N lines of `api_key=\"sk-proj-...\"` (OpenAI-style keys)")
    print()

    rules = load_rules()

    benchmark_config(
        "Patterns only (entropy disabled, no gitleaks)",
        ScanConfig(entropy_enabled=False),
        finding_counts,
    )
    benchmark_config(
        "Patterns + gitleaks rules (entropy disabled)",
        ScanConfig(entropy_enabled=False, rules=rules),
        finding_counts,
    )
    benchmark_config(
        "Default (patterns + gitleaks + entropy)",
        ScanConfig(rules=rules),
        finding_counts,
    )


if __name__ == "__main__":
    main()