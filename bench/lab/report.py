from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from mitmproxy import io as mio
from mitmproxy.http import HTTPFlow

CATEGORIES = ("conversation", "session events", "telemetry", "other")
COLOURS = {"conversation": "#2a78d6", "session events": "#eb6834", "telemetry": "#1baf7a", "other": "#eda100"}
_ID = re.compile(r"[A-Za-z0-9_-]{20,}")
_CONVERSATION = ("/v1/messages", "/chat/completions", "/v1/responses", ":generatecontent", ":streamgeneratecontent", "/v1/complete")
_TELEMETRY_HOSTS = ("statsig", "sentry", "datadog", "segment", "amplitude", "mixpanel", "telemetry", "analytics", "posthog")
_TELEMETRY_PATHS = ("event_logging", "/telemetry", "/analytics", "/metrics", "/log_event", "/events/batch", "/track")


def categorize(host: str, path: str) -> str:
    low = path.lower()
    if any(s in low for s in _CONVERSATION):
        return "conversation"
    if "/v1/code/sessions" in low or "/worker/" in low:
        return "session events"
    if any(s in host for s in _TELEMETRY_HOSTS) or any(s in low for s in _TELEMETRY_PATHS):
        return "telemetry"
    return "other"


def normalize(path: str) -> str:
    return _ID.sub("<id>", path.split("?")[0])


def _size(message) -> int:
    body = len(message.raw_content or b"")
    headers = sum(len(k) + len(v) + 4 for k, v in message.headers.items(multi=True))
    return body + headers


def read_flows(path: Path) -> list[dict]:
    flows = []
    with path.open("rb") as fh:
        for flow in mio.FlowReader(fh).stream():
            if not isinstance(flow, HTTPFlow) or flow.request is None:
                continue
            flows.append({
                "host": flow.request.pretty_host,
                "path": normalize(flow.request.path),
                "category": categorize(flow.request.pretty_host, flow.request.path),
                "request_bytes": _size(flow.request),
                "response_bytes": _size(flow.response) if flow.response else 0,
                "ts": flow.request.timestamp_start or 0.0,
            })
    return flows


def read_audit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries


def summarize_run(run_dir: Path) -> dict:
    meta = json.loads((run_dir / "meta.json").read_text())
    flows = read_flows(run_dir / "session.flows") if (run_dir / "session.flows").exists() else []
    audit = read_audit(run_dir / "audit.log")
    ended = meta.get("agent_ended", 0)
    bytes_by_category = {c: 0 for c in CATEGORIES}
    endpoints: Counter = Counter()
    for f in flows:
        bytes_by_category[f["category"]] += f["request_bytes"]
        endpoints[(f["host"], f["path"])] += 1
    after = [f for f in flows if f["ts"] > ended]
    canary_requests = [e for e in audit if any(fi["kind"] == "canary" for fi in e["findings"])]
    canary_keys = sorted({fi.get("key") or "?" for e in canary_requests for fi in e["findings"] if fi["kind"] == "canary"})
    secret_requests = [e for e in audit if any(fi["kind"] in ("vault", "canary") for fi in e["findings"])]
    return {
        "seed": meta.get("seed"),
        "agent_version": meta.get("agent_version"),
        "keyfence_version": meta.get("keyfence_version"),
        "duration_s": round(ended - meta.get("started", ended), 1),
        "hosts": sorted({f["host"] for f in flows}),
        "requests": len(flows),
        "endpoints": {f"{h}{p}": n for (h, p), n in endpoints.most_common()},
        "request_bytes": sum(f["request_bytes"] for f in flows),
        "response_bytes": sum(f["response_bytes"] for f in flows),
        "bytes_by_category": bytes_by_category,
        "env_read": bool(canary_requests),
        "canary_via": canary_keys,
        "requests_with_secrets": len(secret_requests),
        "requests_with_canary": len(canary_requests),
        "telemetry_separate": bytes_by_category["telemetry"] > 0,
        "after_exit_requests": len(after),
        "after_exit_bytes": sum(f["request_bytes"] for f in after),
        "after_exit_endpoints": sorted({f"{f['host']}{f['path']}" for f in after}),
    }


def summarize_agent(label: str, run_dirs: list[Path]) -> dict:
    runs = [summarize_run(d) for d in sorted(run_dirs)]

    def span(key):
        values = [r[key] for r in runs]
        return {"min": min(values), "max": max(values), "mean": round(sum(values) / len(values), 1)}

    categories = {c: span_of([r["bytes_by_category"][c] for r in runs]) for c in CATEGORIES}
    return {
        "label": label,
        "runs": len(runs),
        "agent_version": runs[0]["agent_version"],
        "keyfence_version": runs[0]["keyfence_version"],
        "hosts": sorted(set().union(*(r["hosts"] for r in runs))),
        "requests": span("requests"),
        "request_bytes": span("request_bytes"),
        "bytes_by_category": categories,
        "env_read_runs": sum(1 for r in runs if r["env_read"]),
        "canary_via": sorted(set().union(*(set(r["canary_via"]) for r in runs))),
        "requests_with_canary": span("requests_with_canary"),
        "telemetry_separate": any(r["telemetry_separate"] for r in runs),
        "after_exit_requests": span("after_exit_requests"),
        "after_exit_bytes": span("after_exit_bytes"),
        "after_exit_endpoints": sorted(set().union(*(set(r["after_exit_endpoints"]) for r in runs))),
        "endpoints": dict(sum((Counter(r["endpoints"]) for r in runs), Counter()).most_common()),
        "per_run": runs,
    }


def span_of(values: list[int]) -> dict:
    return {"min": min(values), "max": max(values), "mean": round(sum(values) / len(values), 1)}


def _kb(n: float) -> str:
    return f"{n / 1024:.0f} KB"


def _range(s: dict, fmt=lambda v: str(v)) -> str:
    return fmt(s["min"]) if s["min"] == s["max"] else f"{fmt(s['min'])} to {fmt(s['max'])}"


def markdown(agents: list[dict]) -> str:
    lines = [
        "| agent | version | runs | hosts | requests | bytes sent | conversation | session events | telemetry | .env read | canary path | same content in N requests | after exit |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for a in agents:
        cats = a["bytes_by_category"]
        lines.append("| " + " | ".join([
            a["label"], a["agent_version"] or "?", str(a["runs"]), ", ".join(a["hosts"]) or "none",
            _range(a["requests"]), _range(a["request_bytes"], _kb),
            _kb(cats["conversation"]["mean"]), _kb(cats["session events"]["mean"]), _kb(cats["telemetry"]["mean"]),
            f"{a['env_read_runs']}/{a['runs']}", ", ".join(a["canary_via"]) or "-",
            _range(a["requests_with_canary"]),
            f"{_range(a['after_exit_requests'])} req, {_range(a['after_exit_bytes'], _kb)}",
        ]) + " |")
    return "\n".join(lines)


def svg_chart(agents: list[dict]) -> str:
    left, bar_h, gap, top = 170, 20, 26, 70
    width = 800
    height = top + len(agents) * (bar_h + gap) + 24
    total_max = max((sum(a["bytes_by_category"][c]["mean"] for c in CATEGORIES) for a in agents), default=1) or 1
    scale = (width - left - 90) / total_max
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
           'font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="12">',
           f'<rect width="{width}" height="{height}" fill="#fcfcfb"/>',
           '<text x="24" y="28" font-size="15" font-weight="600" fill="#0b0b0b">Bytes sent per session, by destination</text>',
           '<text x="24" y="46" fill="#52514e">Mean over runs; request bodies and headers, as recorded by the proxy</text>']
    lx = 24
    for c in CATEGORIES:
        out.append(f'<rect x="{lx}" y="{top - 16}" width="10" height="10" fill="{COLOURS[c]}"/>')
        out.append(f'<text x="{lx + 14}" y="{top - 7}" fill="#52514e">{c}</text>')
        lx += 22 + 7 * len(c)
    y = top + 6
    for a in agents:
        out.append(f'<text x="{left - 10}" y="{y + 14}" text-anchor="end" fill="#0b0b0b">{a["label"]}</text>')
        x = left
        total = 0
        for c in CATEGORIES:
            v = a["bytes_by_category"][c]["mean"]
            total += v
            w = max(0.0, v * scale - 2) if v else 0
            if w > 0:
                out.append(f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{bar_h}" fill="{COLOURS[c]}"><title>{a["label"]}: {c} {_kb(v)}</title></rect>')
                x += v * scale
        out.append(f'<text x="{x + 6:.1f}" y="{y + 14}" fill="#52514e">{_kb(total)}</text>')
        y += bar_h + gap
    out.append("</svg>")
    return "\n".join(out)


def build(out: Path) -> list[dict]:
    groups: dict[str, list[Path]] = defaultdict(list)
    for meta in out.glob("*/run-*/meta.json"):
        groups[meta.parent.parent.name].append(meta.parent)
    agents = [summarize_agent(label, dirs) for label, dirs in sorted(groups.items())]
    (out / "report.json").write_text(json.dumps(agents, indent=2) + "\n")
    (out / "report.md").write_text(markdown(agents) + "\n")
    (out / "bytes.svg").write_text(svg_chart(agents) + "\n")
    return agents


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    out = Path(args[0]) if args else Path("lab-out")
    agents = build(out)
    print(markdown(agents))
    print(f"\nwritten: {out / 'report.md'}, {out / 'report.json'}, {out / 'bytes.svg'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
