"""Report envelope and output renderers.

Every command produces a `Report`: some structured data plus a `FindingSet`.
The renderer decides whether that becomes a human-readable terminal page, a
single JSON document, or a stream of JSONL records.

JSON is the canonical shape - the text renderer is a view over it, never the
other way round. That keeps `-o json` complete rather than a lossy afterthought.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .console import Console
from .findings import Confidence, FindingSet, Severity

OUTPUT_FORMATS = ("text", "json", "jsonl")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Report:
    """Result of one BRAT command."""

    command: str
    target: str | None = None
    started: str = field(default_factory=_now)
    data: dict[str, Any] = field(default_factory=dict)
    findings: FindingSet = field(default_factory=FindingSet)
    notes: list[str] = field(default_factory=list)

    def note(self, text: str) -> None:
        """Record a caveat about coverage - what was skipped and why."""
        self.notes.append(text)

    def to_dict(self) -> dict[str, Any]:
        from .. import __version__

        return {
            "tool": "brat",
            "version": __version__,
            "command": self.command,
            "target": self.target,
            "started": self.started,
            "completed": _now(),
            "summary": {
                "findings": len(self.findings),
                "by_severity": self.findings.counts(),
                "worst": self.findings.worst.name if self.findings.worst else None,
            },
            "notes": self.notes,
            "data": self.data,
            "findings": self.findings.to_list(),
        }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_json(report: Report, stream=None) -> None:
    stream = stream or sys.stdout
    json.dump(report.to_dict(), stream, indent=2, default=str)
    stream.write("\n")


def render_jsonl(report: Report, stream=None) -> None:
    """One record per line: a header, then one line per finding.

    Suited to piping into jq or a log pipeline while a long capture runs.
    """
    stream = stream or sys.stdout
    doc = report.to_dict()
    header = {k: v for k, v in doc.items() if k != "findings"}
    header["record"] = "summary"
    stream.write(json.dumps(header, default=str) + "\n")
    for f in doc["findings"]:
        rec = dict(f)
        rec["record"] = "finding"
        stream.write(json.dumps(rec, default=str) + "\n")
    stream.flush()


def render_findings_text(findings: FindingSet, console: Console) -> None:
    """Human-readable findings block, most severe first."""
    if not findings:
        console.write()
        console.ok("No findings.")
        return

    console.header(f"FINDINGS ({len(findings)})")

    for f in findings.sorted():
        console.write()
        sev = f.severity.name.ljust(8)
        tag = console._c(f" {sev} ", _sev_style(console, f.severity))
        conf = "" if f.confidence is Confidence.CONFIRMED else console.dim("  (inferred)")
        console.write(f"{tag} {console.bold(f.title)}{conf}")
        console.write(f"         {console.dim(f.check)}")

        if f.target:
            console.write(f"         {console.dim('target:')} {f.target}")

        if f.description:
            for line in _wrap(f.description, console.width - 10):
                console.write(f"         {line}")

        if f.evidence:
            console.write(f"         {console.dim('evidence:')}")
            for k, v in f.evidence.items():
                console.write(f"           {console.dim(k + ':')} {_fmt_value(v)}")

        if f.remediation:
            console.write(f"         {console.dim('fix:')}")
            for line in _wrap(f.remediation, console.width - 12):
                console.write(f"           {line}")

        for ref in f.references:
            console.write(f"         {console.dim('ref:')} {ref}")

    _render_summary(findings, console)


def _render_summary(findings: FindingSet, console: Console) -> None:
    counts = findings.counts()
    console.write()
    console.rule()
    parts = []
    for sev in reversed(list(Severity)):
        n = counts[sev.name]
        if n:
            parts.append(console._c(f"{n} {sev.name.lower()}", _sev_style(console, sev)))
    console.write("  " + console.bold("Summary: ") + ("  ".join(parts) if parts else "clean"))


def _sev_style(console: Console, sev: Severity) -> str:
    from .console import SEVERITY_COLOR

    return SEVERITY_COLOR[sev]


def _fmt_value(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        return " ".join(f"{b:02X}" for b in v)
    if isinstance(v, list):
        if len(v) > 6:
            return ", ".join(str(x) for x in v[:6]) + f", ... (+{len(v) - 6})"
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, default=str)
    return str(v)


def _wrap(text: str, width: int) -> list[str]:
    """Minimal greedy wrap. Avoids importing textwrap's full machinery."""
    width = max(30, width)
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def emit(report: Report, fmt: str, console: Console, text_renderer=None) -> None:
    """Emit a report in the requested format.

    `text_renderer` is an optional callable taking (report, console) that draws
    the command-specific body; findings are always appended after it.
    """
    if fmt == "json":
        render_json(report)
        return
    if fmt == "jsonl":
        render_jsonl(report)
        return

    if text_renderer is not None:
        text_renderer(report, console)

    if report.notes:
        console.write()
        console.header("COVERAGE NOTES")
        for n in report.notes:
            console.bullet(n)

    render_findings_text(report.findings, console)
