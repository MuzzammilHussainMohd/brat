"""Findings model.

A finding is one security-relevant statement about a device, produced by a
check. Every finding carries the evidence that produced it, so a report can
always answer "how do you know that?".

Three severities, deliberately. CVSS-style five-level scales invite bikeshedding
over whether something is Medium or Medium-High; the useful question on a BLE
assessment is only ever "is this exploitable now, is it a weakness, or is it
context you need to interpret the rest".
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


def _jsonable(value: Any) -> Any:
    """Recursively normalize raw bytes in evidence to hex strings.

    `Finding.to_dict()` is documented as the canonical shape - the text
    renderer is just a view over it - so evidence must actually render the
    same fact both ways. `asdict()` leaves any bytes/bytearray a check put in
    `evidence` untouched; json.dump's `default=str` then turns those into a
    Python repr string (`"b'\\xa5\\x00'"`) instead of the hex the text
    renderer shows for the same value. No check currently puts raw bytes in
    evidence, but nothing stops a future one from doing so, and this is
    cheap insurance against exactly that becoming a silent JSON/text mismatch.
    """
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


class Severity(enum.Enum):
    """Ordered severity levels. Compare with `>` / `<` - higher is worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value >= other.value

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {text!r}") from None


class Confidence(enum.Enum):
    """How the finding was established.

    This distinction matters and most tools blur it. `CONFIRMED` means BRAT
    actually performed the action and it worked. `INFERRED` means BRAT read a
    property or flag that says the action should work but did not exercise it -
    usually because exercising it would write to the device.
    """

    CONFIRMED = "confirmed"
    INFERRED = "inferred"


@dataclass
class Finding:
    """One security-relevant observation about a device."""

    check: str                       # stable id, e.g. "link.no-encryption"
    title: str                       # one line, human readable
    severity: Severity
    description: str = ""            # why this matters
    confidence: Confidence = Confidence.CONFIRMED
    target: str | None = None        # MAC / UUID / handle this applies to
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["confidence"] = self.confidence.value
        d["evidence"] = _jsonable(d["evidence"])
        return d


class FindingSet:
    """Ordered collection of findings with summary helpers."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings: list[Finding] = list(findings or [])

    def add(self, finding: Finding) -> Finding:
        self._findings.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def __len__(self) -> int:
        return len(self._findings)

    def __iter__(self):
        return iter(self._findings)

    def __bool__(self) -> bool:
        return bool(self._findings)

    @property
    def all(self) -> list[Finding]:
        return list(self._findings)

    def sorted(self) -> list[Finding]:
        """Most severe first; stable within a severity so check order is kept."""
        return sorted(self._findings, key=lambda f: -f.severity.value)

    def at_or_above(self, severity: Severity) -> list[Finding]:
        return [f for f in self._findings if f.severity >= severity]

    def counts(self) -> dict[str, int]:
        out = {s.name: 0 for s in Severity}
        for f in self._findings:
            out[f.severity.name] += 1
        return out

    @property
    def worst(self) -> Severity | None:
        if not self._findings:
            return None
        return max(f.severity for f in self._findings)

    def exit_code(self, fail_at: Severity = Severity.HIGH) -> int:
        """0 if nothing at or above `fail_at`, else 1. For CI use."""
        return 1 if self.at_or_above(fail_at) else 0

    def to_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.sorted()]
