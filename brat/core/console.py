"""Terminal output primitives.

Hand-rolled ANSI rather than a dependency. Two reasons: the install stays at
two packages, and BRAT is meant to be run on a projector where predictable,
high-contrast output beats clever layout.

Respects NO_COLOR (https://no-color.org/) and disables styling when stdout is
not a TTY, so `brat scan | tee` and `-o json` stay clean.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Iterable

from .findings import Severity


class _Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"
    BG_RED = "\033[41m"


SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: _Style.BRIGHT_RED + _Style.BOLD,
    Severity.HIGH: _Style.RED,
    Severity.MEDIUM: _Style.YELLOW,
    Severity.LOW: _Style.CYAN,
    Severity.INFO: _Style.DIM,
}

SEVERITY_MARK: dict[Severity, str] = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: " !",
    Severity.MEDIUM: " *",
    Severity.LOW: " -",
    Severity.INFO: " i",
}


class Console:
    """Styled writer. All BRAT terminal output goes through one of these."""

    def __init__(self, stream=None, force_color: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        if force_color is None:
            self.color = (
                hasattr(self.stream, "isatty")
                and self.stream.isatty()
                and os.environ.get("NO_COLOR") is None
                and os.environ.get("TERM") != "dumb"
            )
        else:
            self.color = force_color

    # -- primitives ---------------------------------------------------------

    def _c(self, text: str, style: str) -> str:
        if not self.color or not style:
            return text
        return f"{style}{text}{_Style.RESET}"

    def write(self, text: str = "") -> None:
        print(text, file=self.stream)

    def bold(self, text: str) -> str:
        return self._c(text, _Style.BOLD)

    def dim(self, text: str) -> str:
        return self._c(text, _Style.DIM)

    def red(self, text: str) -> str:
        return self._c(text, _Style.RED)

    def green(self, text: str) -> str:
        return self._c(text, _Style.GREEN)

    def yellow(self, text: str) -> str:
        return self._c(text, _Style.YELLOW)

    def cyan(self, text: str) -> str:
        return self._c(text, _Style.CYAN)

    def magenta(self, text: str) -> str:
        return self._c(text, _Style.MAGENTA)

    # -- structure ----------------------------------------------------------

    @property
    def width(self) -> int:
        return min(shutil.get_terminal_size((100, 24)).columns, 100)

    def rule(self, title: str = "") -> None:
        if title:
            bar = "-" * max(4, self.width - len(title) - 3)
            self.write(f"{self.bold(title)} {self.dim(bar)}")
        else:
            self.write(self.dim("-" * self.width))

    def header(self, title: str) -> None:
        self.write()
        self.write(self.bold(title))
        self.write(self.dim("=" * min(len(title), self.width)))

    def kv(self, key: str, value: Any, indent: int = 2) -> None:
        pad = " " * indent
        self.write(f"{pad}{self.dim(key + ':'):<28} {value}")

    def bullet(self, text: str, indent: int = 2) -> None:
        self.write(f"{' ' * indent}{self.dim('-')} {text}")

    # -- status lines -------------------------------------------------------

    def info(self, text: str) -> None:
        self.write(f"{self.dim('[*]')} {text}")

    def ok(self, text: str) -> None:
        self.write(f"{self._c('[+]', _Style.BRIGHT_GREEN)} {text}")

    def warn(self, text: str) -> None:
        self.write(f"{self._c('[!]', _Style.BRIGHT_YELLOW)} {text}")

    def error(self, text: str) -> None:
        self.write(f"{self._c('[x]', _Style.BRIGHT_RED)} {text}")

    def step(self, text: str) -> None:
        self.write(f"{self.cyan('[>]')} {text}")

    def severity(self, sev: Severity, text: str) -> None:
        mark = SEVERITY_MARK[sev]
        style = SEVERITY_COLOR[sev]
        self.write(f"{self._c(f'[{mark.strip()}]', style)} {text}")

    # -- tables -------------------------------------------------------------

    def table(
        self,
        headers: list[str],
        rows: Iterable[list[str]],
        indent: int = 2,
    ) -> None:
        """Left-aligned column table. Last column is allowed to overflow."""
        rows = [[str(c) for c in r] for r in rows]
        if not rows:
            return
        ncols = len(headers)
        widths = [len(h) for h in headers]
        for row in rows:
            for i in range(min(ncols, len(row))):
                widths[i] = max(widths[i], len(row[i]))

        pad = " " * indent
        head = pad + "  ".join(
            self.bold(h.ljust(widths[i])) if i < ncols - 1 else self.bold(h)
            for i, h in enumerate(headers)
        )
        self.write(head)
        for row in rows:
            cells = []
            for i in range(ncols):
                cell = row[i] if i < len(row) else ""
                cells.append(cell.ljust(widths[i]) if i < ncols - 1 else cell)
            self.write(pad + "  ".join(cells))

    # -- byte formatting ----------------------------------------------------

    def hexdump(self, data: bytes, indent: int = 8, width: int = 16) -> None:
        """Classic offset / hex / ascii dump."""
        pad = " " * indent
        for off in range(0, len(data), width):
            chunk = data[off : off + width]
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            hexpart = hexpart.ljust(width * 3 - 1)
            asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.write(
                f"{pad}{self.dim(f'{off:04X}')}  {hexpart}  {self.dim('|')}{asciipart}{self.dim('|')}"
            )


def hexstr(data: bytes, sep: str = " ") -> str:
    """Uppercase hex string, space separated by default."""
    return sep.join(f"{b:02X}" for b in data)
