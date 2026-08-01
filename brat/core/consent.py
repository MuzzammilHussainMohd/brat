"""Safety gating.

Two mechanisms, deliberately separate:

* A first-run acknowledgement, shown once per machine. It exists so nobody can
  claim they did not know what the tool does.
* A per-invocation `--confirm` requirement on any command that transmits.
  Recon and posture read; `impersonate` and `inject` put a radio on the air
  pretending to be somebody else's device, and that should never happen because
  a command was recalled from shell history by accident.

There is no environment variable to bypass the `--confirm` flag. Passing the
flag is the bypass, and it has to be typed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .console import Console

BANNER = r"""
     _         _
    | |__  _ _ __ _| |_    BLE Recon and Attack Toolkit
    | '_ \| '_/ _` |  _|
    |_.__/|_| \__,_|\__|   clone it, become it, watch what talks to you
"""

LEGAL = """\
BRAT transmits. `impersonate` and `inject` make this machine advertise as, and
answer for, a device it is not. Point it only at hardware you own or have
written authorisation to test.

Impersonating a device on a radio you do not control may be unlawful where you
are, regardless of intent. Operating a peripheral that a third party's phone
connects to may intercept their data. You are responsible for scope.

Captured output can contain real identifiers, credentials, and personal data.
Treat anything BRAT writes to disk as sensitive, and scrub it before sharing.\
"""


def _marker_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "brat" / "acknowledged"


def show_banner(console: Console) -> None:
    console.write(console.cyan(BANNER))


def first_run_gate(console: Console, assume_yes: bool = False) -> bool:
    """Show the terms once per machine. Returns True if the user may proceed."""
    marker = _marker_path()
    if marker.exists():
        return True

    show_banner(console)
    console.rule("TERMS OF USE")
    console.write()
    for line in LEGAL.splitlines():
        console.write(f"  {line}")
    console.write()
    console.rule()
    console.write()

    if assume_yes:
        console.warn("Acknowledged via --yes.")
    elif not sys.stdin.isatty():
        console.error(
            "First run requires interactive acknowledgement. "
            "Re-run in a terminal, or pass --yes."
        )
        return False
    else:
        try:
            answer = input("  Type 'i agree' to continue: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.write()
            return False
        if answer != "i agree":
            console.error("Not acknowledged. Exiting.")
            return False

    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("acknowledged\n")
    except OSError:
        # A read-only home is not a reason to block the run; it just means the
        # acknowledgement is shown again next time.
        pass

    console.write()
    return True


def require_confirm(
    console: Console,
    confirmed: bool,
    action: str,
    detail: str,
    consequences: list[str],
) -> bool:
    """Gate a transmitting command behind `--confirm`.

    When the flag is absent this prints exactly what would have happened and
    returns False. That makes the un-confirmed run useful as a dry run rather
    than just an error.
    """
    if confirmed:
        return True

    console.write()
    console.error(f"{action} requires --confirm.")
    console.write()
    console.write(f"  {console.bold('Would do:')} {detail}")
    console.write()
    console.write(f"  {console.bold('This will:')}")
    for c in consequences:
        console.bullet(c, indent=4)
    console.write()
    console.write(
        f"  Re-run with {console.bold('--confirm')} once you have authorisation "
        "for this target."
    )
    console.write()
    return False
