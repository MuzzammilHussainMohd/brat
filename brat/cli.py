"""BRAT command line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .core.console import Console
from .core.consent import first_run_gate
from .core.findings import Severity
from .core.profile import ProfileError
from .core.protocol import ProtocolError
from .core.report import OUTPUT_FORMATS, emit

EPILOG = """\
typical workflow:
  brat doctor                                    check the environment first
  brat scan                                      find devices, fingerprint them
  brat posture --address AA:BB:CC:DD:EE:FF       does it demand authentication?
  brat clone   --address AA:BB:CC:DD:EE:FF       write a profile from the device
  brat impersonate --profile mydevice --confirm  become it, log what connects

Recon and posture commands only read. `impersonate` and `inject` transmit and
require --confirm. Point them only at hardware you own or are authorised to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="brat",
        description="BRAT - BLE Recon and Attack Toolkit. "
        "Clone a device into a profile, then become it.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"brat {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-o",
        "--output",
        choices=OUTPUT_FORMATS,
        default="text",
        help="output format (default: text)",
    )
    common.add_argument("--adapter", help="HCI adapter to use, e.g. hci0")
    common.add_argument(
        "--no-color", action="store_true", help="disable ANSI colour output"
    )
    common.add_argument(
        "--yes", action="store_true", help="accept the first-run terms non-interactively"
    )
    common.add_argument(
        "--fail-at",
        choices=[s.name.lower() for s in Severity],
        default="high",
        help="exit non-zero if a finding at or above this severity is reported "
        "(default: high)",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # -- doctor -------------------------------------------------------------
    sub.add_parser(
        "doctor",
        parents=[common],
        help="check adapter, BlueZ, and peripheral-mode readiness",
        description="Verify this machine can do what you are about to ask of it.",
    )

    # -- scan ---------------------------------------------------------------
    p_scan = sub.add_parser(
        "scan",
        parents=[common],
        help="passive discovery with profile fingerprinting",
        description="Listen for advertisements and match them against known profiles.",
    )
    p_scan.add_argument(
        "-t", "--timeout", type=float, default=8.0, help="scan duration in seconds"
    )
    p_scan.add_argument("--name", help="only show devices whose name contains this")
    p_scan.add_argument("--address", help="only show this address")
    p_scan.add_argument("--min-rssi", type=int, help="ignore devices weaker than this")
    p_scan.add_argument(
        "--no-profiles", action="store_true", help="skip profile fingerprinting"
    )

    # -- enum ---------------------------------------------------------------
    p_enum = sub.add_parser(
        "enum",
        parents=[common],
        help="connect and dump the full GATT tree",
        description="Walk every service, characteristic, and descriptor on a device.",
    )
    p_enum.add_argument("-a", "--address", required=True, help="target MAC address")
    p_enum.add_argument(
        "-t", "--timeout", type=float, default=20.0, help="connection timeout"
    )
    p_enum.add_argument(
        "--read-values",
        action="store_true",
        help="also read every readable characteristic",
    )

    # -- posture ------------------------------------------------------------
    p_post = sub.add_parser(
        "posture",
        parents=[common],
        help="security posture check - does it demand authentication?",
        description="Connect cold and report what the device let an unauthenticated "
        "peer do. Generic: works on any device.",
    )
    p_post.add_argument("-a", "--address", required=True, help="target MAC address")
    p_post.add_argument(
        "-t", "--timeout", type=float, default=20.0, help="connection timeout"
    )
    p_post.add_argument(
        "-p", "--profile", help="profile to check expectations against (auto-detected if omitted)"
    )
    p_post.add_argument(
        "--probe-writes",
        action="store_true",
        help="confirm write exposure with zero-length writes "
        "(skips firmware-update characteristics, and any unrecognised vendor "
        "characteristic that looks like a control point - see --probe-unknown-writes)",
    )
    p_post.add_argument(
        "--probe-unknown-writes",
        action="store_true",
        help="also probe control-point-shaped characteristics from vendors BRAT "
        "does not recognise (write + notify/indicate, no read). Off by default: "
        "an unrecognised control point on an unfamiliar device is exactly the "
        "shape of a firmware-update endpoint, and a zero-length write to one can "
        "reboot or brick the device.",
    )
    p_post.add_argument(
        "--check-pairing",
        action="store_true",
        help="attempt Just Works pairing, then unpair, to test the association model",
    )

    # -- clone --------------------------------------------------------------
    p_clone = sub.add_parser(
        "clone",
        parents=[common],
        help="capture a device into a reusable YAML profile",
        description="Walk a device's advertising data and GATT tree and write a "
        "profile that `brat impersonate` can serve.",
    )
    p_clone.add_argument("-a", "--address", required=True, help="device to clone")
    p_clone.add_argument(
        "-t", "--timeout", type=float, default=20.0, help="connection timeout"
    )
    p_clone.add_argument(
        "-f", "--output-file", help="where to write the profile (default: profiles/<slug>.yaml)"
    )
    p_clone.add_argument("--slug", help="profile slug (default: derived from device name)")
    p_clone.add_argument("--name", help="human-readable device name for the profile")
    p_clone.add_argument("--vendor", help="vendor name for the profile")
    p_clone.add_argument(
        "--no-values",
        action="store_true",
        help="capture structure only, do not read characteristic values",
    )
    p_clone.add_argument(
        "--no-protocol-stub",
        action="store_true",
        help="omit the commented protocol scaffold from the generated file",
    )

    # -- impersonate --------------------------------------------------------
    p_imp = sub.add_parser(
        "impersonate",
        parents=[common],
        help="serve a profile as a rogue peripheral [transmits]",
        description="Advertise as the profiled device and log everything a "
        "connecting central sends. Requires --confirm.",
    )
    p_imp.add_argument("-p", "--profile", required=True, help="profile to serve")
    p_imp.add_argument("--name", help="override the advertised name")
    p_imp.add_argument(
        "--duration", type=float, help="stop automatically after this many seconds"
    )
    p_imp.add_argument(
        "--payload",
        action="append",
        metavar="NAME=FILE",
        help="load a binary blob referenceable as {blob.NAME} (repeatable)",
    )
    p_imp.add_argument("--session-log", help="write the full session log to this JSON file")
    p_imp.add_argument(
        "--confirm", action="store_true", help="required: acknowledge that this transmits"
    )

    # -- inject -------------------------------------------------------------
    p_inj = sub.add_parser(
        "inject",
        parents=[common],
        help="serve a profile and feed the client fabricated data [transmits]",
        description="Run the rogue peripheral with an extra rule that replies to a "
        "chosen command with attacker-controlled content. Requires --confirm.",
    )
    p_inj.add_argument("-p", "--profile", required=True, help="profile to serve")
    p_inj.add_argument("--name", help="override the advertised name")
    p_inj.add_argument(
        "--on-cmd", help="trigger: respond when the client sends this command, e.g. 0x93"
    )
    p_inj.add_argument(
        "--push",
        action="store_true",
        help="trigger on any decoded frame rather than a specific command",
    )
    p_inj.add_argument(
        "--inject",
        metavar="TEMPLATE",
        help="payload template to send, e.g. '02{ts:u32be}{rand:64}' or '{blob.data}'",
    )
    p_inj.add_argument(
        "--inject-raw",
        metavar="TEMPLATE",
        help="send these bytes verbatim, bypassing frame construction",
    )
    p_inj.add_argument(
        "--as-cmd", help="command byte for the injected frame (default: the trigger command)"
    )
    p_inj.add_argument("--direction", help="value for the frame's direction field, if it has one")
    p_inj.add_argument("--delay", type=float, default=0.2, help="delay before injecting")
    p_inj.add_argument("--repeat", type=int, default=1, help="send the payload this many times")
    p_inj.add_argument(
        "--interval", type=float, default=1.0, help="delay between repeats"
    )
    p_inj.add_argument(
        "--duration", type=float, help="stop automatically after this many seconds"
    )
    p_inj.add_argument(
        "--payload",
        action="append",
        metavar="NAME=FILE",
        help="load a binary blob referenceable as {blob.NAME} (repeatable)",
    )
    p_inj.add_argument("--session-log", help="write the full session log to this JSON file")
    p_inj.add_argument(
        "--confirm", action="store_true", help="required: acknowledge that this transmits"
    )

    # -- profiles -----------------------------------------------------------
    p_prof = sub.add_parser(
        "profiles",
        parents=[common],
        help="list, show, and validate device profiles",
    )
    prof_sub = p_prof.add_subparsers(dest="profile_action", metavar="<action>")
    prof_sub.add_parser("list", parents=[common], help="list discoverable profiles")
    p_show = prof_sub.add_parser("show", parents=[common], help="print one profile in full")
    p_show.add_argument("name", help="profile slug or path")
    p_val = prof_sub.add_parser("validate", parents=[common], help="check profiles are well formed")
    p_val.add_argument("name", nargs="?", help="profile slug or path (default: all)")

    return parser


# Commands that transmit, and therefore need the terms acknowledged.
_TRANSMITTING = {"impersonate", "inject"}

_MODULES = {
    "doctor": "doctor",
    "scan": "scan",
    "enum": "enumerate",
    "posture": "posture",
    "clone": "clone",
    "impersonate": "impersonate",
    "inject": "inject",
    "profiles": "profiles",
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    console = Console(force_color=False if args.no_color else None)
    if args.output != "text":
        # Structured output must stay parseable, so styling and progress chatter
        # go to stderr-free silence rather than into the document.
        console = Console(stream=sys.stderr, force_color=False)

    if args.command in _TRANSMITTING and not first_run_gate(console, assume_yes=args.yes):
        return 2

    if args.command == "profiles" and not getattr(args, "profile_action", None):
        args.profile_action = "list"

    import importlib

    module = importlib.import_module(f".commands.{_MODULES[args.command]}", package="brat")

    try:
        report = asyncio.run(module.execute(args, console))
    except KeyboardInterrupt:
        console.write()
        console.warn("Interrupted.")
        return 130
    except (ProfileError, ProtocolError, ValueError) as exc:
        console.error(str(exc))
        return 2
    except PermissionError as exc:
        console.error(f"{exc}")
        console.info("Peripheral mode and raw HCI access usually need sudo.")
        return 2
    except Exception as exc:  # noqa: BLE001
        from .core.peripheral import PeripheralError

        if isinstance(exc, PeripheralError):
            console.error(str(exc))
            return 2
        console.error(f"{type(exc).__name__}: {exc}")
        console.info("Run `brat doctor` to check the environment.")
        return 1

    emit(report, args.output, console, text_renderer=_renderer_for(module))

    return report.findings.exit_code(Severity.parse(args.fail_at))


def _renderer_for(module):
    render = getattr(module, "render", None)
    if render is None:
        return None

    def wrapper(report, console):
        render(report, console)

    return wrapper


if __name__ == "__main__":
    sys.exit(main())
