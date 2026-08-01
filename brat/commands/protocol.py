"""`brat protocol` - work out a device's framing, and check that you have.

The gap this fills: `brat impersonate` will happily log everything a client
sends, but turning that pile of hex into a `protocol:` block is manual work,
and until you have one the rogue peripheral can only listen. These two
subcommands close that loop.

    brat protocol infer  --session-log session.json     # hex   -> draft block
    brat protocol decode --profile mine --session-log session.json   # block -> proof

`infer` guesses; `decode` checks. Keep both in the loop - a plausible wrong
guess costs more to discover later than no guess at all, which is why `infer`
builds an engine from its own output and re-decodes the capture before
reporting anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..core.console import Console
from ..core.infer import infer, to_protocol_config
from ..core.profile import load_profile
from ..core.protocol import ProtocolEngine, ProtocolError, parse_hex
from ..core.report import Report


def load_frames(path: str, include_tx: bool = False) -> list[bytes]:
    """Pull frame bytes out of a session log written by impersonate/inject."""
    doc = json.loads(Path(path).expanduser().read_text())
    # Accept both the whole report and the bare session object, since the
    # former is what -o json writes and the latter what --session-log writes.
    session = doc.get("session", doc)
    entries = session.get("entries", [])
    wanted = {"rx", "tx"} if include_tx else {"rx"}
    return [
        bytes.fromhex(e["hex"])
        for e in entries
        if e.get("direction") in wanted and e.get("hex")
    ]


async def execute(args, console: Console) -> Report:
    if args.protocol_action == "decode":
        return _decode(args, console)
    return _infer(args, console)


# ---------------------------------------------------------------------------
# infer
# ---------------------------------------------------------------------------


def _infer(args, console: Console) -> Report:
    report = Report(command="protocol", target=args.session_log)

    frames = load_frames(args.session_log, include_tx=args.include_tx)
    if not frames:
        report.note(
            f"No frames in {args.session_log}. `infer` reads what a client wrote to "
            "the peripheral; if the session log is empty, the client never wrote "
            "anything (check that it subscribed to the notify characteristic)."
        )
        report.data = {"frames": 0, "inferred": None}
        return report

    result = infer(frames, min_frames=args.min_frames)
    config = to_protocol_config(result, name=args.name)

    # Self-check. An inference nobody verified is a guess wearing a suit.
    decoded, checksum_ok, build_error = 0, 0, ""
    try:
        engine = ProtocolEngine(config)
        for raw in frames:
            frame = engine.decode(raw)
            if frame is None:
                continue
            decoded += 1
            if frame.checksum_ok:
                checksum_ok += 1
    except ProtocolError as exc:
        build_error = str(exc)

    report.data = {
        "session_log": args.session_log,
        "frames": len(frames),
        "prefix": result.prefix.hex(),
        "suffix": result.suffix.hex(),
        "length_field": (
            None
            if result.length_offset is None
            else {
                "offset": result.length_offset,
                "type": result.length_type,
                "overhead": result.length_overhead,
            }
        ),
        "command_field": (
            None
            if result.cmd_offset is None
            else {
                "offset": result.cmd_offset,
                "observed": [f"0x{c:02X}" for c in result.commands],
            }
        ),
        "checksum_candidates": [
            {"algorithm": a, "byte_order": b, "covers_from": c}
            for a, b, c, _ in result.crc_matches
        ],
        "self_check": {
            "frames": len(frames),
            "decoded": decoded,
            "checksum_verified": checksum_ok,
            "build_error": build_error or None,
        },
        "notes": result.notes,
        "protocol": config,
        "yaml": yaml.safe_dump({"protocol": config}, sort_keys=False, width=100),
    }

    for note in result.notes:
        report.note(note)
    if build_error:
        report.note(f"The inferred block does not build: {build_error}")
    elif decoded < len(frames):
        report.note(
            f"Only {decoded} of {len(frames)} frames decode with the inferred block, "
            "so it does not describe the whole capture. The frames it rejects are "
            "the interesting ones - they may be a second frame format, or "
            "fragments of a frame split across two ATT writes."
        )
    elif checksum_ok < decoded:
        report.note(
            f"{decoded - checksum_ok} frame(s) decode structurally but fail the "
            "checksum, so the algorithm or covered range is not quite right."
        )
    return report


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


def _decode(args, console: Console) -> Report:
    profile = load_profile(args.profile)
    report = Report(command="protocol", target=profile.slug)

    engine = profile.protocol
    if engine is None:
        report.note(
            f"Profile '{profile.slug}' has no protocol: block, so there is nothing to "
            "decode against. Run `brat protocol infer` on a session log to draft one."
        )
        report.data = {"profile": profile.slug, "frames": []}
        return report

    if args.session_log:
        raw_frames = load_frames(args.session_log, include_tx=args.include_tx)
    else:
        raw_frames = [parse_hex("".join(args.hex))] if args.hex else []

    results = []
    for raw in raw_frames:
        frame = engine.decode(raw)
        entry: dict = {"hex": raw.hex(), "length": len(raw), "decoded": frame is not None}
        if frame is not None:
            entry["description"] = engine.describe(frame)
            entry["checksum_ok"] = frame.checksum_ok
            entry["fields"] = {
                name: value.hex() if isinstance(value, (bytes, bytearray)) else value
                for name, value in frame.values.items()
            }
            try:
                entry["would_reply"] = [
                    {"delay": d, "label": label, "hex": out.hex()}
                    for d, out, label in engine.responses_for(frame)
                ]
            except ProtocolError as exc:
                entry["would_reply"] = []
                entry["reply_error"] = str(exc)
        results.append(entry)

    ok = sum(1 for r in results if r["decoded"] and r.get("checksum_ok"))
    report.data = {
        "profile": profile.slug,
        "protocol": engine.name,
        "frames": results,
        "summary": {"total": len(results), "verified": ok},
    }
    if results and ok < len(results):
        report.note(
            f"{len(results) - ok} of {len(results)} frames did not decode cleanly. "
            "Check the const field values and the checksum block."
        )
    return report


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render(report: Report, console: Console) -> None:
    data = report.data
    if "yaml" in data:
        _render_infer(data, console)
    elif "frames" in data and isinstance(data["frames"], list):
        _render_decode(data, console)


def _render_infer(data: dict, console: Console) -> None:
    console.header("INFERRED FRAME LAYOUT")
    console.kv("session log", data["session_log"])
    console.kv("frames analysed", str(data["frames"]))

    rows = [
        ["start bytes", data["prefix"].upper() or "(none)"],
        ["end bytes", data["suffix"].upper() or "(none)"],
    ]
    length = data["length_field"]
    rows.append(
        [
            "length field",
            f"offset {length['offset']}, {length['type']}, "
            f"frame = payload + {length['overhead']}"
            if length
            else "not identified",
        ]
    )
    command = data["command_field"]
    rows.append(
        [
            "command field",
            f"offset {command['offset']} ({', '.join(command['observed'])})"
            if command
            else "not identified",
        ]
    )
    candidates = data["checksum_candidates"]
    if candidates:
        rows.append(
            [
                "checksum",
                "  |  ".join(
                    f"{c['algorithm']} {c['byte_order']}-endian" for c in candidates
                ),
            ]
        )
    else:
        rows.append(["checksum", "none matched"])
    console.write()
    console.table(["FIELD", "FINDING"], rows)

    check = data["self_check"]
    console.write()
    if check["build_error"]:
        console.error(f"the inferred block does not build: {check['build_error']}")
    elif check["decoded"] == check["frames"] and check["checksum_verified"] == check["frames"]:
        console.ok(
            f"Self-check: all {check['frames']} frames decode and verify against the "
            "block below."
        )
    else:
        console.warn(
            f"Self-check: {check['decoded']}/{check['frames']} decode, "
            f"{check['checksum_verified']}/{check['frames']} verify. "
            "The block below is a starting point, not an answer."
        )

    console.write()
    console.rule("PASTE INTO YOUR PROFILE")
    console.write()
    console.write(data["yaml"])
    console.info(
        "Rename the fields to something meaningful, then check it with "
        "`brat protocol decode --profile <slug> --session-log <same log>`."
    )


def _render_decode(data: dict, console: Console) -> None:
    console.header("DECODED FRAMES")
    console.kv("profile", data.get("profile", "-"))
    console.kv("protocol", data.get("protocol", "-"))

    for entry in data["frames"]:
        console.write()
        console.write(f"  {entry['length']}B  {entry['hex'].upper()}")
        if not entry["decoded"]:
            console.error("    not a frame for this protocol")
            console.info("    Check the const field values and the length fields.")
            continue
        console.write(f"    {console.bold(entry['description'])}")
        for name, value in entry["fields"].items():
            console.write(f"      {name:<12} {value}")
        if not entry.get("checksum_ok"):
            console.warn("    checksum did not verify - the crc block may be wrong")
        for reply in entry.get("would_reply", []):
            console.write(
                f"    -> +{reply['delay']:.2f}s  {reply['label']:<14} "
                f"{reply['hex'].upper()}"
            )
        if entry.get("reply_error"):
            console.error(f"    reply could not be built: {entry['reply_error']}")

    summary = data.get("summary")
    if summary:
        console.write()
        console.kv("verified", f"{summary['verified']}/{summary['total']}")
