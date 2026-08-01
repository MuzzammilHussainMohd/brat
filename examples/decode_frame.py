#!/usr/bin/env python3
"""Decode captured frames against a profile's protocol block.

Handy while writing a `protocol:` block: paste hex you pulled out of a sniffer
capture or a `brat impersonate` session log and check that your field list and
checksum settings actually parse it.

    ./examples/decode_frame.py mira_ultra4 A5 00 00 D0 E0 A3 00 0E ...
    ./examples/decode_frame.py mira_ultra4 --session-log session.json

Also serves as a short tour of the library API - every BRAT command is built
from these same pieces.
"""

import argparse
import json
import sys
from pathlib import Path

# Run straight from a clone, without installing first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from brat.core.profile import load_profile  # noqa: E402
from brat.core.protocol import parse_hex  # noqa: E402


def decode_one(engine, data: bytes) -> bool:
    frame = engine.decode(data)

    print(f"\n{len(data)} bytes: {data.hex(' ').upper()}")
    if frame is None:
        print("  -> not a frame for this protocol")
        print("     Check the const field values and the frame length fields.")
        return False

    print(f"  -> {engine.describe(frame)}")
    for name, value in frame.values.items():
        rendered = (
            value.hex(" ").upper()
            if isinstance(value, (bytes, bytearray))
            else f"{value} (0x{value:X})"
            if isinstance(value, int)
            else value
        )
        print(f"       {name:<10} {rendered}")

    if not frame.checksum_ok:
        print("  !! checksum did not verify - the profile's crc block may be wrong")
        return False

    # Show what the profile would send back, if anything.
    responses = engine.responses_for(frame)
    if responses:
        print(f"  -> profile would reply with {len(responses)} frame(s):")
        for delay, out, label in responses:
            print(f"       +{delay:<5.2f}s  {label:<14} {out.hex(' ').upper()}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("profile", help="profile slug or path")
    parser.add_argument("hex", nargs="*", help="frame bytes as hex")
    parser.add_argument("--session-log", help="decode every rx frame in a session log")
    args = parser.parse_args()

    profile = load_profile(args.profile)
    engine = profile.protocol
    if engine is None:
        print(f"profile '{profile.slug}' has no protocol block", file=sys.stderr)
        return 2

    print(f"protocol: {engine.name}  ({len(engine.commands)} known commands)")

    frames = []
    if args.session_log:
        log = json.loads(open(args.session_log).read())
        frames = [
            bytes.fromhex(e["hex"]) for e in log["entries"] if e["direction"] == "rx"
        ]
    elif args.hex:
        frames = [parse_hex("".join(args.hex))]
    else:
        parser.error("give some hex bytes, or --session-log")

    ok = sum(decode_one(engine, f) for f in frames)
    print(f"\n{ok}/{len(frames)} frame(s) decoded cleanly")
    return 0 if ok == len(frames) else 1


if __name__ == "__main__":
    sys.exit(main())
