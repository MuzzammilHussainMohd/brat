"""Guess a frame layout from captured frames.

A GATT walk sees the pipe; it cannot see the frames going through it. So the
normal way to learn an undocumented device is to stand up a rogue peripheral,
let the real client talk to it, and read what arrives. That leaves you with a
pile of hex and the tedious part still to do: work out where the length field
is, which byte is the command, and which of the dozen plausible CRC variants
the vendor used.

This does that mechanically. It is deliberately a *guess* - it reports what fits
the evidence and how much evidence there was, and the caller is expected to
check the result by building an engine from it and decoding the same frames
back. Inference that cannot be checked is worse than none, because a plausible
wrong answer costs more to discover than no answer.

Nothing here is device-specific.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .checksum import PRESETS, Checksum, CrcParams

_INT_TYPES = {"u8": (1, "big"), "u16be": (2, "big"), "u16le": (2, "little")}

# Frame headers are short. Searching further turns coincidences into
# confident-looking answers, which is worse than reporting nothing.
_MAX_HEADER = 12


@dataclass
class Candidate:
    """One inferred aspect of the frame, with the evidence for it."""

    what: str
    value: str
    detail: str = ""
    confident: bool = True


@dataclass
class Inference:
    prefix: bytes = b""
    suffix: bytes = b""
    length_offset: int | None = None
    length_type: str = ""
    length_overhead: int = 0
    cmd_offset: int | None = None
    commands: list[int] = field(default_factory=list)
    crc_matches: list[tuple[str, str, int, int]] = field(default_factory=list)
    # offset -> ("const" | "enum" | "var", observed values)
    header: dict[int, tuple[str, list[int]]] = field(default_factory=dict)
    varying_prefix: dict[int, list[int]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    frame_count: int = 0

    @property
    def crc(self) -> tuple[str, str, int, int] | None:
        return self.crc_matches[0] if self.crc_matches else None


def _common_prefix(frames: list[bytes]) -> bytes:
    first = frames[0]
    n = 0
    while n < len(first) and all(len(f) > n and f[n] == first[n] for f in frames):
        n += 1
    return first[:n]


def _common_suffix(frames: list[bytes]) -> bytes:
    first = frames[0]
    n = 0
    while n < len(first) and all(len(f) > n and f[-1 - n] == first[-1 - n] for f in frames):
        n += 1
    return first[len(first) - n :] if n else b""


def _find_length_field(frames: list[bytes], max_offset: int) -> tuple[int, str, int] | None:
    """An offset/width whose value tracks frame length with a fixed overhead.

    Requires frames of at least two distinct lengths - otherwise every constant
    byte in the frame "predicts" the length perfectly and the answer is noise.
    """
    if len({len(f) for f in frames}) < 2:
        return None

    for offset in range(max_offset + 1):
        for type_name, (width, endian) in _INT_TYPES.items():
            if any(len(f) < offset + width for f in frames):
                continue
            overheads = {
                len(f) - int.from_bytes(f[offset : offset + width], endian) for f in frames
            }
            if len(overheads) == 1:
                overhead = overheads.pop()
                # An overhead equal to the shortest frame just means that frame
                # carried an empty payload, which is normal - only a negative
                # or zero overhead is impossible.
                if 0 < overhead <= min(len(f) for f in frames):
                    return offset, type_name, overhead
    return None


def _find_command_field(frames: list[bytes], region: range) -> int | None:
    """The byte that varies most across frames - the command, usually."""
    best, best_distinct = None, 1
    for offset in region:
        if any(len(f) <= offset for f in frames):
            continue
        distinct = len({f[offset] for f in frames})
        if distinct > best_distinct:
            best, best_distinct = offset, distinct
    return best


def _find_checksum(
    frames: list[bytes], suffix_len: int, prefix_len: int
) -> list[tuple[str, str, int, int]]:
    """Every (algorithm, byte order, crc offset, cover start) fitting all frames.

    Reports all of them rather than the first: several presets are genuinely
    the same polynomial, and when two distinct ones both fit, the operator
    needs to know the evidence does not separate them.
    """
    matches: list[tuple[str, str, int, int]] = []
    seen_params: set[tuple] = set()

    for name, params in PRESETS.items():
        width_bytes = params.width // 8
        # The checksum sits between the payload and the trailing constant.
        crc_offset = len(frames[0]) - suffix_len - width_bytes
        if crc_offset <= 0:
            continue
        if any(len(f) - suffix_len - width_bytes != crc_offset for f in frames):
            # Frames differ in length, so locate it relative to each frame's end.
            pass

        for byte_order in ("big", "little"):
            for cover_start in range(prefix_len + 1):
                ok = True
                for frame in frames:
                    off = len(frame) - suffix_len - width_bytes
                    if off <= cover_start:
                        ok = False
                        break
                    checksum = Checksum(
                        {"algorithm": name, "byte_order": byte_order}
                    )
                    if not checksum.verify(
                        frame[cover_start:off], frame[off : off + width_bytes]
                    ):
                        ok = False
                        break
                if not ok:
                    continue
                # Dedupe by the actual polynomial parameters: crc16-ibm and
                # crc16-modbus are the same thing under two names, and
                # reporting both as "ambiguous" would be misleading.
                key = (_params_key(params), byte_order, cover_start)
                if key in seen_params:
                    continue
                seen_params.add(key)
                matches.append((name, byte_order, cover_start, width_bytes))
    return matches


def _params_key(p: CrcParams) -> tuple:
    return (p.width, p.poly, p.init, p.reflect_in, p.reflect_out, p.xor_out)


def infer(frames: list[bytes], min_frames: int = 3) -> Inference:
    """Work out what layout the given frames share."""
    frames = [bytes(f) for f in frames if f]
    result = Inference(frame_count=len(frames))
    if not frames:
        result.notes.append("no frames to work from")
        return result

    if len(frames) < min_frames:
        result.notes.append(
            f"only {len(frames)} frame(s); at least {min_frames} are needed before "
            "a shared layout means anything. Treat everything below as a sketch."
        )

    result.prefix = _common_prefix(frames)
    result.suffix = _common_suffix(frames)

    min_len = min(len(f) for f in frames)
    # Headers are short; searching far into the frame turns coincidences into
    # confident-looking answers.
    found = _find_length_field(frames, max_offset=min(_MAX_HEADER, min_len - 1))
    if found:
        result.length_offset, result.length_type, result.length_overhead = found
    else:
        if len({len(f) for f in frames}) < 2:
            result.notes.append(
                "every frame is the same length, so a length field cannot be "
                "distinguished from a constant. Capture a longer exchange."
            )
        else:
            result.notes.append("no offset tracked the frame length consistently")

    header_end = (
        result.length_offset
        if result.length_offset is not None
        else min(_MAX_HEADER, min_len - 1)
    )
    result.cmd_offset = _find_command_field(frames, range(len(result.prefix), max(header_end, 1)))
    if result.cmd_offset is not None:
        result.commands = sorted({f[result.cmd_offset] for f in frames})

    # Classify every remaining header byte on its own. Taking the longest
    # common prefix and stopping there loses the constants that sit *after* a
    # varying byte - a fixed source/destination pair behind a direction flag,
    # say - and typing those as free u8 gives up the ability to reject a frame
    # that is not this protocol at all.
    for offset in range(header_end):
        if offset == result.cmd_offset:
            continue
        values = sorted({f[offset] for f in frames})
        if len(values) == 1:
            result.header[offset] = ("const", values)
        elif len(values) <= 3:
            # A small enumerated field - a direction flag, typically. Calling
            # it const would make the profile reject half the traffic.
            result.header[offset] = ("enum", values)
        else:
            result.header[offset] = ("var", values)
    result.varying_prefix = {
        off: vals for off, (kind, vals) in result.header.items() if kind == "enum"
    }

    result.crc_matches = _find_checksum(frames, len(result.suffix), len(result.prefix))
    if not result.crc_matches:
        result.notes.append(
            "no checksum preset verified every frame. The device may not use one, "
            "may cover a different byte range, or may use a variant not in "
            "brat/core/checksum.py."
        )
    elif len(result.crc_matches) > 1:
        result.notes.append(
            f"{len(result.crc_matches)} checksum configurations fit equally well; "
            "more frames would separate them."
        )
    return result


def to_protocol_config(result: Inference, name: str = "inferred") -> dict:
    """Turn an inference into a `protocol:` block that can be built and tested."""
    fields: list[dict] = []
    header_end = (
        result.length_offset
        if result.length_offset is not None
        else (result.cmd_offset + 1 if result.cmd_offset is not None else 0)
    )

    offset = 0
    while offset < header_end:
        if offset == result.cmd_offset:
            fields.append({"name": "cmd", "type": "u8"})
            offset += 1
            continue
        kind, values = result.header.get(offset, ("var", []))
        if kind == "const":
            fields.append(
                {"name": f"const{offset}", "type": "const", "value": f"{values[0]:02X}"}
            )
        elif kind == "enum":
            fields.append(
                {
                    "name": f"field{offset}",
                    "type": "u8",
                    "default": values[0],
                    "description": "observed values: "
                    + ", ".join(f"0x{v:02X}" for v in values),
                }
            )
        else:
            fields.append({"name": f"byte{offset}", "type": "u8"})
        offset += 1

    if result.length_offset is not None:
        fields.append(
            {"name": "length", "type": result.length_type, "length_of": "payload"}
        )

    fields.append({"name": "payload", "type": "bytes", "length_from": "length"}
                  if result.length_offset is not None
                  else {"name": "payload", "type": "bytes"})

    covered = [f["name"] for f in fields]
    if result.crc:
        fields.append({"name": "crc", "type": "crc"})
    for i, byte in enumerate(result.suffix):
        fields.append({"name": f"end{i}", "type": "const", "value": f"{byte:02X}"})

    config: dict = {"name": name, "frame": {"fields": fields}}
    if result.crc:
        algorithm, byte_order, cover_start, _ = result.crc
        config["crc"] = {
            "algorithm": algorithm,
            "byte_order": byte_order,
            "covers": covered,
        }
        if cover_start:
            config["crc"]["_note"] = (
                f"checksum appeared to start {cover_start} byte(s) into the frame"
            )
    if result.commands:
        config["commands"] = {f"0x{c:02X}": f"UNKNOWN_{c:02X}" for c in result.commands}
    return config
