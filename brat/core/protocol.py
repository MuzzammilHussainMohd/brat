"""Declarative framed-protocol engine.

Most custom BLE devices do not speak GATT semantically - they open a
transparent serial pipe (Nordic UART or a vendor equivalent) and push
fixed-layout frames through it. Those frames are nearly always the same shape:
a start byte, some routing/command bytes, a length, a payload, a checksum, and
a terminator.

Rather than make every profile ship Python, a profile declares the frame as a
field list. BRAT can then decode what a phone sends to a rogue peripheral, and
build correctly-checksummed replies, for a protocol it has never seen.

    fields:
      - {name: start,     type: const, value: "A5"}
      - {name: cmd,       type: u8}
      - {name: length,    type: u16be, length_of: payload}
      - {name: payload,   type: bytes, length_from: length}
      - {name: crc,       type: crc}
      - {name: end,       type: const, value: "5A"}

This is the piece that lets one impersonation engine serve any device.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .checksum import Checksum

# name -> (byte width, endianness)
INT_TYPES: dict[str, tuple[int, str]] = {
    "u8": (1, "big"),
    "u16be": (2, "big"),
    "u16le": (2, "little"),
    "u24be": (3, "big"),
    "u24le": (3, "little"),
    "u32be": (4, "big"),
    "u32le": (4, "little"),
}


class ProtocolError(ValueError):
    """Malformed protocol definition in a profile."""


def parse_hex(text: str | bytes | None) -> bytes:
    """Accept 'A5 00 5A', 'a5005a', '0xA5', or bytes."""
    if text is None:
        return b""
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    cleaned = re.sub(r"(0x)|[\s:,_-]", "", str(text), flags=re.IGNORECASE)
    if not cleaned:
        return b""
    if len(cleaned) % 2:
        raise ProtocolError(f"hex string has odd length: {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ProtocolError(f"invalid hex {text!r}: {exc}") from None


def as_int(value: Any) -> int:
    """Coerce a protocol byte/command value to int.

    Every other numeric value in this module - `parse_hex`, byte fields, the
    `commands:` map's keys - is hex, with or without a `0x` prefix. A bare
    numeric string like "93" here used to fall back to decimal, so a profile
    author or `--on-cmd 93` writing what they read off a sniffer capture as
    hex silently got a different byte value (93 decimal = 0x5D, not 0x93) with
    no warning. Strings are now always read as hex, matching the rest of the
    module; only a real `int` (from YAML's own `0x..` literal syntax) passes
    through unchanged.
    """
    if isinstance(value, bool):  # bool is an int subclass; not a valid byte value here
        raise ProtocolError(f"expected an integer, got a bool: {value!r}")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise ProtocolError("empty value where a hex integer was expected")
    cleaned = text[2:] if text.lower().startswith("0x") else text
    try:
        return int(cleaned, 16)
    except ValueError:
        raise ProtocolError(
            f"expected a hex integer (e.g. 0x93 or 93 - both mean the same thing "
            f"here), got {value!r}"
        ) from None


# ---------------------------------------------------------------------------
# Frame definition
# ---------------------------------------------------------------------------


@dataclass
class FieldSpec:
    name: str
    type: str
    value: bytes | None = None        # const only
    length: int | None = None         # bytes, fixed length
    length_from: str | None = None    # bytes, length taken from this int field
    length_of: str | None = None      # int field, auto-set to len(that field)
    default: Any = None
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "FieldSpec":
        if "name" not in d or "type" not in d:
            raise ProtocolError(f"frame field needs name and type: {d!r}")
        ftype = str(d["type"]).lower()
        known = set(INT_TYPES) | {"const", "bytes", "crc"}
        if ftype not in known:
            raise ProtocolError(
                f"unknown field type {ftype!r} in field {d['name']!r}; "
                f"known: {', '.join(sorted(known))}"
            )
        return cls(
            name=str(d["name"]),
            type=ftype,
            value=parse_hex(d["value"]) if d.get("value") is not None else None,
            length=int(d["length"]) if d.get("length") is not None else None,
            length_from=d.get("length_from"),
            length_of=d.get("length_of"),
            default=d.get("default"),
            description=str(d.get("description", "")),
        )

    def fixed_size(self, checksum: Checksum) -> int | None:
        """Serialized size when it is knowable without data. None if variable."""
        if self.type == "const":
            return len(self.value or b"")
        if self.type in INT_TYPES:
            return INT_TYPES[self.type][0]
        if self.type == "crc":
            return checksum.nbytes
        if self.type == "bytes":
            return self.length  # None when driven by length_from
        return None


@dataclass
class Frame:
    """A decoded frame.

    `command_field`/`payload_field` name which of `values` the `.cmd`/
    `.payload` properties read - a profile can rename these fields (e.g.
    `opcode`/`data`) via `protocol.roles`, and a frame built by a codec with
    non-default roles must still expose `.cmd`/`.payload` correctly rather
    than silently returning None/empty for a real field under another name.
    """

    values: dict[str, Any]
    raw: bytes
    checksum_ok: bool = True
    command_field: str = "cmd"
    payload_field: str = "payload"

    @property
    def payload(self) -> bytes:
        v = self.values.get(self.payload_field)
        return v if isinstance(v, (bytes, bytearray)) else b""

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    @property
    def cmd(self) -> int | None:
        v = self.values.get(self.command_field)
        return v if isinstance(v, int) else None


class FrameCodec:
    """Builds and parses frames from a declarative field list."""

    def __init__(
        self,
        fields: list[dict],
        checksum: Checksum,
        command_field: str = "cmd",
        payload_field: str = "payload",
    ) -> None:
        if not fields:
            raise ProtocolError("frame definition has no fields")
        self.fields = [FieldSpec.from_dict(f) for f in fields]
        self.checksum = checksum
        self._by_name = {f.name: f for f in self.fields}
        self.field_widths: dict[str, int] = {
            f.name: INT_TYPES[f.type][0] for f in self.fields if f.type in INT_TYPES
        }

        crc_fields = [f for f in self.fields if f.type == "crc"]
        if len(crc_fields) > 1:
            raise ProtocolError("frame may declare at most one crc field")
        if crc_fields and checksum.algorithm == "none":
            raise ProtocolError("frame declares a crc field but crc.algorithm is 'none'")

        for f in self.fields:
            if f.length_from and f.length_from not in self._by_name:
                raise ProtocolError(f"{f.name}.length_from references unknown field {f.length_from!r}")
            if f.length_of and f.length_of not in self._by_name:
                raise ProtocolError(f"{f.name}.length_of references unknown field {f.length_of!r}")

        # `command_field`/`payload_field` let a profile rename cmd/payload
        # (via `protocol.roles`) without every consumer of Frame.cmd/.payload
        # silently reading nothing. Only validate a caller-supplied override -
        # the "cmd"/"payload" defaults are allowed to be absent (not every
        # protocol has a command byte or a variable payload), but a rename
        # that points at a field which does not exist is a config mistake
        # worth failing on immediately rather than discovering it as an
        # emulation rule that mysteriously never fires.
        if command_field != "cmd" and command_field not in self._by_name:
            raise ProtocolError(
                f"protocol.roles.command names field {command_field!r}, which this "
                "frame does not declare"
            )
        if payload_field != "payload" and payload_field not in self._by_name:
            raise ProtocolError(
                f"protocol.roles.payload names field {payload_field!r}, which this "
                "frame does not declare"
            )
        self.command_field = command_field
        self.payload_field = payload_field

    # -- helpers ------------------------------------------------------------

    def _covered_names(self) -> list[str]:
        """Field names the checksum is computed over."""
        if self.checksum.covers:
            return list(self.checksum.covers)
        # Default: everything preceding the crc field.
        out: list[str] = []
        for f in self.fields:
            if f.type == "crc":
                break
            out.append(f.name)
        return out

    def _trailing_fixed_size(self, index: int) -> int | None:
        """Total size of fields after `index`, or None if any is variable."""
        total = 0
        for f in self.fields[index + 1 :]:
            size = f.fixed_size(self.checksum)
            if size is None:
                return None
            total += size
        return total

    # -- build --------------------------------------------------------------

    def build(self, values: dict[str, Any]) -> bytes:
        """Serialize a frame. Const and crc fields are filled automatically."""
        parts: dict[str, bytes] = {}
        order: list[str] = []

        for spec in self.fields:
            order.append(spec.name)

            if spec.type == "const":
                parts[spec.name] = spec.value or b""
                continue

            if spec.type == "crc":
                parts[spec.name] = b""  # filled below
                continue

            raw = values.get(spec.name, spec.default)

            if spec.type == "bytes":
                data = parse_hex(raw) if not isinstance(raw, (bytes, bytearray)) else bytes(raw)
                if spec.length is not None and len(data) != spec.length:
                    if len(data) > spec.length:
                        raise ProtocolError(
                            f"field {spec.name!r} is {len(data)}B, fixed length is {spec.length}B"
                        )
                    data = data + b"\x00" * (spec.length - len(data))
                parts[spec.name] = data
                continue

            # integer field
            width, endian = INT_TYPES[spec.type]
            if spec.length_of is not None:
                target = parts.get(spec.length_of)
                if target is None:
                    # length precedes payload in the field list, which is the
                    # normal ordering; resolve the payload eagerly.
                    tgt_spec = self._by_name[spec.length_of]
                    tgt_raw = values.get(spec.length_of, tgt_spec.default)
                    target = (
                        bytes(tgt_raw)
                        if isinstance(tgt_raw, (bytes, bytearray))
                        else parse_hex(tgt_raw)
                    )
                    parts[spec.length_of] = target
                number = len(target)
            elif raw is None:
                number = 0
            else:
                number = as_int(raw)
            try:
                parts[spec.name] = number.to_bytes(width, endian)
            except OverflowError:
                raise ProtocolError(
                    f"value {number} does not fit in {spec.type} field {spec.name!r}"
                ) from None

        # Fill the checksum now that every other field is known.
        crc_spec = next((f for f in self.fields if f.type == "crc"), None)
        if crc_spec is not None:
            covered = b"".join(parts.get(n, b"") for n in self._covered_names())
            parts[crc_spec.name] = self.checksum.pack(self.checksum.compute(covered))

        return b"".join(parts[n] for n in order)

    # -- parse --------------------------------------------------------------

    def parse(self, data: bytes, strict: bool = True) -> Frame | None:
        """Decode a frame. Returns None if `data` is not this protocol.

        With strict=False, a checksum mismatch still returns a Frame (flagged
        via `checksum_ok`) - useful when analysing a device that computes its
        checksum differently to what the profile claims.
        """
        data = bytes(data)
        values: dict[str, Any] = {}
        raw_parts: dict[str, bytes] = {}
        offset = 0

        for index, spec in enumerate(self.fields):
            if spec.type == "const":
                expect = spec.value or b""
                chunk = data[offset : offset + len(expect)]
                if chunk != expect:
                    return None
                raw_parts[spec.name] = chunk
                values[spec.name] = chunk
                offset += len(expect)
                continue

            if spec.type in INT_TYPES:
                width, endian = INT_TYPES[spec.type]
                chunk = data[offset : offset + width]
                if len(chunk) < width:
                    return None
                values[spec.name] = int.from_bytes(chunk, endian)
                raw_parts[spec.name] = chunk
                offset += width
                continue

            if spec.type == "bytes":
                if spec.length is not None:
                    size = spec.length
                elif spec.length_from is not None:
                    size = values.get(spec.length_from)
                    if not isinstance(size, int):
                        return None
                else:
                    trailing = self._trailing_fixed_size(index)
                    if trailing is None:
                        raise ProtocolError(
                            f"field {spec.name!r} has no length and is followed by "
                            "another variable-length field"
                        )
                    size = len(data) - offset - trailing
                if size < 0 or offset + size > len(data):
                    return None
                chunk = data[offset : offset + size]
                values[spec.name] = chunk
                raw_parts[spec.name] = chunk
                offset += size
                continue

            if spec.type == "crc":
                n = self.checksum.nbytes
                chunk = data[offset : offset + n]
                if len(chunk) < n:
                    return None
                values[spec.name] = self.checksum.unpack(chunk)
                raw_parts[spec.name] = chunk
                offset += n
                continue

        covered = b"".join(raw_parts.get(n, b"") for n in self._covered_names())
        crc_spec = next((f for f in self.fields if f.type == "crc"), None)
        ok = True
        if crc_spec is not None:
            ok = self.checksum.verify(covered, raw_parts.get(crc_spec.name, b""))
            if not ok and strict:
                return None

        return Frame(
            values=values,
            raw=data[:offset],
            checksum_ok=ok,
            command_field=self.command_field,
            payload_field=self.payload_field,
        )

    @property
    def min_size(self) -> int:
        """Smallest possible frame - used to reject obvious fragments."""
        total = 0
        for f in self.fields:
            size = f.fixed_size(self.checksum)
            total += size if size is not None else 0
        return total


# ---------------------------------------------------------------------------
# Response templating
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\{([^}]+)\}")
_SLICE_RE = re.compile(r"^(?P<src>req\.(?:payload|raw))(?:\[(?P<a>-?\d*):(?P<b>-?\d*)\])?$")


@dataclass
class TemplateContext:
    """Everything a response template may reference."""

    request: Frame | None = None
    variables: dict[str, bytes] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)
    # Declared byte width for each int-typed frame field, e.g. {"length": 2}
    # for a u16be field. Lets {req.NAME} emit the field's real width instead
    # of the minimal width needed to hold its current value - without this,
    # {req.length} on a u16be field currently holding 5 emitted 1 byte, not
    # 2, silently truncating any raw template that echoes a header field back.
    field_widths: dict[str, int] = field(default_factory=dict)


def render_template(template: str | bytes | None, ctx: TemplateContext) -> bytes:
    """Build bytes from a template string.

    Literal text is hex. Tokens in braces are substituted:

      {req.payload}          whole request payload
      {req.payload[0:8]}     a slice of it
      {req.raw[2:3]}         a slice of the raw request frame
      {var.NAME}             a profile variable (hex)
      {blob.NAME}            a loaded binary blob (e.g. --payload file)
      {ts}  {ts:u32le}       current unix time, u32be by default
      {rand:N}               N random bytes
      {zero:N}               N zero bytes
    """
    if template is None:
        return b""
    if isinstance(template, (bytes, bytearray)):
        return bytes(template)

    out = bytearray()
    pos = 0
    for match in _TOKEN_RE.finditer(template):
        literal = template[pos : match.start()]
        out += parse_hex(literal)
        out += _resolve_token(match.group(1).strip(), ctx)
        pos = match.end()
    out += parse_hex(template[pos:])
    return bytes(out)


def _resolve_token(token: str, ctx: TemplateContext) -> bytes:
    slice_match = _SLICE_RE.match(token)
    if slice_match:
        if ctx.request is None:
            raise ProtocolError(f"token {{{token}}} used with no request in context")
        source = (
            ctx.request.payload
            if slice_match.group("src") == "req.payload"
            else ctx.request.raw
        )
        a_txt, b_txt = slice_match.group("a"), slice_match.group("b")
        if a_txt is None and b_txt is None:
            return bytes(source)
        a = int(a_txt) if a_txt else 0
        b = int(b_txt) if b_txt else len(source)
        return bytes(source[a:b])

    if token.startswith("var."):
        name = token[4:]
        if name not in ctx.variables:
            raise ProtocolError(f"undefined profile variable {name!r}")
        return ctx.variables[name]

    if token.startswith("blob."):
        name = token[5:]
        if name not in ctx.blobs:
            raise ProtocolError(
                f"blob {name!r} not loaded - supply it with --payload {name}=FILE"
            )
        return ctx.blobs[name]

    if token == "ts" or token.startswith("ts:"):
        kind = token.split(":", 1)[1] if ":" in token else "u32be"
        if kind not in INT_TYPES:
            raise ProtocolError(f"unknown timestamp format {kind!r}")
        width, endian = INT_TYPES[kind]
        return (int(time.time()) & ((1 << (width * 8)) - 1)).to_bytes(width, endian)

    if token.startswith("rand:"):
        return os.urandom(int(token[5:]))

    if token.startswith("zero:"):
        return b"\x00" * int(token[5:])

    if token.startswith("req."):
        # A named non-payload field, emitted in its declared width - e.g.
        # {req.length} on a u16be field must emit 2 bytes even when the
        # current value fits in 1, since a raw template echoing a header
        # field back needs the real wire width, not the minimal one.
        if ctx.request is None:
            raise ProtocolError(f"token {{{token}}} used with no request in context")
        name = token[4:]
        value = ctx.request.get(name)
        if value is None:
            raise ProtocolError(f"request has no field {name!r}")
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        width = ctx.field_widths.get(name) or max(1, (int(value).bit_length() + 7) // 8)
        return int(value).to_bytes(width, "big")

    raise ProtocolError(f"unknown template token {{{token}}}")


# ---------------------------------------------------------------------------
# Emulation rules
# ---------------------------------------------------------------------------


@dataclass
class ResponseSpec:
    """One outbound frame in a rule's response sequence."""

    delay: float = 0.0
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None
    label: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "ResponseSpec":
        known_meta = {"delay", "raw", "label"}
        return cls(
            delay=float(d.get("delay", 0.0)),
            raw=d.get("raw"),
            label=str(d.get("label", "")),
            fields={k: v for k, v in d.items() if k not in known_meta},
        )


@dataclass
class EmulationRule:
    name: str
    on_cmd: int | None = None
    on_any: bool = False
    responses: list[ResponseSpec] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "EmulationRule":
        on_cmd = d.get("on_cmd")
        return cls(
            name=str(d.get("name") or (f"cmd-{on_cmd}" if on_cmd is not None else "any")),
            on_cmd=as_int(on_cmd) if on_cmd is not None else None,
            on_any=bool(d.get("on_any", False)),
            responses=[ResponseSpec.from_dict(r) for r in d.get("respond", [])],
            description=str(d.get("description", "")),
        )

    def matches(self, frame: Frame) -> bool:
        if self.on_any:
            return True
        if self.on_cmd is None:
            return False
        return frame.cmd == self.on_cmd


class ProtocolEngine:
    """A profile's `protocol:` block, ready to decode and respond."""

    def __init__(self, config: dict) -> None:
        self.name = str(config.get("name", "unnamed"))
        self.description = str(config.get("description", ""))

        # Which characteristics carry this protocol. Optional: when absent the
        # peripheral infers the response channel from the service the client
        # wrote to, which is right for the common single-service case.
        transport = config.get("transport") or {}
        self.write_uuid: str | None = transport.get("write_uuid")
        self.notify_uuid: str | None = transport.get("notify_uuid")

        frame_cfg = config.get("frame") or {}
        fields = frame_cfg.get("fields")
        if not fields:
            raise ProtocolError("protocol.frame.fields is required")

        # A profile whose command/payload fields aren't named "cmd"/"payload"
        # declares that here. Without this, on_cmd rules would silently never
        # match and {req.payload} would silently render empty - both look
        # like "the device rejected everything" rather than a config mistake.
        roles = config.get("roles") or {}
        command_field = str(roles.get("command", "cmd"))
        payload_field = str(roles.get("payload", "payload"))

        self.checksum = Checksum(config.get("crc"))
        self.codec = FrameCodec(
            fields, self.checksum, command_field=command_field, payload_field=payload_field
        )

        self.commands: dict[int, str] = {
            as_int(k): str(v) for k, v in (config.get("commands") or {}).items()
        }

        emulation = config.get("emulation") or {}
        self.variables: dict[str, bytes] = {
            str(k): parse_hex(v) for k, v in (emulation.get("variables") or {}).items()
        }
        self.rules = [EmulationRule.from_dict(r) for r in (emulation.get("rules") or [])]

    # -- decode -------------------------------------------------------------

    def decode(self, data: bytes) -> Frame | None:
        if len(data) < self.codec.min_size:
            return None
        frame = self.codec.parse(data, strict=True)
        if frame is None:
            # Retry leniently so a checksum-algorithm mismatch surfaces as
            # "bad checksum" rather than "not my protocol".
            frame = self.codec.parse(data, strict=False)
        return frame

    def command_name(self, cmd: int | None) -> str:
        if cmd is None:
            return "?"
        return self.commands.get(cmd, f"unknown-0x{cmd:02X}")

    def describe(self, frame: Frame) -> str:
        bits = []
        if frame.cmd is not None:
            bits.append(f"CMD=0x{frame.cmd:02X} ({self.command_name(frame.cmd)})")
        for name in ("direction", "length"):
            if name in frame.values and isinstance(frame.values[name], int):
                bits.append(f"{name}={frame.values[name]}")
        bits.append(f"payload={len(frame.payload)}B")
        if not frame.checksum_ok:
            bits.append("CHECKSUM-BAD")
        return "  ".join(bits)

    # -- respond ------------------------------------------------------------

    def responses_for(
        self, frame: Frame, blobs: dict[str, bytes] | None = None
    ) -> list[tuple[float, bytes, str]]:
        """Return (delay, frame_bytes, label) for every rule matching `frame`."""
        ctx = TemplateContext(
            request=frame,
            variables=self.variables,
            blobs=blobs or {},
            field_widths=self.codec.field_widths,
        )
        out: list[tuple[float, bytes, str]] = []
        for rule in self.rules:
            if not rule.matches(frame):
                continue
            for i, spec in enumerate(rule.responses):
                label = spec.label or f"{rule.name}[{i}]"
                if spec.raw is not None:
                    out.append((spec.delay, render_template(spec.raw, ctx), label))
                    continue
                values: dict[str, Any] = {}
                for key, raw in spec.fields.items():
                    field_spec = self.codec._by_name.get(key)
                    if field_spec is not None and field_spec.type == "bytes":
                        values[key] = render_template(raw, ctx)
                    elif isinstance(raw, str) and "{" in raw:
                        values[key] = int.from_bytes(render_template(raw, ctx), "big")
                    else:
                        values[key] = as_int(raw) if raw is not None else None
                out.append((spec.delay, self.codec.build(values), label))
        return out
