"""Protocol engine tests.

The important one is `test_real_captured_frame`: a 237-byte frame whose
structure came off real hardware must parse, verify its checksum, and rebuild
byte-identically from the declarative field list alone. If the codec can do
that, it can handle the framed protocols most BLE devices actually use.
(Identifying bytes in that fixture are synthetic - see the constant.)
"""

import pytest

from brat.core.protocol import (
    FrameCodec,
    ProtocolEngine,
    ProtocolError,
    TemplateContext,
    parse_hex,
    render_template,
)
from brat.core.checksum import Checksum

# A5 00 <dir> D0 E0 <cmd> <len:u16be> <payload> <crc16be> 5A
FRAME_CONFIG = {
    "name": "test-a5",
    "frame": {
        "fields": [
            {"name": "start", "type": "const", "value": "A5"},
            {"name": "reserved", "type": "const", "value": "00"},
            {"name": "direction", "type": "u8", "default": 0},
            {"name": "dst", "type": "const", "value": "D0"},
            {"name": "src", "type": "const", "value": "E0"},
            {"name": "cmd", "type": "u8"},
            {"name": "length", "type": "u16be", "length_of": "payload"},
            {"name": "payload", "type": "bytes", "length_from": "length"},
            {"name": "crc", "type": "crc"},
            {"name": "end", "type": "const", "value": "5A"},
        ]
    },
    "crc": {
        "algorithm": "crc16-ibm",
        "byte_order": "big",
        "covers": [
            "start", "reserved", "direction", "dst", "src", "cmd", "length", "payload",
        ],
    },
    "commands": {"0x92": "DATA_SYNC", "0xA3": "AUTH"},
}

# Structure taken verbatim from a frame recorded off real hardware: 237 bytes,
# 16-bit length field (0x00E2 = 226), CRC-16/MODBUS big-endian. The two
# identifying fields in the payload - an account identifier and a bind token
# derived from the device address - have been replaced with synthetic values
# and the checksum recomputed, so no captured data ships in this repo.
REAL_FRAME = bytes.fromhex(
    "a50001d0e09200e24944454e54303031deadbeefcafe00010107014700004e05"
    "69c1b0ee69c1b4b072b0417ba4673f35e0325a85ebdf976579b68db4230dbe3e"
    "321c88dfe8931f181b4ca9d517a3fe53451390ba077402a14faf90e9589451f2"
    "49dae68215d9146f5cd000484d5a179b2e3c5a38d1c728e177a5a9b74672bb52"
    "a4a6d13b47071919692fccef787dfe753604a09c8f6930c7d7e88c5e94fc03cd"
    "d449c5ffc0fdaa9a8c6ae4a8bd15bee1f28d62aa8c733bdecd6bbd222dc42093"
    "94e5cb8992fdebe4bf9078bccf8ef6fd6dc58ae073217d56ffcf52ff06e30e90"
    "638f50a56bfce38e0001026b5a"
)


@pytest.fixture
def engine():
    return ProtocolEngine(FRAME_CONFIG)


# ---------------------------------------------------------------------------
# Hex parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("A5 00 5A", b"\xa5\x00\x5a"),
        ("a5005a", b"\xa5\x00\x5a"),
        ("A5:00:5A", b"\xa5\x00\x5a"),
        ("A5-00-5A", b"\xa5\x00\x5a"),
        ("0xA5", b"\xa5"),
        ("", b""),
        (None, b""),
    ],
)
def test_parse_hex(text, expected):
    assert parse_hex(text) == expected


def test_parse_hex_rejects_odd_length():
    with pytest.raises(ProtocolError, match="odd length"):
        parse_hex("A5C")


# ---------------------------------------------------------------------------
# Frame codec
# ---------------------------------------------------------------------------


def test_real_captured_frame(engine):
    """Parse, verify, and rebuild a frame recorded from a live device."""
    frame = engine.decode(REAL_FRAME)

    assert frame is not None
    assert frame.checksum_ok
    assert frame.cmd == 0x92
    assert frame.get("direction") == 1
    assert frame.get("length") == 226
    assert len(frame.payload) == 226

    rebuilt = engine.codec.build(
        {"direction": frame.get("direction"), "cmd": frame.cmd, "payload": frame.payload}
    )
    assert rebuilt == REAL_FRAME


def test_roundtrip_arbitrary_payloads(engine):
    for size in (0, 1, 8, 255, 256, 901):
        payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        built = engine.codec.build({"direction": 2, "cmd": 0x93, "payload": payload})
        frame = engine.decode(built)
        assert frame is not None and frame.checksum_ok
        assert frame.payload == payload
        assert frame.cmd == 0x93


def test_length_field_is_16_bit(engine):
    """A payload over 255 bytes must use both length bytes."""
    built = engine.codec.build({"direction": 1, "cmd": 0x93, "payload": b"\x00" * 901})
    assert built[6:8] == (901).to_bytes(2, "big")
    assert engine.decode(built).get("length") == 901


def test_rejects_foreign_frame(engine):
    assert engine.decode(bytes.fromhex("deadbeef00112233")) is None


def test_rejects_truncated_frame(engine):
    assert engine.decode(REAL_FRAME[:10]) is None


def test_corrupt_checksum_is_flagged_not_dropped(engine):
    """A bad checksum must surface as a decoded frame marked invalid.

    Silently returning None would make a checksum-algorithm mismatch in a
    profile indistinguishable from "this device speaks something else".
    """
    corrupt = bytearray(REAL_FRAME)
    corrupt[-2] ^= 0xFF
    frame = engine.decode(bytes(corrupt))
    assert frame is not None
    assert frame.checksum_ok is False


def test_const_mismatch_rejects(engine):
    wrong = bytearray(REAL_FRAME)
    wrong[0] = 0xA6
    assert engine.decode(bytes(wrong)) is None


def test_fixed_length_bytes_field_pads():
    codec = FrameCodec(
        [
            {"name": "hdr", "type": "const", "value": "01"},
            {"name": "body", "type": "bytes", "length": 4},
        ],
        Checksum({"algorithm": "none"}),
    )
    assert codec.build({"body": b"\xaa"}) == b"\x01\xaa\x00\x00\x00"


def test_oversize_value_rejected():
    codec = FrameCodec(
        [{"name": "body", "type": "bytes", "length": 2}],
        Checksum({"algorithm": "none"}),
    )
    with pytest.raises(ProtocolError, match="fixed length"):
        codec.build({"body": b"\x01\x02\x03"})


def test_bad_field_reference_rejected():
    with pytest.raises(ProtocolError, match="unknown field"):
        FrameCodec(
            [{"name": "p", "type": "bytes", "length_from": "nonexistent"}],
            Checksum({"algorithm": "none"}),
        )


def test_unknown_field_type_rejected():
    with pytest.raises(ProtocolError, match="unknown field type"):
        FrameCodec(
            [{"name": "x", "type": "float64"}], Checksum({"algorithm": "none"})
        )


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(engine):
    payload = b"IDENT001" + bytes.fromhex("69C1B4B0") + bytes.fromhex("014A")
    frame = engine.decode(engine.codec.build({"cmd": 0xA3, "payload": payload}))
    return TemplateContext(
        request=frame,
        variables={"token": bytes.fromhex("DEADBEEF")},
        blobs={"data": b"\x01\x02\x03"},
    )


def test_template_literal_and_slices(ctx):
    assert render_template("{req.payload[0:8]}01", ctx) == b"IDENT001\x01"
    assert render_template("{req.payload}", ctx) == ctx.request.payload
    assert render_template("FF{req.payload[8:12]}FF", ctx) == bytes.fromhex(
        "FF69C1B4B0FF"
    )


def test_template_variables_and_blobs(ctx):
    assert render_template("{var.token}", ctx) == b"\xde\xad\xbe\xef"
    assert render_template("{blob.data}", ctx) == b"\x01\x02\x03"


def test_template_generators(ctx):
    assert len(render_template("{ts:u32be}", ctx)) == 4
    assert len(render_template("{ts:u16le}", ctx)) == 2
    assert len(render_template("{rand:16}", ctx)) == 16
    assert render_template("{zero:3}", ctx) == b"\x00\x00\x00"
    # Random must actually vary.
    assert render_template("{rand:32}", ctx) != render_template("{rand:32}", ctx)


def test_template_whitespace_is_ignored(ctx):
    assert render_template("0E 25 01 00", ctx) == bytes.fromhex("0E250100")


def test_template_unknown_token_rejected(ctx):
    with pytest.raises(ProtocolError, match="unknown template token"):
        render_template("{nope.thing}", ctx)


def test_template_undefined_variable_rejected(ctx):
    with pytest.raises(ProtocolError, match="undefined profile variable"):
        render_template("{var.missing}", ctx)


def test_template_missing_blob_gives_actionable_error(ctx):
    with pytest.raises(ProtocolError, match="--payload"):
        render_template("{blob.absent}", ctx)


# ---------------------------------------------------------------------------
# Emulation
# ---------------------------------------------------------------------------


def test_emulation_rule_builds_valid_response():
    config = dict(FRAME_CONFIG)
    config["emulation"] = {
        "variables": {"token": "DEADBEEFCAFE0001"},
        "rules": [
            {
                "name": "auth",
                "on_cmd": "0xA3",
                "respond": [
                    {
                        "delay": 0.1,
                        "direction": 1,
                        "cmd": "0xA3",
                        "payload": "{req.payload[0:8]}01",
                        "label": "ack",
                    },
                    {
                        "delay": 0.5,
                        "direction": 2,
                        "cmd": "0xA4",
                        "payload": "{req.payload[0:8]}{var.token}{ts:u32be}",
                    },
                ],
            }
        ],
    }
    engine = ProtocolEngine(config)
    request = engine.decode(
        engine.codec.build({"cmd": 0xA3, "payload": b"IDENT001" + b"\x00" * 6})
    )

    responses = engine.responses_for(request)
    assert len(responses) == 2

    delay, data, label = responses[0]
    assert delay == 0.1
    assert label == "ack"
    ack = engine.decode(data)
    assert ack is not None and ack.checksum_ok
    assert ack.cmd == 0xA3
    assert ack.payload == b"IDENT001\x01"

    _delay, data2, _label = responses[1]
    confirm = engine.decode(data2)
    assert confirm.checksum_ok
    assert confirm.payload[:8] == b"IDENT001"
    assert confirm.payload[8:16] == bytes.fromhex("DEADBEEFCAFE0001")
    assert len(confirm.payload) == 20


def test_rule_does_not_fire_on_other_commands():
    config = dict(FRAME_CONFIG)
    config["emulation"] = {
        "rules": [{"on_cmd": "0xA3", "respond": [{"cmd": "0xA3", "payload": "01"}]}]
    }
    engine = ProtocolEngine(config)
    other = engine.decode(engine.codec.build({"cmd": 0x91, "payload": b""}))
    assert engine.responses_for(other) == []


def test_on_any_rule_fires_for_every_frame():
    config = dict(FRAME_CONFIG)
    config["emulation"] = {
        "rules": [{"on_any": True, "respond": [{"raw": "A5005A"}]}]
    }
    engine = ProtocolEngine(config)
    frame = engine.decode(engine.codec.build({"cmd": 0x77, "payload": b""}))
    responses = engine.responses_for(frame)
    assert len(responses) == 1
    assert responses[0][1] == bytes.fromhex("A5005A")


def test_command_names(engine):
    assert engine.command_name(0x92) == "DATA_SYNC"
    assert engine.command_name(0x11) == "unknown-0x11"
    assert engine.command_name(None) == "?"


def test_missing_frame_definition_rejected():
    with pytest.raises(ProtocolError, match="frame.fields is required"):
        ProtocolEngine({"name": "broken"})


# ---------------------------------------------------------------------------
# as_int - hex-always parsing
# ---------------------------------------------------------------------------


def test_as_int_bare_string_is_hex_not_decimal():
    """'93' must mean 0x93 (147), matching parse_hex's hex-always convention.

    Previously fell back to decimal, so a profile author or `--on-cmd 93`
    copying a byte value straight off a sniffer capture silently got the
    wrong command (93 decimal == 0x5D).
    """
    from brat.core.protocol import as_int

    assert as_int("93") == 0x93
    assert as_int("0x93") == 0x93
    assert as_int("A3") == 0xA3
    assert as_int(0x93) == 0x93  # a real int passes through unchanged


def test_as_int_rejects_non_hex_string_with_protocol_error():
    from brat.core.protocol import as_int

    with pytest.raises(ProtocolError, match="hex integer"):
        as_int("not-a-number")


def test_as_int_rejects_bool():
    """bool is an int subclass in Python - must not silently become 0/1."""
    from brat.core.protocol import as_int

    with pytest.raises(ProtocolError):
        as_int(True)


# ---------------------------------------------------------------------------
# Renamed cmd/payload fields (protocol.roles)
# ---------------------------------------------------------------------------


def test_frame_cmd_and_payload_use_default_names(engine):
    frame = engine.decode(engine.codec.build({"cmd": 0x92, "payload": b"\x01\x02"}))
    assert frame.cmd == 0x92
    assert frame.payload == b"\x01\x02"


def test_renamed_fields_are_readable_via_cmd_and_payload_properties():
    """A profile can name its command/payload fields anything; roles: maps them.

    Before this, Frame.cmd/.payload only ever read fields literally named
    "cmd"/"payload" - a profile using "opcode"/"data" decoded real frames but
    .cmd and .payload silently returned None/b"" with no error, so every
    on_cmd rule failed to match.
    """
    config = {
        "name": "renamed-fields",
        "roles": {"command": "opcode", "payload": "data"},
        "frame": {
            "fields": [
                {"name": "start", "type": "const", "value": "A5"},
                {"name": "opcode", "type": "u8"},
                {"name": "length", "type": "u8", "length_of": "data"},
                {"name": "data", "type": "bytes", "length_from": "length"},
                {"name": "end", "type": "const", "value": "5A"},
            ]
        },
        "crc": {"algorithm": "none"},
    }
    engine = ProtocolEngine(config)
    built = engine.codec.build({"opcode": 0x42, "data": b"\xaa\xbb"})
    frame = engine.decode(built)

    assert frame.cmd == 0x42
    assert frame.payload == b"\xaa\xbb"


def test_renamed_command_field_makes_on_cmd_rules_match():
    config = {
        "name": "renamed-rules",
        "roles": {"command": "opcode", "payload": "data"},
        "frame": {
            "fields": [
                {"name": "start", "type": "const", "value": "A5"},
                {"name": "opcode", "type": "u8"},
                {"name": "length", "type": "u8", "length_of": "data"},
                {"name": "data", "type": "bytes", "length_from": "length"},
                {"name": "end", "type": "const", "value": "5A"},
            ]
        },
        "crc": {"algorithm": "none"},
        "emulation": {
            "rules": [{"on_cmd": "0x42", "respond": [{"opcode": "0x43", "data": "01"}]}]
        },
    }
    engine = ProtocolEngine(config)
    request = engine.decode(engine.codec.build({"opcode": 0x42, "data": b""}))
    responses = engine.responses_for(request)

    assert len(responses) == 1
    reply = engine.decode(responses[0][1])
    assert reply.cmd == 0x43
    assert reply.payload == b"\x01"


def test_roles_pointing_at_unknown_field_is_rejected_at_construction():
    """A typo'd roles: mapping must fail loudly, not decode silently wrong."""
    config = {
        "name": "bad-roles",
        "roles": {"command": "nonexistent_field"},
        "frame": {
            "fields": [
                {"name": "start", "type": "const", "value": "A5"},
                {"name": "cmd", "type": "u8"},
            ]
        },
        "crc": {"algorithm": "none"},
    }
    with pytest.raises(ProtocolError, match="nonexistent_field"):
        ProtocolEngine(config)


# ---------------------------------------------------------------------------
# {req.NAME} emits the field's declared width
# ---------------------------------------------------------------------------


def test_req_name_token_emits_declared_width_not_minimal_width(engine):
    """A u16be field currently holding 5 must echo back as 2 bytes, not 1.

    Regression: {req.NAME} used to emit `(bit_length + 7) // 8` bytes, so a
    small value in a wide field silently rendered too short - any raw
    template echoing a header field back (e.g. {req.length}) produced a
    truncated frame.
    """
    request = engine.decode(engine.codec.build({"cmd": 0x92, "payload": b"\x01\x02\x03\x04\x05"}))
    assert request.get("length") == 5  # small value in a u16be (2-byte) field

    rendered = render_template("{req.length}", TemplateContext(
        request=request, field_widths=engine.codec.field_widths
    ))
    assert len(rendered) == 2
    assert rendered == (5).to_bytes(2, "big")


def test_req_name_token_falls_back_to_minimal_width_without_field_widths():
    """Without field_widths supplied (e.g. a hand-built context), behaviour is
    unchanged from before - minimal width - so this is purely additive."""
    config = dict(FRAME_CONFIG)
    engine = ProtocolEngine(config)
    request = engine.decode(engine.codec.build({"cmd": 0x92, "payload": b"\x01"}))
    rendered = render_template("{req.length}", TemplateContext(request=request))
    assert rendered == b"\x01"


# ---------------------------------------------------------------------------
# Cross-frame session state
#
# A real handshake routinely needs a value from an *earlier* frame - an
# identifier sent during authentication that has to reappear in a later data
# frame. Before `capture:` the only expressible responses were ones derivable
# from the frame that triggered them.
# ---------------------------------------------------------------------------


def _emulation(rules, variables=None):
    cfg = dict(FRAME_CONFIG)
    cfg["emulation"] = {"variables": variables or {}, "rules": rules}
    return ProtocolEngine(cfg)


def test_capture_makes_a_value_available_to_a_later_rule():
    eng = _emulation(
        [
            {"name": "auth", "on_cmd": 0xA3, "capture": {"uid": "{req.payload[0:8]}"}},
            {
                "name": "sync",
                "on_cmd": 0x92,
                "respond": [{"cmd": 0x92, "payload": "{sess.uid}FF"}],
            },
        ]
    )
    eng.responses_for(eng.decode(eng.codec.build({"cmd": 0xA3, "payload": b"IDENT001x"})))
    assert eng.session["uid"] == b"IDENT001"

    _, data, _ = eng.responses_for(eng.decode(eng.codec.build({"cmd": 0x92, "payload": b""})))[0]
    assert b"IDENT001\xff" in data


def test_a_rule_can_use_what_it_just_captured():
    eng = _emulation(
        [
            {
                "name": "auth",
                "on_cmd": 0xA3,
                "capture": {"uid": "{req.payload[0:8]}"},
                "respond": [{"cmd": 0xA3, "payload": "{sess.uid}01"}],
            }
        ]
    )
    _, data, _ = eng.responses_for(
        eng.decode(eng.codec.build({"cmd": 0xA3, "payload": b"IDENT001"}))
    )[0]
    assert b"IDENT001\x01" in data


def test_reading_an_uncaptured_value_names_the_capture_clause():
    eng = _emulation(
        [{"name": "sync", "on_cmd": 0x92, "respond": [{"cmd": 0x92, "payload": "{sess.uid}"}]}]
    )
    with pytest.raises(ProtocolError, match="capture:"):
        eng.responses_for(eng.decode(eng.codec.build({"cmd": 0x92, "payload": b""})))


def test_reset_session_clears_captures_between_connections():
    """Otherwise the second client to connect is answered with the first
    client's identifiers.
    """
    eng = _emulation(
        [{"name": "auth", "on_cmd": 0xA3, "capture": {"uid": "{req.payload[0:8]}"}}]
    )
    eng.responses_for(eng.decode(eng.codec.build({"cmd": 0xA3, "payload": b"IDENT001"})))
    assert eng.session
    eng.reset_session()
    assert eng.session == {}


def test_once_rule_fires_only_once_per_connection():
    """Clients that time out restart the handshake; a rule that pushes
    unsolicited data must not push it twice.
    """
    eng = _emulation(
        [{"name": "push", "on_cmd": 0x90, "once": True, "respond": [{"cmd": 0x92}]}]
    )
    frame = eng.decode(eng.codec.build({"cmd": 0x90, "payload": b""}))
    assert len(eng.responses_for(frame)) == 1
    assert eng.responses_for(frame) == []
    eng.reset_session()
    assert len(eng.responses_for(frame)) == 1


# ---------------------------------------------------------------------------
# Slicing beyond req.*
# ---------------------------------------------------------------------------


def test_blob_and_var_tokens_can_be_sliced():
    """A captured replay blob nearly always needs fields patched around, so
    using one at all means slicing it.
    """
    eng = _emulation(
        [{"name": "r", "on_cmd": 0x92, "respond": [{"cmd": 0x92, "payload": "{blob.b[1:4]}{var.v[0:2]}"}]}],
        variables={"v": "DEADBEEF"},
    )
    _, data, _ = eng.responses_for(
        eng.decode(eng.codec.build({"cmd": 0x92, "payload": b""})),
        blobs={"b": bytes.fromhex("00112233445566")},
    )[0]
    assert b"\x11\x22\x33\xde\xad" in data


def test_unsliced_var_and_blob_tokens_still_work():
    eng = _emulation(
        [{"name": "r", "on_cmd": 0x92, "respond": [{"cmd": 0x92, "payload": "{var.v}{blob.b}"}]}],
        variables={"v": "AABB"},
    )
    _, data, _ = eng.responses_for(
        eng.decode(eng.codec.build({"cmd": 0x92, "payload": b""})),
        blobs={"b": b"\xcc"},
    )[0]
    assert b"\xaa\xbb\xcc" in data


def test_out_of_range_slice_is_an_error_not_a_short_field():
    """Python would clamp silently, building a malformed frame that looks like
    the device answered with nonsense.
    """
    eng = _emulation(
        [{"name": "r", "on_cmd": 0xA3, "respond": [{"cmd": 0xA3, "payload": "{req.payload[0:99]}"}]}]
    )
    with pytest.raises(ProtocolError, match="do not exist"):
        eng.responses_for(eng.decode(eng.codec.build({"cmd": 0xA3, "payload": b"short"})))
