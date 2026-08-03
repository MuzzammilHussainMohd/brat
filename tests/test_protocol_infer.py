"""Frame-layout inference.

The load-bearing test is `test_recovers_the_example_layout_exactly`: build frames
with a known-good codec, throw the codec away, and check that inference gets
the same structure back. If it can rediscover a layout somebody hand-wrote from
a real capture, it is doing the job.

Everything else here is about not overclaiming. Inference that cannot say "I
don't know" is worse than none, because a plausible wrong answer costs more to
discover than no answer.
"""

import json

import pytest

from brat.commands.protocol import load_frames
from brat.core.infer import infer, to_protocol_config
from brat.core.profile import load_profile
from brat.core.protocol import ProtocolEngine


@pytest.fixture
def engine(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    return load_profile("example_nus_device").protocol


@pytest.fixture
def frames(engine):
    """A plausible session: several commands, several payload lengths."""
    return [
        engine.codec.build({"cmd": 0xA3, "payload": b"IDENT001" + bytes(6)}),
        engine.codec.build({"cmd": 0x90, "payload": bytes(27)}),
        engine.codec.build({"cmd": 0x91, "payload": b"\x01"}),
        engine.codec.build({"cmd": 0x92, "payload": bytes(60)}),
        engine.codec.build({"cmd": 0xA8, "payload": b""}),
        engine.codec.build({"cmd": 0x93, "direction": 1, "payload": bytes(12)}),
    ]


def test_recovers_the_example_layout_exactly(frames, engine):
    result = infer(frames)

    assert result.prefix == b"\xa5\x00"
    assert result.suffix == b"\x5a"
    assert (result.length_offset, result.length_type) == (6, "u16be")
    assert result.length_overhead == 11
    assert result.cmd_offset == 5
    assert result.commands == [0x90, 0x91, 0x92, 0x93, 0xA3, 0xA8]
    assert result.notes == []

    algorithm, byte_order, cover_start, _ = result.crc
    assert algorithm in ("crc16-modbus", "crc16-ibm")  # the same polynomial
    assert (byte_order, cover_start) == ("big", 0)


def test_inferred_field_types_match_the_hand_written_profile(frames, engine):
    """Names will differ - the operator renames them - but the shape must not."""
    inferred = to_protocol_config(infer(frames))["frame"]["fields"]
    real = load_profile("example_nus_device").protocol_config["frame"]["fields"]

    def shape(fields):
        return [(f["type"], f.get("value")) for f in fields]

    assert shape(inferred) == shape(real)


def test_the_inferred_block_decodes_the_frames_it_came_from(frames):
    """The self-check `brat protocol infer` performs before reporting."""
    engine = ProtocolEngine(to_protocol_config(infer(frames)))
    for raw in frames:
        frame = engine.decode(raw)
        assert frame is not None, f"failed to decode {raw.hex()}"
        assert frame.checksum_ok


def test_the_inferred_block_still_rejects_a_foreign_frame(frames):
    """Recovering the constants is what makes this possible - a layout of all
    free u8 fields would accept anything.
    """
    engine = ProtocolEngine(to_protocol_config(infer(frames)))
    assert engine.decode(bytes.fromhex("DEADBEEFCAFE0011223344")) is None


def test_a_constant_after_a_varying_byte_is_still_found(frames):
    """The dst/src pair sits behind the direction flag, so anything that stops
    at the longest common prefix types them as free u8 and loses the ability
    to reject a frame that is not this protocol.
    """
    header = infer(frames).header
    assert header[3] == ("const", [0xD0])
    assert header[4] == ("const", [0xE0])
    assert header[2][0] == "enum", "direction varies and must not become a const"


# ---------------------------------------------------------------------------
# Refusing to guess
# ---------------------------------------------------------------------------


def test_too_few_frames_is_said_out_loud(engine):
    two = [
        engine.codec.build({"cmd": 0xA3, "payload": b"AAAA"}),
        engine.codec.build({"cmd": 0x91, "payload": b"\x01"}),
    ]
    result = infer(two, min_frames=3)
    assert any("at least 3" in n for n in result.notes)


def test_uniform_lengths_cannot_yield_a_length_field(engine):
    """With every frame the same length, any constant byte "predicts" the
    length perfectly. Reporting one would be noise.
    """
    same = [engine.codec.build({"cmd": c, "payload": b"AAAA"}) for c in (0x90, 0x91, 0x92)]
    result = infer(same)

    assert result.length_offset is None
    assert any("same length" in n for n in result.notes)


def test_no_checksum_is_reported_rather_than_invented():
    frames = [b"\xa5" + bytes([c]) + b"payload" + b"\x5a" for c in (1, 2, 3)]
    result = infer(frames)
    assert result.crc is None
    assert any("no checksum preset" in n for n in result.notes)


def test_empty_input_does_not_raise():
    result = infer([])
    assert result.frame_count == 0
    assert result.notes


def test_equivalent_crc_presets_are_not_reported_as_ambiguous(frames):
    """crc16-ibm and crc16-modbus are the same polynomial under two names;
    listing both would suggest the evidence is weaker than it is.
    """
    result = infer(frames)
    assert len(result.crc_matches) == 1
    assert not any("configurations fit" in n for n in result.notes)


# ---------------------------------------------------------------------------
# Session log reading
# ---------------------------------------------------------------------------


def _log(tmp_path, entries):
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"entries": entries}))
    return str(path)


def test_load_frames_reads_only_what_the_client_wrote(tmp_path):
    path = _log(
        tmp_path,
        [
            {"direction": "rx", "hex": "a501"},
            {"direction": "tx", "hex": "a502"},
        ],
    )
    assert load_frames(path) == [bytes.fromhex("a501")]
    assert len(load_frames(path, include_tx=True)) == 2


def test_load_frames_accepts_a_whole_report_as_well_as_a_bare_session(tmp_path):
    """-o json writes the report; --session-log writes the session object."""
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"data": {}, "session": {"entries": [{"direction": "rx", "hex": "a5"}]}})
    )
    assert load_frames(str(path)) == [b"\xa5"]
