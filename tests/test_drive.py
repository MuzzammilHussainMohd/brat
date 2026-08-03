"""`brat drive` - sequence parsing and state-change inference.

The interesting logic is `find_state_changes`: it is what turns "the device
replied" into "the device changed because of what we sent", and it has to be
conservative about that claim. A false positive here is a CRITICAL finding
asserting an attacker can change state when all that happened was a sensor
reading drifting on its own.
"""

import argparse

import pytest

from brat.commands.drive import Step, diff_bytes, find_state_changes, parse_steps
from brat.core.profile import load_profile
from brat.core.protocol import ProtocolEngine


@pytest.fixture
def engine():
    profile = load_profile("glucosense_open")
    if profile.protocol_config is None:
        pytest.skip("glucosense_open has no protocol block")
    return ProtocolEngine(profile.protocol_config)


def _args(**kwargs):
    defaults = {"cmd": None, "payload": None, "send": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _step(cmd: int, reply: bytes | None, payload: bytes = b"") -> Step:
    """A step that was sent and (optionally) answered with `reply` as payload."""
    step = Step(cmd=cmd, payload=payload, label=f"{cmd:02x}")
    if reply is not None:
        frame = type("F", (), {"payload": reply, "cmd": cmd, "checksum_ok": True})()
        step.replies = [b"\x00"]
        step.decoded = [frame]
    return step


# -- sequence parsing -------------------------------------------------------


def test_send_is_parsed_as_hex_in_order():
    steps = parse_steps(_args(send=["30", "20:00", "30"]))

    assert [s.cmd for s in steps] == [0x30, 0x20, 0x30]
    assert [s.payload for s in steps] == [b"", b"\x00", b""]


def test_cmd_and_payload_build_a_single_step():
    steps = parse_steps(_args(cmd="0x20", payload="00"))

    assert len(steps) == 1
    assert steps[0].cmd == 0x20
    assert steps[0].payload == b"\x00"


def test_bare_numeric_command_is_hex_not_decimal():
    """Consistency with the rest of the protocol module.

    `--send 20` is the byte 0x20 read off a sniffer, not decimal 20 (0x14).
    Reading it as decimal would send a different command with no warning.
    """
    steps = parse_steps(_args(send=["20"]))
    assert steps[0].cmd == 0x20


def test_payload_without_cmd_is_rejected():
    with pytest.raises(ValueError, match="needs --cmd"):
        parse_steps(_args(payload="00"))


def test_no_commands_at_all_is_rejected():
    with pytest.raises(ValueError, match="nothing to send"):
        parse_steps(_args())


# -- state-change inference -------------------------------------------------


def test_state_change_is_reported_when_a_readback_differs(engine):
    """The demo case: STATUS, ALARM_SET, STATUS with different STATUS replies."""
    steps = [
        _step(0x30, b"\x00\x28\x01\x01"),   # 40 mg/dL, alarm active
        _step(0x20, b"\x00\x01", b"\x00"),  # ALARM_SET 0 - silence
        _step(0x30, b"\x00\x28\x00\x01"),   # 40 mg/dL, alarm now clear
    ]

    changes = find_state_changes(steps, engine)

    assert len(changes) == 1
    change = changes[0]
    assert change["probe_cmd"] == "0x30"
    assert change["before"] == "00280101"
    assert change["after"] == "00280001"
    assert [c["cmd"] for c in change["caused_by"]] == ["0x20"]
    # Only the alarm flag moved; the reading behind it did not. That contrast is
    # the finding - a silenced alarm over an unchanged dangerous value.
    assert change["changed_bytes"] == [{"offset": 2, "before": "01", "after": "00"}]


# -- byte diff --------------------------------------------------------------


def test_diff_names_only_the_offsets_that_moved():
    assert diff_bytes(bytes.fromhex("00280101"), bytes.fromhex("00280001")) == [
        {"offset": 2, "before": "01", "after": "00"}
    ]


def test_diff_of_identical_payloads_is_empty():
    assert diff_bytes(b"\x01\x02", b"\x01\x02") == []


def test_diff_handles_a_length_change():
    """A reply that grew or shrank still has to produce a readable diff."""
    diff = diff_bytes(b"\x01", b"\x01\x02")

    assert diff == [{"offset": 1, "before": None, "after": "02"}]


def test_no_intervening_command_is_not_a_state_change(engine):
    """Two consecutive identical reads that differ prove nothing.

    A glucose value drifts on its own. Attributing that drift to a command
    nobody sent would be a fabricated CRITICAL finding.
    """
    steps = [
        _step(0x30, b"\x00\x28\x01\x01"),
        _step(0x30, b"\x00\x27\x01\x01"),  # drifted by itself
    ]

    assert find_state_changes(steps, engine) == []


def test_identical_replies_are_not_a_state_change(engine):
    steps = [
        _step(0x30, b"\x00\x28\x01\x01"),
        _step(0x20, b"\x00\x01", b"\x00"),
        _step(0x30, b"\x00\x28\x01\x01"),  # unchanged - the command did nothing
    ]

    assert find_state_changes(steps, engine) == []


def test_unanswered_probe_cannot_witness_a_change(engine):
    """A missing before or after is not evidence of anything."""
    steps = [
        _step(0x30, None),                  # no reply
        _step(0x20, b"\x00\x01", b"\x00"),
        _step(0x30, b"\x00\x28\x00\x01"),
    ]

    assert find_state_changes(steps, engine) == []


def test_only_one_witness_is_reported_per_command(engine):
    """Repeating the probe many times must not multiply the same finding."""
    steps = [
        _step(0x30, b"\x00\x28\x01\x01"),
        _step(0x20, b"\x00\x01", b"\x00"),
        _step(0x30, b"\x00\x28\x00\x01"),
        _step(0x20, b"\x00\x01", b"\x01"),
        _step(0x30, b"\x00\x28\x01\x01"),
    ]

    assert len(find_state_changes(steps, engine)) == 1


def test_a_single_probe_reading_cannot_show_a_change(engine):
    steps = [_step(0x20, b"\x00\x01", b"\x00"), _step(0x30, b"\x00\x28\x00\x01")]

    assert find_state_changes(steps, engine) == []
