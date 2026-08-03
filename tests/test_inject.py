"""`brat inject` rule construction and collision handling.

The interesting behaviour is what happens when the injection trigger collides
with a command the profile already answers, which is the common case: the
command worth injecting over is usually one the device replies to.
"""

import struct

import pytest

from brat.commands.inject import install_injection_rule
from brat.core.profile import load_profile
from brat.core.protocol import EmulationRule, ProtocolEngine, ResponseSpec


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _frame(cmd: int, payload: bytes = b"", direction: int = 0) -> bytes:
    body = bytes([0x7E, 0x00, direction, 0x10, 0x20, cmd]) + struct.pack(">H", len(payload)) + payload
    crc = _crc16(body)
    return body + bytes([crc >> 8, crc & 0xFF, 0xEF])


@pytest.fixture
def engine():
    profile = load_profile("glucosense_open")
    if profile.protocol_config is None:
        pytest.skip("glucosense_open has no protocol block")
    return ProtocolEngine(profile.protocol_config)


def _injection_rule(on_cmd: int, payload: str) -> EmulationRule:
    return EmulationRule(
        name="injection",
        on_cmd=on_cmd,
        responses=[
            ResponseSpec(
                delay=0.2,
                fields={"cmd": on_cmd, "payload": payload, "direction": 1},
                label="injected",
            )
        ],
    )


def test_injection_replaces_a_colliding_profile_rule(engine):
    """Regression: one request must not produce two conflicting answers.

    `responses_for` collects responses from every matching rule. Appending the
    injection rule without removing the profile's rule for the same command
    answered a single request twice - the profile's reply first, the injected
    one milliseconds later. A client rendering the first answer showed exactly
    the value the operator was replacing, so the injection looked inert while
    both frames had in fact gone out.
    """
    rule = _injection_rule(0x30, "0028010101000001")
    suppressed = install_injection_rule(engine, rule)

    assert "status" in suppressed

    responses = engine.responses_for(engine.decode(_frame(0x30)))
    assert len(responses) == 1, "a single request must yield a single reply"

    _delay, data, label = responses[0]
    assert label == "injected"
    payload = data[8:-3]
    assert int.from_bytes(payload[0:2], "big") == 0x0028  # the injected value


def test_injection_leaves_other_commands_alone(engine):
    """Suppression must be scoped to the colliding command only."""
    install_injection_rule(engine, _injection_rule(0x30, "0028010101000001"))

    ping = engine.responses_for(engine.decode(_frame(0x01)))
    assert [label for _d, _b, label in ping] == ["ping-ack"]

    auth = engine.responses_for(engine.decode(_frame(0x10, b"DEMOUSER")))
    assert any(label == "auth-ack" for _d, _b, label in auth)


def test_injection_on_an_unanswered_command_suppresses_nothing(engine):
    """Injecting over a command the profile ignores must not drop any rule."""
    before = len(engine.rules)
    suppressed = install_injection_rule(engine, _injection_rule(0x77, "AABB"))

    assert suppressed == []
    assert len(engine.rules) == before + 1
