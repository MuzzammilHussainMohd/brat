"""Checksum tests, anchored to published check values.

Every CRC preset is verified against the standard "123456789" check value from
the CRC catalogue, so a preset that is subtly wrong fails here rather than in
the field against a device that rejects every frame.
"""

import pytest

from brat.core.checksum import PRESETS, Checksum, crc

CHECK_INPUT = b"123456789"

# Published check values (CRC RevEng catalogue).
CHECK_VALUES = {
    "crc16-modbus": 0x4B37,
    "crc16-ibm": 0x4B37,
    "crc16-arc": 0xBB3D,
    "crc16-ccitt-false": 0x29B1,
    "crc16-xmodem": 0x31C3,
    "crc16-kermit": 0x2189,
    "crc16-usb": 0xB4C8,
    "crc8": 0xF4,
    "crc8-maxim": 0xA1,
    "crc32": 0xCBF43926,
}


@pytest.mark.parametrize("name,expected", sorted(CHECK_VALUES.items()))
def test_preset_check_value(name, expected):
    assert crc(CHECK_INPUT, PRESETS[name]) == expected


def test_modbus_matches_reflected_loop():
    """The preset must equal the poly-0xA001 loop vendors ship in their SDKs."""

    def vendor_loop(data: bytes) -> int:
        value = 0xFFFF
        for byte in data:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ 0xA001 if value & 1 else value >> 1
        return value & 0xFFFF

    for payload in (b"", b"\x00", b"A5\x00", bytes(range(256))):
        assert crc(payload, PRESETS["crc16-modbus"]) == vendor_loop(payload)


def test_simple_algorithms():
    assert Checksum({"algorithm": "sum8"}).compute(b"\x01\x02\x03") == 6
    assert Checksum({"algorithm": "xor8"}).compute(b"\x0f\xf0") == 0xFF
    assert Checksum({"algorithm": "sum16"}).compute(b"\xff\xff") == 0x1FE
    assert Checksum({"algorithm": "none"}).compute(b"anything") == 0


def test_byte_order_and_width():
    big = Checksum({"algorithm": "crc16-ibm", "byte_order": "big"})
    little = Checksum({"algorithm": "crc16-ibm", "byte_order": "little"})
    assert big.nbytes == 2
    assert big.pack(0x1234) == b"\x12\x34"
    assert little.pack(0x1234) == b"\x34\x12"
    assert big.unpack(b"\x12\x34") == 0x1234


def test_parameter_override():
    """A profile may override any CRC parameter without a named preset."""
    custom = Checksum({"algorithm": "crc16-ibm", "init": 0x0000})
    assert custom.compute(CHECK_INPUT) == CHECK_VALUES["crc16-arc"]


def test_verify_roundtrip():
    check = Checksum({"algorithm": "crc16-ibm", "byte_order": "big"})
    data = b"hello world"
    assert check.verify(data, check.pack(check.compute(data)))
    assert not check.verify(data, b"\x00\x00")


def test_unknown_algorithm_rejected():
    with pytest.raises(ValueError, match="unknown checksum algorithm"):
        Checksum({"algorithm": "crc16-invented"})
