"""Checksum algorithms for framed protocols.

Custom BLE protocols overwhelmingly use one of a handful of CRCs, or a naive
sum/xor. Rather than make profile authors write Python, the profile names an
algorithm and BRAT computes it.

A generic bitwise CRC covers every CRC variant; the named presets are just
parameter sets for it. Slow relative to a table-driven implementation, and
irrelevant at BLE frame sizes.
"""

from __future__ import annotations

from dataclasses import dataclass


def _reflect(value: int, bits: int) -> int:
    out = 0
    for i in range(bits):
        if value & (1 << i):
            out |= 1 << (bits - 1 - i)
    return out


@dataclass(frozen=True)
class CrcParams:
    width: int
    poly: int
    init: int
    reflect_in: bool
    reflect_out: bool
    xor_out: int

    @property
    def nbytes(self) -> int:
        return self.width // 8


# Named presets. `poly` is always the normal (non-reflected) polynomial;
# reflection is expressed by the reflect_in/reflect_out flags.
PRESETS: dict[str, CrcParams] = {
    # CRC-16/MODBUS. Equivalent to the widespread "poly 0xA001, init 0xFFFF,
    # LSB-first" loop seen in vendor SDKs. Also shipped as "CRC-16/IBM".
    "crc16-modbus": CrcParams(16, 0x8005, 0xFFFF, True, True, 0x0000),
    "crc16-ibm": CrcParams(16, 0x8005, 0xFFFF, True, True, 0x0000),
    "crc16-arc": CrcParams(16, 0x8005, 0x0000, True, True, 0x0000),
    "crc16-ccitt-false": CrcParams(16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16-xmodem": CrcParams(16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16-kermit": CrcParams(16, 0x1021, 0x0000, True, True, 0x0000),
    "crc16-usb": CrcParams(16, 0x8005, 0xFFFF, True, True, 0xFFFF),
    "crc8": CrcParams(8, 0x07, 0x00, False, False, 0x00),
    "crc8-maxim": CrcParams(8, 0x31, 0x00, True, True, 0x00),
    "crc32": CrcParams(32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
}

# Non-CRC algorithms, handled separately.
SIMPLE = {"sum8", "sum16", "xor8", "none"}

ALGORITHMS = sorted(set(PRESETS) | SIMPLE)


def crc(data: bytes, params: CrcParams) -> int:
    mask = (1 << params.width) - 1
    top = 1 << (params.width - 1)
    shift = params.width - 8

    value = params.init
    for byte in data:
        b = _reflect(byte, 8) if params.reflect_in else byte
        value ^= (b << shift) & mask if shift >= 0 else b & mask
        for _ in range(8):
            value = ((value << 1) ^ params.poly) & mask if value & top else (value << 1) & mask

    if params.reflect_out:
        value = _reflect(value, params.width)
    return value ^ params.xor_out


class Checksum:
    """A configured checksum, built from a profile's `crc:` block."""

    def __init__(self, config: dict | None) -> None:
        config = config or {}
        self.algorithm = str(config.get("algorithm", "none")).lower().strip()
        self.byte_order = str(config.get("byte_order", "big")).lower().strip()
        self.covers: list[str] | None = config.get("covers")

        if self.algorithm in PRESETS:
            base = PRESETS[self.algorithm]
            # Allow per-profile overrides of any CRC parameter.
            self.params = CrcParams(
                width=int(config.get("width", base.width)),
                poly=_as_int(config.get("poly", base.poly)),
                init=_as_int(config.get("init", base.init)),
                reflect_in=bool(config.get("reflect_in", config.get("reflect", base.reflect_in))),
                reflect_out=bool(config.get("reflect_out", config.get("reflect", base.reflect_out))),
                xor_out=_as_int(config.get("xor_out", base.xor_out)),
            )
        elif self.algorithm in SIMPLE:
            self.params = None
        else:
            raise ValueError(
                f"unknown checksum algorithm {self.algorithm!r}; "
                f"known: {', '.join(ALGORITHMS)}"
            )

    @property
    def nbytes(self) -> int:
        if self.algorithm == "none":
            return 0
        if self.algorithm == "sum16":
            return 2
        if self.algorithm in ("sum8", "xor8"):
            return 1
        return self.params.nbytes

    def compute(self, data: bytes) -> int:
        if self.algorithm == "none":
            return 0
        if self.algorithm == "sum8":
            return sum(data) & 0xFF
        if self.algorithm == "sum16":
            return sum(data) & 0xFFFF
        if self.algorithm == "xor8":
            out = 0
            for b in data:
                out ^= b
            return out
        return crc(data, self.params)

    def pack(self, value: int) -> bytes:
        if self.nbytes == 0:
            return b""
        order = "big" if self.byte_order.startswith("b") else "little"
        return value.to_bytes(self.nbytes, order)

    def unpack(self, data: bytes) -> int:
        order = "big" if self.byte_order.startswith("b") else "little"
        return int.from_bytes(data, order)

    def verify(self, covered: bytes, expected: bytes) -> bool:
        if self.algorithm == "none":
            return True
        return self.pack(self.compute(covered)) == expected


def _as_int(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)
