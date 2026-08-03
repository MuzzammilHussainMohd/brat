"""Secret-shaped-value detection.

Deliberately vendor-agnostic: none of these fixtures reference any real
device. A detector that only fires on API-key-shaped data would be useless
against the next device someone points BRAT at.
"""

import base64

from brat.core.secrets import scan


def test_too_short_is_ignored():
    assert scan(b"\x01\x02") == []


def test_ordinary_ascii_text_is_ignored():
    assert scan(b"Example-Band-1234") == []


def test_uuid_shaped_hex_is_not_flagged():
    # A characteristic value that is itself a UUID (e.g. a service reference)
    # is common and benign - must not be confused with a raw key.
    assert scan(b"550e8400-e29b-41d4-a716-446655440000") == []


def test_jwt_is_flagged_high_confidence():
    fake_jwt = (
        b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzbm90YXJlYWxzaWc"
    )
    matches = scan(fake_jwt)
    assert len(matches) == 1
    assert matches[0].kind == "jwt"
    assert matches[0].confidence == "high"


def test_github_token_prefix_is_flagged():
    fake_token = b"ghp_" + b"a" * 36
    matches = scan(fake_token)
    assert any(m.kind == "vendor-api-key" for m in matches)
    assert all(m.confidence == "high" for m in matches)


def test_openai_style_key_is_flagged():
    fake_key = b"sk-" + b"A1b2C3d4E5f6G7h8I9j0" * 2
    matches = scan(fake_key)
    assert any(m.kind == "vendor-api-key" for m in matches)


def test_long_hex_string_is_flagged_medium_confidence():
    long_hex = bytes.fromhex("deadbeef" * 8).hex().encode("ascii")
    matches = scan(long_hex)
    assert any(m.kind == "hex-blob" for m in matches)
    assert all(m.confidence == "medium" for m in matches)


def test_high_entropy_base64_is_flagged():
    import os

    random_bytes = bytes((i * 37 + 11) % 256 for i in range(32))
    encoded = base64.b64encode(random_bytes)
    matches = scan(encoded)
    assert any(m.kind == "base64-high-entropy" for m in matches)


def test_low_entropy_base64_is_not_flagged():
    # Repetitive data that happens to be valid base64 should not trip the
    # high-entropy heuristic - this is what keeps the false-positive rate low.
    repetitive = base64.b64encode(b"\x00" * 32)
    assert scan(repetitive) == []


def test_raw_binary_firmware_blob_is_not_necessarily_flagged():
    # Structured binary (not ASCII, not hex-string-shaped, not base64-shaped)
    # should not trip any pattern - it is not shaped like an encoded secret.
    blob = bytes([0xA5, 0x00, 0x01, 0xD0, 0xE0, 0x92, 0x00, 0xE2] + [0x00] * 20)
    assert scan(blob) == []
