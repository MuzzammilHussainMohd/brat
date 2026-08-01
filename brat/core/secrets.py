"""Detect credential-shaped data in a characteristic value.

Any device can put a token, key, or JWT in a GATT characteristic and nothing
about GATT permissions tells you that happened - you only find out by looking
at the bytes. This is deliberately independent of any profile or vendor: it
runs the same way whether the device under test is the one profile BRAT ships
or something it has never seen.

Kept to patterns with a low false-positive rate. A hit here is always worth a
human look, so it is better to miss an obfuscated secret than to bury real
ones under noise from every high-entropy firmware blob.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass

_JWT_RE = re.compile(rb"^eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*$")

# Vendor-prefixed API key formats with a distinctive, low-collision prefix.
_PREFIXED_KEY_RE = re.compile(
    rb"(sk-[A-Za-z0-9]{20,}|"  # OpenAI/Stripe-style secret keys
    rb"ghp_[A-Za-z0-9]{36}|"  # GitHub personal access token
    rb"gh[oprsu]_[A-Za-z0-9]{36}|"  # other GitHub token kinds
    rb"AIza[A-Za-z0-9_-]{35}|"  # Google API key
    rb"xox[baprs]-[A-Za-z0-9-]{10,})"  # Slack token
)

_HEX_RE = re.compile(rb"^[0-9a-fA-F]{32,}$")
_UUID_RE = re.compile(
    rb"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass
class SecretMatch:
    kind: str
    detail: str
    confidence: str  # "high" | "medium"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts if c
    )


def _looks_like_uuid(text: bytes) -> bool:
    return bool(_UUID_RE.match(text))


def _try_base64_high_entropy(data: bytes) -> SecretMatch | None:
    """A long base64 string that decodes cleanly and carries real entropy.

    Distinguishes an encoded secret from a base64-looking string that is
    actually low-entropy padding or a repeated pattern.
    """
    if len(data) < 24:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:  # noqa: BLE001
        return None
    if len(decoded) < 16:
        return None
    if _shannon_entropy(decoded) < 4.0:
        return None
    return SecretMatch(
        kind="base64-high-entropy",
        detail=f"{len(text)}-char base64 string decoding to {len(decoded)} bytes of high-entropy data",
        confidence="medium",
    )


def scan(data: bytes) -> list[SecretMatch]:
    """Check one characteristic value for credential-shaped content.

    Returns every distinct pattern that matched - usually zero or one, but a
    value can legitimately trip more than one (e.g. a hex string that is also
    high entropy).
    """
    if not data or len(data) < 16:
        return []

    matches: list[SecretMatch] = []

    if _JWT_RE.match(data):
        matches.append(
            SecretMatch(kind="jwt", detail="value has the three-part JWT structure", confidence="high")
        )
        return matches  # a JWT match is unambiguous; skip weaker heuristics

    prefixed = _PREFIXED_KEY_RE.search(data)
    if prefixed:
        matches.append(
            SecretMatch(
                kind="vendor-api-key",
                detail=f"matches a known API key prefix ({prefixed.group(1)[:6].decode('ascii', 'replace')}...)",
                confidence="high",
            )
        )
        return matches

    if _HEX_RE.match(data) and not _looks_like_uuid(data):
        # A long, even-length hex string is the shape of a raw key or token.
        # UUIDs are excluded - they are common, benign, and hex-shaped.
        matches.append(
            SecretMatch(
                kind="hex-blob",
                detail=f"{len(data)}-char hex string, long enough to be a raw key or token",
                confidence="medium",
            )
        )

    b64_match = _try_base64_high_entropy(data)
    if b64_match:
        matches.append(b64_match)

    return matches
