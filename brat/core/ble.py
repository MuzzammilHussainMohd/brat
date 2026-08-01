"""BLE central-side helpers built on bleak.

Two things here that bleak does not give you directly and that every check
needs:

* Error classification. A failed read means very different things depending on
  whether the peripheral said "not permitted", "insufficient authentication",
  or the link just dropped. Posture verdicts hinge on that distinction, and it
  arrives as a D-Bus error string that has to be interpreted.

* Address typing. Whether a device advertises a fixed public address or a
  rotating resolvable private address is a privacy property of the device, and
  it is only visible at scan time.
"""

from __future__ import annotations

import asyncio
import enum
import re
from dataclasses import dataclass, field
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

from .uuids import label as uuid_label
from .uuids import normalize as norm_uuid

# BlueZ discovery/connect calls go through D-Bus, and a `timeout=` kwarg only
# bounds bleak's own internal wait (e.g. an `asyncio.sleep`) - it does not
# abort a StartDiscovery/Connect D-Bus call that never replies, which can
# hang far longer than requested (observed against a BlueZ instance left in a
# corrupted state after a peripheral-mode session). Every call in this module
# that talks to BlueZ is wrapped in a hard wall-clock deadline so a stuck
# D-Bus call can never hang the calling command indefinitely.
_HARD_DEADLINE_MARGIN = 15.0


# ---------------------------------------------------------------------------
# GATT error classification
# ---------------------------------------------------------------------------


class GattResult(enum.Enum):
    """What happened when we tried an operation."""

    SUCCESS = "success"
    AUTHENTICATION_REQUIRED = "authentication-required"
    ENCRYPTION_REQUIRED = "encryption-required"
    AUTHORIZATION_REQUIRED = "authorization-required"
    NOT_PERMITTED = "not-permitted"
    NOT_SUPPORTED = "not-supported"
    DISCONNECTED = "disconnected"
    TIMEOUT = "timeout"
    UNKNOWN_ERROR = "unknown-error"

    @property
    def is_security_refusal(self) -> bool:
        """True when the peripheral refused *because of* a security requirement.

        This is the "device did its job" signal. `NOT_PERMITTED` deliberately
        does not count: a characteristic that is simply not readable tells you
        nothing about whether the device enforces authentication.
        """
        return self in (
            GattResult.AUTHENTICATION_REQUIRED,
            GattResult.ENCRYPTION_REQUIRED,
            GattResult.AUTHORIZATION_REQUIRED,
        )


# BlueZ surfaces ATT error codes as D-Bus errors with human-readable text.
# The mapping is not perfectly stable across BlueZ versions, so match on
# substrings, most specific first.
_ERROR_PATTERNS: list[tuple[str, GattResult]] = [
    ("insufficient authentication", GattResult.AUTHENTICATION_REQUIRED),
    ("insufficient authorization", GattResult.AUTHORIZATION_REQUIRED),
    ("insufficient encryption key size", GattResult.ENCRYPTION_REQUIRED),
    ("insufficient encryption", GattResult.ENCRYPTION_REQUIRED),
    ("encryption required", GattResult.ENCRYPTION_REQUIRED),
    ("authentication required", GattResult.AUTHENTICATION_REQUIRED),
    ("not authorized", GattResult.AUTHORIZATION_REQUIRED),
    ("notauthorized", GattResult.AUTHORIZATION_REQUIRED),
    ("not paired", GattResult.AUTHENTICATION_REQUIRED),
    ("not permitted", GattResult.NOT_PERMITTED),
    ("notpermitted", GattResult.NOT_PERMITTED),
    ("read not permitted", GattResult.NOT_PERMITTED),
    ("write not permitted", GattResult.NOT_PERMITTED),
    ("not supported", GattResult.NOT_SUPPORTED),
    ("notsupported", GattResult.NOT_SUPPORTED),
    ("request not supported", GattResult.NOT_SUPPORTED),
    ("disconnected", GattResult.DISCONNECTED),
    ("not connected", GattResult.DISCONNECTED),
    ("timed out", GattResult.TIMEOUT),
    ("timeout", GattResult.TIMEOUT),
]

# Raw ATT error codes, when they leak through in the message.
_ATT_CODES: dict[int, GattResult] = {
    0x02: GattResult.NOT_PERMITTED,
    0x03: GattResult.NOT_PERMITTED,
    0x05: GattResult.AUTHENTICATION_REQUIRED,
    0x06: GattResult.NOT_SUPPORTED,
    0x08: GattResult.AUTHORIZATION_REQUIRED,
    0x0C: GattResult.ENCRYPTION_REQUIRED,
    0x0F: GattResult.ENCRYPTION_REQUIRED,
}


def classify_error(exc: BaseException) -> tuple[GattResult, str]:
    """Map an exception from a GATT operation to a result class plus detail."""
    detail = str(exc)

    dbus_error = getattr(exc, "dbus_error", None)
    dbus_details = getattr(exc, "dbus_error_details", None)
    haystack = " ".join(
        str(x) for x in (dbus_error, dbus_details, detail) if x
    ).lower()

    if isinstance(exc, TimeoutError) or "timeouterror" in type(exc).__name__.lower():
        return GattResult.TIMEOUT, detail or "operation timed out"

    code_match = re.search(r"att error(?:[: ]+)(?:0x)?([0-9a-f]{1,2})", haystack)
    if code_match:
        code = int(code_match.group(1), 16)
        if code in _ATT_CODES:
            return _ATT_CODES[code], detail

    for pattern, result in _ERROR_PATTERNS:
        if pattern in haystack:
            return result, detail

    return GattResult.UNKNOWN_ERROR, detail


# ---------------------------------------------------------------------------
# Address typing
# ---------------------------------------------------------------------------


class AddressType(enum.Enum):
    PUBLIC = "public"
    RANDOM_STATIC = "random-static"
    RESOLVABLE_PRIVATE = "resolvable-private"
    NON_RESOLVABLE_PRIVATE = "non-resolvable-private"
    UNKNOWN = "unknown"

    @property
    def is_trackable(self) -> bool:
        """True if the address is stable enough to follow a device around.

        Static random addresses are only permitted to change at power-on, so in
        practice they are as trackable as a public address for a device that
        stays powered.
        """
        return self in (AddressType.PUBLIC, AddressType.RANDOM_STATIC)


def classify_address(address: str, dbus_type: str | None = None) -> AddressType:
    """Determine the BLE address type.

    `dbus_type` is BlueZ's AddressType property ("public" / "random"). The two
    most-significant bits of a random address encode its sub-type.
    """
    if dbus_type and dbus_type.lower() == "public":
        return AddressType.PUBLIC

    try:
        msb = int(address.split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return AddressType.UNKNOWN

    if dbus_type is None:
        # Without BlueZ's flag we cannot distinguish a public address from a
        # static random one that happens to share the bit pattern.
        return AddressType.UNKNOWN

    top = (msb >> 6) & 0b11
    return {
        0b11: AddressType.RANDOM_STATIC,
        0b01: AddressType.RESOLVABLE_PRIVATE,
        0b00: AddressType.NON_RESOLVABLE_PRIVATE,
    }.get(top, AddressType.UNKNOWN)


def _dbus_props(device: Any) -> dict:
    """Best-effort access to BlueZ's property dict for a scanned device."""
    details = getattr(device, "details", None)
    if isinstance(details, dict):
        props = details.get("props")
        if isinstance(props, dict):
            return props
        return details
    props = getattr(details, "props", None)
    return props if isinstance(props, dict) else {}


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    address: str
    name: str | None = None
    rssi: int | None = None
    address_type: AddressType = AddressType.UNKNOWN
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_data: dict[str, bytes] = field(default_factory=dict)
    tx_power: int | None = None
    appearance: int | None = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "address_type": self.address_type.value,
            "trackable_address": self.address_type.is_trackable,
            "service_uuids": self.service_uuids,
            "service_names": [uuid_label(u, "service") for u in self.service_uuids],
            "manufacturer_data": {
                str(k): v.hex() for k, v in self.manufacturer_data.items()
            },
            "service_data": {k: v.hex() for k, v in self.service_data.items()},
            "tx_power": self.tx_power,
            "appearance": self.appearance,
        }


async def scan(timeout: float = 8.0, adapter: str | None = None) -> list[ScanResult]:
    """Passive discovery. Returns one result per unique address.

    No `connectable` field: BlueZ's org.bluez.Device1 interface, which this
    reads its properties from, has no such property, so it was previously
    always None/null - present in every JSON scan record as though it had
    been collected and simply came back empty, rather than never collected
    at all.
    """
    kwargs: dict[str, Any] = {"timeout": timeout, "return_adv": True}
    if adapter:
        kwargs["adapter"] = adapter

    discovered = await asyncio.wait_for(
        BleakScanner.discover(**kwargs), timeout=timeout + _HARD_DEADLINE_MARGIN
    )

    results: list[ScanResult] = []
    for device, adv in discovered.values():
        props = _dbus_props(device)
        results.append(
            ScanResult(
                address=device.address,
                name=adv.local_name or getattr(device, "name", None),
                rssi=adv.rssi,
                address_type=classify_address(device.address, props.get("AddressType")),
                service_uuids=[norm_uuid(u) for u in (adv.service_uuids or [])],
                manufacturer_data={
                    int(k): bytes(v) for k, v in (adv.manufacturer_data or {}).items()
                },
                service_data={
                    norm_uuid(k): bytes(v) for k, v in (adv.service_data or {}).items()
                },
                tx_power=adv.tx_power,
                appearance=props.get("Appearance"),
            )
        )

    results.sort(key=lambda r: (r.rssi is None, -(r.rssi or 0)))
    return results


async def find_device(
    address: str, timeout: float = 10.0, adapter: str | None = None
):
    """Locate a device by address before connecting. Returns None if not seen."""
    kwargs: dict[str, Any] = {"timeout": timeout}
    if adapter:
        kwargs["adapter"] = adapter
    return await asyncio.wait_for(
        BleakScanner.find_device_by_address(address, **kwargs),
        timeout=timeout + _HARD_DEADLINE_MARGIN,
    )


# ---------------------------------------------------------------------------
# GATT enumeration
# ---------------------------------------------------------------------------


@dataclass
class CharacteristicInfo:
    uuid: str
    handle: int | None
    properties: list[str]
    descriptors: list[dict] = field(default_factory=list)
    value: bytes | None = None
    read_result: GattResult | None = None
    read_detail: str = ""

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": uuid_label(self.uuid, "characteristic"),
            "handle": self.handle,
            "properties": self.properties,
            "descriptors": self.descriptors,
            "value": self.value.hex() if self.value is not None else None,
            "read_result": self.read_result.value if self.read_result else None,
            "read_detail": self.read_detail or None,
        }


@dataclass
class ServiceInfo:
    uuid: str
    handle: int | None
    characteristics: list[CharacteristicInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": uuid_label(self.uuid, "service"),
            "handle": self.handle,
            "characteristics": [c.to_dict() for c in self.characteristics],
        }


async def enumerate_gatt(
    client: BleakClient, read_values: bool = False, per_read_timeout: float = 8.0
) -> list[ServiceInfo]:
    """Walk the full GATT tree.

    With `read_values`, every readable characteristic is also read and the
    outcome recorded - including the failure class, which is what the posture
    checks consume.

    Each read gets its own `per_read_timeout` bound. Without this, one
    characteristic whose read never completes (a sensor that only replies
    once triggered, or a firmware bug) hangs the whole enumeration - and if
    that hang is what trips an outer hard deadline (see core/ble.py's own
    scan/connect wrapping, and posture.py's probe), every characteristic
    after it - and the ones already read - is lost, so the finding set looks
    clean instead of incomplete. A per-read timeout means a single bad
    characteristic costs its own timeout, not the entire tree.
    """
    services: list[ServiceInfo] = []

    for service in client.services:
        info = ServiceInfo(
            uuid=norm_uuid(service.uuid), handle=getattr(service, "handle", None)
        )

        for char in service.characteristics:
            cinfo = CharacteristicInfo(
                uuid=norm_uuid(char.uuid),
                handle=getattr(char, "handle", None),
                properties=list(char.properties),
            )

            for desc in char.descriptors:
                cinfo.descriptors.append(
                    {
                        "uuid": norm_uuid(desc.uuid),
                        "name": uuid_label(desc.uuid, "descriptor"),
                        "handle": getattr(desc, "handle", None),
                    }
                )

            if read_values and "read" in char.properties:
                try:
                    value = await asyncio.wait_for(
                        client.read_gatt_char(char), timeout=per_read_timeout
                    )
                    cinfo.value = bytes(value)
                    cinfo.read_result = GattResult.SUCCESS
                except asyncio.TimeoutError:
                    cinfo.read_result = GattResult.TIMEOUT
                    cinfo.read_detail = f"read exceeded {per_read_timeout:g}s"
                except Exception as exc:  # noqa: BLE001 - classify everything
                    result, detail = classify_error(exc)
                    cinfo.read_result = result
                    cinfo.read_detail = detail

            info.characteristics.append(cinfo)

        services.append(info)

    return services


def decode_value(uuid: str, data: bytes) -> str | None:
    """Human rendering for well-known characteristic values."""
    from .uuids import short_form

    short = short_form(uuid)
    if not data:
        return None

    string_chars = {"2a00", "2a24", "2a25", "2a26", "2a27", "2a28", "2a29"}
    if short in string_chars:
        try:
            text = data.decode("utf-8").strip("\x00").strip()
            return text or None
        except UnicodeDecodeError:
            return None

    if short == "2a19":
        return f"{data[0]}%"
    if short == "2a01" and len(data) >= 2:
        return f"appearance 0x{int.from_bytes(data[:2], 'little'):04X}"
    if short == "2a23" and len(data) >= 8:
        return f"system id {data.hex()}"

    # Printable ASCII is worth surfacing on unknown characteristics too - it is
    # frequently a serial number or a token the vendor did not think about.
    if all(32 <= b < 127 for b in data) and len(data) >= 4:
        return f"ascii {data.decode('ascii')!r}"
    return None
