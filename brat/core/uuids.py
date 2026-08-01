"""UUID knowledge base.

Three jobs:

1. Turn a UUID into a human name (Bluetooth SIG assigned numbers).
2. Recognise well-known vendor UUIDs that SIG does not cover.
3. Flag UUIDs that are security-relevant on sight - firmware update interfaces,
   transparent serial bridges, debug services, and characteristics that carry
   health or identity data.

Point 3 is the one that earns its keep. A GATT dump full of 128-bit UUIDs is
noise until something tells you that `8ec90003-...` is a bootloader trigger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .findings import Severity

# The Bluetooth SIG base UUID. Any 16- or 32-bit UUID expands into this.
BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def normalize(uuid: str) -> str:
    """Return a lowercase 128-bit UUID string.

    Accepts `180f`, `0x180F`, `0000180f-...`, or a full 128-bit UUID.
    """
    u = str(uuid).strip().lower().replace("0x", "")
    if _UUID_RE.match(u):
        return u
    u = u.replace("-", "")
    if len(u) == 4:
        return f"0000{u}{BASE_UUID_SUFFIX}"
    if len(u) == 8:
        return f"{u}{BASE_UUID_SUFFIX}"
    if len(u) == 32:
        return f"{u[0:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}"
    return str(uuid).strip().lower()


def short_form(uuid: str) -> str | None:
    """Return the 16-bit short form if this is a SIG base UUID, else None."""
    u = normalize(uuid)
    if u.endswith(BASE_UUID_SUFFIX) and u.startswith("0000"):
        return u[4:8]
    return None


def is_sig(uuid: str) -> bool:
    return normalize(uuid).endswith(BASE_UUID_SUFFIX)


# ---------------------------------------------------------------------------
# Bluetooth SIG assigned numbers (16-bit short form -> name)
# ---------------------------------------------------------------------------

SIG_SERVICES: dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "1806": "Reference Time Update",
    "1807": "Next DST Change",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180e": "Phone Alert Status",
    "180f": "Battery",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181a": "Environmental Sensing",
    "181b": "Body Composition",
    "181c": "User Data",
    "181d": "Weight Scale",
    "181e": "Bond Management",
    "181f": "Continuous Glucose Monitoring",
    "1820": "Internet Protocol Support",
    "1821": "Indoor Positioning",
    "1822": "Pulse Oximeter",
    "1823": "HTTP Proxy",
    "1824": "Transport Discovery",
    "1825": "Object Transfer",
    "1826": "Fitness Machine",
    "1827": "Mesh Provisioning",
    "1828": "Mesh Proxy",
    "1829": "Reconnection Configuration",
    "183a": "Insulin Delivery",
    "183b": "Binary Sensor",
    "183c": "Emergency Configuration",
    "183e": "Physical Activity Monitor",
    "1843": "Audio Input Control",
    "1844": "Volume Control",
    "1845": "Volume Offset Control",
    "1846": "Coordinated Set Identification",
    "1847": "Device Time",
    "1848": "Media Control",
    "184e": "Audio Stream Control",
    "1850": "Published Audio Capabilities",
    "1853": "Common Audio",
    "1854": "Hearing Access",
    "fe59": "Nordic Secure DFU",
}

SIG_CHARACTERISTICS: dict[str, str] = {
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a02": "Peripheral Privacy Flag",
    "2a03": "Reconnection Address",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a06": "Alert Level",
    "2a07": "Tx Power Level",
    "2a08": "Date Time",
    "2a18": "Glucose Measurement",
    "2a19": "Battery Level",
    "2a1c": "Temperature Measurement",
    "2a1e": "Intermediate Temperature",
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a2a": "IEEE 11073-20601 Regulatory Certification",
    "2a2b": "Current Time",
    "2a31": "Scan Refresh",
    "2a35": "Blood Pressure Measurement",
    "2a37": "Heart Rate Measurement",
    "2a38": "Body Sensor Location",
    "2a39": "Heart Rate Control Point",
    "2a3f": "Alert Status",
    "2a4a": "HID Information",
    "2a4b": "HID Report Map",
    "2a4c": "HID Control Point",
    "2a4d": "HID Report",
    "2a50": "PnP ID",
    "2a52": "Record Access Control Point",
    "2a5f": "CGM Measurement",
    "2a63": "Cycling Power Measurement",
    "2a6d": "Pressure",
    "2a6e": "Temperature",
    "2a6f": "Humidity",
    "2a76": "UV Index",
    "2a7e": "Aerobic Heart Rate Lower Limit",
    "2a85": "Date of Birth",
    "2a8c": "Gender",
    "2a8e": "Height",
    "2a98": "Weight",
    "2a99": "Database Change Increment",
    "2a9a": "User Index",
    "2a9c": "Body Composition Measurement",
    "2a9d": "Weight Measurement",
    "2a9f": "User Control Point",
    "2aa5": "Bond Management Control Point",
    "2ab3": "Altitude",
    "2b29": "Client Supported Features",
    "2b2a": "Database Hash",
    "2b3a": "Server Supported Features",
}

SIG_DESCRIPTORS: dict[str, str] = {
    "2900": "Characteristic Extended Properties",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration",
    "2903": "Server Characteristic Configuration",
    "2904": "Characteristic Presentation Format",
    "2905": "Characteristic Aggregate Format",
    "2906": "Valid Range",
    "290b": "Environmental Sensing Configuration",
    "2910": "Characteristic Observation Schedule",
}


# ---------------------------------------------------------------------------
# Well-known vendor UUIDs (full 128-bit -> name)
# ---------------------------------------------------------------------------

VENDOR_UUIDS: dict[str, str] = {
    # Nordic UART Service - a transparent serial bridge over GATT. Extremely
    # common on custom devices; almost always carries a proprietary protocol.
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART Service (NUS)",
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e": "NUS RX (central writes here)",
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e": "NUS TX (peripheral notifies here)",
    # Nordic Secure DFU (bootloader present)
    "8ec90001-f315-4f60-9fb8-838830daea50": "Nordic Secure DFU Control Point",
    "8ec90002-f315-4f60-9fb8-838830daea50": "Nordic Secure DFU Packet",
    "8ec90003-f315-4f60-9fb8-838830daea50": "Nordic Buttonless DFU (unbonded)",
    "8ec90004-f315-4f60-9fb8-838830daea50": "Nordic Buttonless DFU (bonded)",
    # Nordic Legacy DFU
    "00001530-1212-efde-1523-785feabcd123": "Nordic Legacy DFU Service",
    "00001531-1212-efde-1523-785feabcd123": "Nordic Legacy DFU Control Point",
    "00001532-1212-efde-1523-785feabcd123": "Nordic Legacy DFU Packet",
    "00001534-1212-efde-1523-785feabcd123": "Nordic Legacy DFU Version",
    # Texas Instruments OAD (over-the-air download)
    "f000ffc0-0451-4000-b000-000000000000": "TI OAD Service",
    "f000ffc1-0451-4000-b000-000000000000": "TI OAD Image Identify",
    "f000ffc2-0451-4000-b000-000000000000": "TI OAD Image Block",
    "f000ffc5-0451-4000-b000-000000000000": "TI OAD Control Point",
    # Silicon Labs OTA
    "1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0": "Silicon Labs OTA Service",
    "f7bf3564-fb6d-4e53-88a4-5e37e0326063": "Silicon Labs OTA Control",
    "984227f3-34fc-4045-a5d0-2c581f81a153": "Silicon Labs OTA Data",
    # Telink OTA
    "00010203-0405-0607-0809-0a0b0c0d1912": "Telink OTA Service",
    "00010203-0405-0607-0809-0a0b0c0d2b12": "Telink OTA Characteristic",
    # Apple
    "7905f431-b5ce-4e99-a40f-4b1e122d00d0": "Apple Notification Center Service",
    "89d3502b-0f36-433a-8ef4-c502ad55f8dc": "Apple Media Service",
}


# ---------------------------------------------------------------------------
# Risk fingerprints
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskEntry:
    """A security judgement attached to a UUID."""

    label: str
    severity: Severity
    category: str
    rationale: str
    remediation: str = ""


# Keyed by normalized 128-bit UUID.
RISK_UUIDS: dict[str, RiskEntry] = {}


def _risk(uuid: str, entry: RiskEntry) -> None:
    RISK_UUIDS[normalize(uuid)] = entry


# --- Firmware update interfaces --------------------------------------------
# An exposed DFU trigger is the single highest-value BLE target: at minimum it
# is a remote reboot into bootloader (denial of service), and if image signing
# is absent it is remote code execution.

_DFU_REMEDIATION = (
    "Require an authenticated, encrypted link before exposing the DFU trigger, "
    "and enforce cryptographic image signature verification in the bootloader."
)

for _u, _label in [
    ("8ec90003-f315-4f60-9fb8-838830daea50", "Nordic Buttonless DFU (unbonded)"),
    ("8ec90004-f315-4f60-9fb8-838830daea50", "Nordic Buttonless DFU (bonded)"),
    ("8ec90001-f315-4f60-9fb8-838830daea50", "Nordic Secure DFU Control Point"),
    ("00001531-1212-efde-1523-785feabcd123", "Nordic Legacy DFU Control Point"),
    ("00001530-1212-efde-1523-785feabcd123", "Nordic Legacy DFU Service"),
    ("f000ffc1-0451-4000-b000-000000000000", "TI OAD Image Identify"),
    ("f000ffc5-0451-4000-b000-000000000000", "TI OAD Control Point"),
    ("f7bf3564-fb6d-4e53-88a4-5e37e0326063", "Silicon Labs OTA Control"),
    ("00010203-0405-0607-0809-0a0b0c0d2b12", "Telink OTA Characteristic"),
]:
    _risk(
        _u,
        RiskEntry(
            label=_label,
            severity=Severity.HIGH,
            category="firmware-update",
            rationale=(
                "Firmware update interface exposed over GATT. If writable without "
                "authentication this is at minimum a remote forced reboot into "
                "bootloader, and a full device compromise if image signing is absent."
            ),
            remediation=_DFU_REMEDIATION,
        ),
    )

# Legacy DFU deserves its own note - it predates signature enforcement.
_risk(
    "00001530-1212-efde-1523-785feabcd123",
    RiskEntry(
        label="Nordic Legacy DFU Service",
        severity=Severity.CRITICAL,
        category="firmware-update",
        rationale=(
            "Nordic *Legacy* DFU. Unlike Secure DFU this bootloader generation has "
            "no signature verification, so an unauthenticated writer can usually "
            "flash arbitrary firmware."
        ),
        remediation="Migrate to Secure DFU with ECDSA P-256 image signing.",
    ),
)

# --- Transparent serial bridges --------------------------------------------

_risk(
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
    RiskEntry(
        label="Nordic UART Service (NUS)",
        severity=Severity.MEDIUM,
        category="proprietary-protocol",
        rationale=(
            "A transparent serial bridge over GATT. GATT-level permissions say "
            "nothing about what the proprietary protocol on top enforces - any "
            "authentication lives in the application layer and must be tested "
            "separately. Define a `protocol:` block in a BRAT profile to test it."
        ),
        remediation=(
            "Do not treat the transport as a trust boundary. Authenticate every "
            "command in the application protocol, and bind commands to a session "
            "with a nonce so captured frames cannot be replayed."
        ),
    ),
)

_risk(
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e",
    RiskEntry(
        label="NUS RX (central -> peripheral)",
        severity=Severity.MEDIUM,
        category="proprietary-protocol",
        rationale="Command ingress for a proprietary protocol carried over NUS.",
        remediation="Authenticate commands at the application layer.",
    ),
)

# --- HID -------------------------------------------------------------------

_risk(
    "1812",
    RiskEntry(
        label="Human Interface Device",
        severity=Severity.MEDIUM,
        category="input-injection",
        rationale=(
            "HID over GATT. If a central can be induced to bond with a rogue "
            "peripheral advertising this service, the peripheral can inject "
            "keystrokes into the host."
        ),
        remediation="Require LE Secure Connections with MITM protection for HID bonds.",
    ),
)

# --- Health and identity data ----------------------------------------------

_HEALTH_SERVICES = {
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180d": "Heart Rate",
    "1810": "Blood Pressure",
    "181b": "Body Composition",
    "181d": "Weight Scale",
    "181f": "Continuous Glucose Monitoring",
    "1822": "Pulse Oximeter",
    "183a": "Insulin Delivery",
    "183e": "Physical Activity Monitor",
}

for _u, _label in _HEALTH_SERVICES.items():
    _risk(
        _u,
        RiskEntry(
            label=_label,
            severity=Severity.MEDIUM,
            category="sensitive-data",
            rationale=(
                f"The {_label} service carries health data. Readable or notifiable "
                "without an encrypted, authenticated link means this is available "
                "to anyone in radio range."
            ),
            remediation="Require encryption and authentication on all health characteristics.",
        ),
    )

# Insulin delivery is not merely a confidentiality problem.
_risk(
    "183a",
    RiskEntry(
        label="Insulin Delivery",
        severity=Severity.HIGH,
        category="sensitive-data",
        rationale=(
            "Insulin Delivery service. Beyond disclosure, writable control points "
            "on this service have direct physical-safety consequences."
        ),
        remediation="Require authenticated encryption; never accept unauthenticated writes.",
    ),
)

_IDENTITY_CHARS = {
    "2a23": "System ID",
    "2a25": "Serial Number String",
    "2a50": "PnP ID",
}

for _u, _label in _IDENTITY_CHARS.items():
    _risk(
        _u,
        RiskEntry(
            label=_label,
            severity=Severity.LOW,
            category="privacy",
            rationale=(
                f"{_label} is a stable per-device identifier. Readable without "
                "authentication, it lets a passive observer correlate and track "
                "this specific unit even if the MAC address rotates."
            ),
            remediation="Gate identifying characteristics behind an encrypted link.",
        ),
    )


# ---------------------------------------------------------------------------
# Lookup API
# ---------------------------------------------------------------------------


def describe(uuid: str, kind: str = "any") -> str | None:
    """Best-effort human name for a UUID.

    `kind` is one of "service", "characteristic", "descriptor", "any" and only
    disambiguates when a 16-bit value collides across tables.
    """
    u = normalize(uuid)
    if u in VENDOR_UUIDS:
        return VENDOR_UUIDS[u]

    s = short_form(u)
    if not s:
        return None

    tables = {
        "service": [SIG_SERVICES],
        "characteristic": [SIG_CHARACTERISTICS],
        "descriptor": [SIG_DESCRIPTORS],
        "any": [SIG_SERVICES, SIG_CHARACTERISTICS, SIG_DESCRIPTORS],
    }[kind]

    for table in tables:
        if s in table:
            return table[s]
    return None


def risk_for(uuid: str) -> RiskEntry | None:
    """Return the risk judgement for a UUID, if BRAT knows one."""
    return RISK_UUIDS.get(normalize(uuid))


def label(uuid: str, kind: str = "any") -> str:
    """Human label for display: name if known, else the short/full UUID."""
    name = describe(uuid, kind)
    if name:
        return name
    s = short_form(uuid)
    return f"0x{s.upper()}" if s else normalize(uuid)
