"""`brat posture` - does this device demand authentication before it talks?

One generic script, no device-specific logic. It connects cold, tries to use
the device, and reports what the device let it do.

The checks are written as small independent functions against a shared context
so adding a new one is a local change. Each is explicit about whether its
verdict is CONFIRMED (BRAT performed the action and it worked) or INFERRED
(BRAT read a property saying it would work but did not exercise it). Tools that
blur those two produce findings that evaporate under scrutiny.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable

from bleak import BleakClient

from ..core import ble
from ..core.ble import AddressType, GattResult
from ..core.console import Console
from ..core.findings import Confidence, Finding, Severity
from ..core.profile import Profile, load_all_profiles, load_profile
from ..core.report import Report
from ..core.uuids import label as uuid_label
from ..core.uuids import normalize as norm_uuid
from ..core.uuids import risk_for, short_form

# Writing to these is how you brick or reboot a device, so write-probing skips
# them even when the user asked for probing.
_NEVER_PROBE_CATEGORIES = {"firmware-update"}

# "authenticated-signed-writes" (Signed Write Command) is included so this
# matches enumerate.py's definition - without it, a characteristic whose ONLY
# write-capable property is signed writes was invisible to every check below,
# a silent gap rather than a deliberate "not applicable". It is handled
# separately from plain write/write-without-response below: a signed write is
# authenticated at the ATT layer via a CSRK established during bonding, so
# being unpaired at the link layer does not mean this channel accepts
# unauthenticated input the way plain `write` does.
_WRITE_PROPS = {"write", "write-without-response", "authenticated-signed-writes"}
_PLAIN_WRITE_PROPS = {"write", "write-without-response"}

# A zero-length "write-without-response" is an ATT Write Command: BlueZ
# reports success as soon as it is queued, which proves nothing about whether
# the peripheral accepted, rejected, or silently dropped it. Only an
# acknowledged Write Request (response=True) can produce a genuine CONFIRMED
# result, so the two outcomes are tracked under different markers.
_UNVERIFIED_NO_RESPONSE = "unverified-no-response"

# Characteristics whose contents identify a person or a specific unit.
_IDENTITY_CHARS = {"2a23", "2a25", "2a50"}


@dataclass
class PostureContext:
    address: str
    connected_unpaired: bool = False
    connect_error: str = ""
    connect_error_class: GattResult | None = None
    mtu: int | None = None
    services: list[dict] = field(default_factory=list)
    scan_result: ble.ScanResult | None = None
    profile: Profile | None = None
    write_probes: dict[str, str] = field(default_factory=dict)
    pairing_result: dict | None = None
    skipped: list[str] = field(default_factory=list)

    def characteristics(self):
        for service in self.services:
            for char in service["characteristics"]:
                yield service, char

    def is_sensitive(self, uuid: str) -> bool:
        if self.profile and self.profile.security.is_sensitive(uuid):
            return True
        risk = risk_for(uuid)
        return bool(risk and risk.category == "sensitive-data")


CheckFn = Callable[[PostureContext], list[Finding]]
CHECKS: list[tuple[str, CheckFn]] = []


def check(name: str):
    def wrap(fn: CheckFn) -> CheckFn:
        CHECKS.append((name, fn))
        return fn

    return wrap


# ---------------------------------------------------------------------------
# Link-layer checks
# ---------------------------------------------------------------------------


@check("link")
def check_link(ctx: PostureContext) -> list[Finding]:
    if not ctx.connected_unpaired:
        if ctx.connect_error_class and ctx.connect_error_class.is_security_refusal:
            return [
                Finding(
                    check="link.authentication-enforced",
                    title="Device requires authentication before GATT access",
                    severity=Severity.INFO,
                    target=ctx.address,
                    description=(
                        "The peripheral refused an unauthenticated peer. This is the "
                        "gate working as designed."
                    ),
                    evidence={"error": ctx.connect_error},
                )
            ]
        return []

    expected_gate = not ctx.profile or ctx.profile.security.expect_pairing

    findings = [
        Finding(
            check="link.unauthenticated-connect",
            title="Accepts connections with no pairing or authentication",
            severity=Severity.MEDIUM if expected_gate else Severity.INFO,
            target=ctx.address,
            confidence=Confidence.CONFIRMED,
            description=(
                "Any device in radio range can open a GATT connection to this "
                "peripheral without pairing. On its own this is common and not always "
                "wrong; it becomes the foundation of every other finding below, "
                "because nothing that follows required a credential."
            ),
            evidence={"address": ctx.address, "mtu": ctx.mtu},
            remediation=(
                "Require pairing with LE Secure Connections before exposing any "
                "characteristic that carries data or accepts commands."
            ),
        )
    ]

    # The rigorous form of "the link is unencrypted": LE link encryption is
    # derived from pairing keys, so data that arrives without pairing arrived
    # in the clear. That is an observation, not an inference from a flag.
    #
    # Matches on `read_result == "success"` alone (not also requiring a
    # non-empty value) - a successful read of zero bytes still proves the ATT
    # operation was permitted over an unauthenticated link, which is exactly
    # what this finding is about. Requiring a truthy value made this and
    # `profile.encryption-expected` disagree on the same underlying fact for
    # a device whose readable characteristics happen to be uninitialised or
    # zero-length (a freshly reset or unbound unit, for instance).
    readable = [
        (s, c) for s, c in ctx.characteristics() if c.get("read_result") == "success"
    ]
    if readable:
        findings.append(
            Finding(
                check="link.no-encryption",
                title="Data is transferred over an unencrypted link",
                severity=Severity.HIGH,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "Characteristic values were read after connecting without pairing. "
                    "LE link encryption keys are established during pairing, so this "
                    "traffic was necessarily in plaintext over the air and is readable "
                    "by any passive sniffer in range."
                ),
                evidence={
                    "characteristics_read": len(readable),
                    "example": readable[0][1]["uuid"],
                },
                remediation=(
                    "Mandate an encrypted link (LE Secure Connections) before "
                    "permitting reads."
                ),
                references=["Bluetooth Core Spec, Vol 3, Part H (Security Manager)"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# GATT access checks
# ---------------------------------------------------------------------------


@check("read-access")
def check_unauthenticated_reads(ctx: PostureContext) -> list[Finding]:
    if not ctx.connected_unpaired:
        return []

    succeeded, refused = [], []
    for _service, char in ctx.characteristics():
        result = char.get("read_result")
        if result == "success":
            succeeded.append(char)
        elif result in (
            GattResult.AUTHENTICATION_REQUIRED.value,
            GattResult.ENCRYPTION_REQUIRED.value,
            GattResult.AUTHORIZATION_REQUIRED.value,
        ):
            refused.append(char)

    findings: list[Finding] = []

    sensitive = [c for c in succeeded if ctx.is_sensitive(c["uuid"])]
    ordinary = [c for c in succeeded if c not in sensitive]

    if sensitive:
        findings.append(
            Finding(
                check="gatt.sensitive-read-unauthenticated",
                title=f"{len(sensitive)} sensitive characteristic(s) readable without authentication",
                severity=Severity.CRITICAL,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "Characteristics carrying health, identity, or otherwise sensitive "
                    "data returned their contents to an unpaired peer. Anyone in range "
                    "can read this, and anyone passively listening already has it."
                ),
                evidence={
                    "characteristics": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']})"
                        for c in sensitive
                    ]
                },
                remediation="Require an authenticated, encrypted link for these characteristics.",
            )
        )

    if ordinary:
        findings.append(
            Finding(
                check="gatt.read-unauthenticated",
                title=f"{len(ordinary)} characteristic(s) readable without authentication",
                severity=Severity.MEDIUM,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "These characteristics returned data to an unpaired peer. Whether "
                    "that matters depends on the contents; device information and "
                    "battery level are usually intended to be open."
                ),
                evidence={
                    "characteristics": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']})"
                        for c in ordinary
                    ]
                },
                remediation="Gate anything beyond public metadata behind an encrypted link.",
            )
        )

    if refused:
        findings.append(
            Finding(
                check="gatt.read-enforced",
                title=f"{len(refused)} characteristic(s) correctly required authentication",
                severity=Severity.INFO,
                target=ctx.address,
                description="These reads were refused with a security error - working as intended.",
                evidence={"characteristics": [c["uuid"] for c in refused]},
            )
        )

    return findings


@check("secrets")
def check_secret_values(ctx: PostureContext) -> list[Finding]:
    """Flag characteristic values shaped like a credential.

    Deliberately vendor-agnostic: it runs the same regardless of which
    device this is, because a leaked token is a finding on any device, not
    just the ones BRAT ships a profile for.
    """
    if not ctx.connected_unpaired:
        return []

    from ..core import secrets as secret_scan

    hits: list[tuple[dict, "secret_scan.SecretMatch"]] = []
    for _service, char in ctx.characteristics():
        if char.get("read_result") != "success" or not char.get("value"):
            continue
        try:
            raw = bytes.fromhex(char["value"])
        except ValueError:
            continue
        for match in secret_scan.scan(raw):
            hits.append((char, match))

    if not hits:
        return []

    high_confidence = [(c, m) for c, m in hits if m.confidence == "high"]
    medium_confidence = [(c, m) for c, m in hits if m.confidence == "medium"]

    findings: list[Finding] = []
    if high_confidence:
        findings.append(
            Finding(
                check="gatt.credential-in-value",
                title=f"{len(high_confidence)} characteristic(s) contain a likely credential",
                severity=Severity.CRITICAL,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "A characteristic value matched a known credential format (JWT or a "
                    "vendor-prefixed API key) and was readable without authentication. "
                    "This is very unlikely to be a false positive."
                ),
                evidence={
                    "matches": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']}): "
                        f"{m.kind} - {m.detail}"
                        for c, m in high_confidence
                    ]
                },
                remediation=(
                    "Do not store live credentials in a GATT characteristic readable "
                    "without authentication. Rotate any credential this exposed."
                ),
            )
        )
    if medium_confidence:
        findings.append(
            Finding(
                check="gatt.possible-credential-in-value",
                title=f"{len(medium_confidence)} characteristic(s) contain possibly encoded data",
                severity=Severity.MEDIUM,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "A characteristic value looked like an encoded key or token (long hex "
                    "or high-entropy base64) and was readable without authentication. This "
                    "can be a false positive - firmware blobs and binary IDs can look the "
                    "same way - so treat it as a lead to check by hand, not a confirmed leak."
                ),
                evidence={
                    "matches": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']}): "
                        f"{m.kind} - {m.detail}"
                        for c, m in medium_confidence
                    ]
                },
                remediation=(
                    "Inspect the flagged value by hand. If it is a credential, gate it "
                    "behind authentication; if not, no action is needed."
                ),
            )
        )
    return findings


@check("write-access")
def check_write_exposure(ctx: PostureContext) -> list[Finding]:
    if not ctx.connected_unpaired:
        return []

    findings: list[Finding] = []
    all_writable = [
        (s, c) for s, c in ctx.characteristics() if _WRITE_PROPS & set(c["properties"])
    ]
    if not all_writable:
        return findings

    # Signed-write-only characteristics are authenticated by a CSRK from
    # bonding, not by the unauthenticated link this check is otherwise about -
    # they must not be bucketed into "exposed to an unpaired peer" below,
    # which would overclaim severity for a channel that is not actually
    # driven by anyone in range the way a plain write is.
    signed_only = [
        (s, c)
        for s, c in all_writable
        if not (_PLAIN_WRITE_PROPS & set(c["properties"]))
    ]
    if signed_only:
        findings.append(
            Finding(
                check="gatt.signed-write-only",
                title=f"{len(signed_only)} characteristic(s) require authenticated "
                "signed writes",
                severity=Severity.INFO,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "These characteristics only accept the Signed Write Command, "
                    "which requires a CSRK established during bonding - unlike plain "
                    "write, an unbonded peer cannot use this channel even over an "
                    "unencrypted, unpaired connection."
                ),
                evidence={"characteristics": [c["uuid"] for _s, c in signed_only]},
            )
        )

    writable = [(s, c) for s, c in all_writable if _PLAIN_WRITE_PROPS & set(c["properties"])]
    if not writable:
        return findings

    # Confirmed results first, if the user opted into probing.
    confirmed = [
        (s, c)
        for s, c in writable
        if ctx.write_probes.get(c["uuid"]) == GattResult.SUCCESS.value
    ]
    if confirmed:
        findings.append(
            Finding(
                check="gatt.write-unauthenticated",
                title=f"{len(confirmed)} characteristic(s) accept writes without authentication",
                severity=Severity.CRITICAL,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "A write from an unpaired peer was accepted. Whatever these "
                    "characteristics control can be driven by anyone in radio range."
                ),
                evidence={
                    "characteristics": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']})"
                        for _s, c in confirmed
                    ],
                    "probe": "zero-length write",
                },
                remediation="Require an authenticated link for every writable characteristic.",
            )
        )

    unverified = [
        (s, c)
        for s, c in writable
        if ctx.write_probes.get(c["uuid"]) == _UNVERIFIED_NO_RESPONSE
    ]
    if unverified:
        findings.append(
            Finding(
                check="gatt.write-unverified-no-response",
                title=f"{len(unverified)} write-without-response characteristic(s) "
                "sent without confirmation",
                severity=Severity.HIGH,
                target=ctx.address,
                confidence=Confidence.INFERRED,
                description=(
                    "A zero-length write was sent, but write-without-response is an "
                    "unacknowledged ATT Write Command: BlueZ reports success as soon as "
                    "the packet is queued, which does not prove the peripheral accepted, "
                    "processed, or even received it. Treat as exposed based on declared "
                    "properties, not as a confirmed accepted write."
                ),
                evidence={
                    "characteristics": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']})"
                        for _s, c in unverified
                    ]
                },
                remediation="Require an authenticated link for every writable characteristic.",
            )
        )

    unprobed = [(s, c) for s, c in writable if c["uuid"] not in ctx.write_probes]
    if unprobed:
        findings.append(
            Finding(
                check="gatt.write-exposed",
                title=f"{len(unprobed)} writable characteristic(s) exposed to an unpaired peer",
                severity=Severity.HIGH,
                target=ctx.address,
                confidence=Confidence.INFERRED,
                description=(
                    "These characteristics advertise write permission and are visible "
                    "to a peer that never authenticated. BRAT did not write to them, so "
                    "this is based on declared properties - pass --probe-writes to "
                    "confirm with a zero-length write."
                ),
                evidence={
                    "characteristics": [
                        f"{uuid_label(c['uuid'], 'characteristic')} ({c['uuid']}) "
                        f"[{','.join(c['properties'])}]"
                        for _s, c in unprobed
                    ]
                },
                remediation="Require an authenticated link for every writable characteristic.",
            )
        )

    silent = [
        (s, c) for s, c in writable if "write-without-response" in c["properties"]
    ]
    if silent:
        findings.append(
            Finding(
                check="gatt.write-without-response",
                title=f"{len(silent)} characteristic(s) accept write-without-response",
                severity=Severity.MEDIUM,
                target=ctx.address,
                confidence=Confidence.INFERRED,
                description=(
                    "Write-without-response gives the writer no error feedback, so the "
                    "peripheral cannot signal rejection and malformed input fails "
                    "silently. It is the usual path for fuzzing a device's parser."
                ),
                evidence={"characteristics": [c["uuid"] for _s, c in silent]},
                remediation=(
                    "Validate all input regardless of the write type, and prefer "
                    "acknowledged writes for anything that changes state."
                ),
            )
        )

    return findings


@check("firmware-update")
def check_dfu(ctx: PostureContext) -> list[Finding]:
    """Exposed firmware update interfaces - the highest-value BLE target."""
    # GATT *properties* (this loop's `writable` check) are not ATT
    # *permissions* - a characteristic can declare `write` and still require
    # an authenticated link to actually exercise it. DFU characteristics are
    # deliberately never write-probed (a real write can reboot or brick the
    # device), so this finding is inherently INFERRED from properties alone.
    # If other characteristics on the SAME device demonstrably refused reads
    # with a security error, that is direct contradicting evidence sitting in
    # the same context - a well-behaved device and a device that has simply
    # not been tested must not produce an identical CRITICAL verdict.
    other_reads_enforced = any(
        c.get("read_result")
        in (
            GattResult.AUTHENTICATION_REQUIRED.value,
            GattResult.ENCRYPTION_REQUIRED.value,
            GattResult.AUTHORIZATION_REQUIRED.value,
        )
        for _s, c in ctx.characteristics()
    )

    findings: list[Finding] = []
    for _service, char in ctx.characteristics():
        risk = risk_for(char["uuid"])
        if not risk or risk.category != "firmware-update":
            continue

        writable = bool(_WRITE_PROPS & set(char["properties"]))
        write_confirmed = ctx.write_probes.get(char["uuid"]) == GattResult.SUCCESS.value

        if write_confirmed:
            severity = Severity.CRITICAL
            confidence = Confidence.CONFIRMED
            title = "Firmware update interface accepted an unauthenticated write"
            description = (
                f"{risk.label} accepted a write from an unpaired peer. At minimum "
                "this is an unauthenticated forced reboot into bootloader - a denial "
                "of service against a device someone may depend on. If the "
                "bootloader does not enforce image signature verification, it is "
                "remote code execution."
            )
        elif writable and ctx.connected_unpaired and other_reads_enforced:
            # Contradicting evidence: this device does enforce authentication
            # somewhere, and this characteristic's write permission was never
            # tested (by design). Treat as HIGH/INFERRED, not CRITICAL - a
            # CRITICAL verdict here would be indistinguishable from a device
            # confirmed to accept the write.
            severity = Severity.HIGH
            confidence = Confidence.INFERRED
            title = "Firmware update interface exposed, write permission not verified"
            description = (
                f"{risk.label} declares write permission and was visible after "
                "connecting without pairing. This device did demonstrate "
                "authentication enforcement on other characteristics, so whether "
                "this specific write is actually gated is unconfirmed rather than "
                "disproven - BRAT does not write-probe firmware-update interfaces. "
                "Verify explicitly, e.g. with --probe-unknown-writes if the risk of "
                "doing so is acceptable, before treating this as equivalent to a "
                "confirmed-writable device."
            )
        elif writable and ctx.connected_unpaired:
            severity = Severity.CRITICAL
            confidence = Confidence.INFERRED
            title = "Firmware update interface writable by an unauthenticated peer"
            description = (
                f"{risk.label} is writable and was reachable without pairing. At "
                "minimum this is an unauthenticated forced reboot into bootloader - a "
                "denial of service against a device someone may depend on. If the "
                "bootloader does not enforce image signature verification, it is "
                "remote code execution. The write itself was not exercised (BRAT "
                "never write-probes firmware-update characteristics), so this is "
                "based on declared properties."
            )
        else:
            severity = Severity.MEDIUM
            confidence = Confidence.CONFIRMED
            title = "Firmware update interface present"
            description = risk.rationale

        findings.append(
            Finding(
                check="gatt.dfu-exposed",
                title=title,
                severity=severity,
                target=char["uuid"],
                confidence=confidence,
                description=description,
                evidence={
                    "characteristic": char["uuid"],
                    "label": risk.label,
                    "properties": char["properties"],
                    "reachable_unpaired": ctx.connected_unpaired,
                    "write_confirmed": write_confirmed,
                    "other_characteristics_enforced_auth": other_reads_enforced,
                },
                remediation=risk.remediation,
            )
        )
    return findings


@check("proprietary-protocol")
def check_proprietary_protocol(ctx: PostureContext) -> list[Finding]:
    """Transparent serial bridges - GATT permissions say nothing about them."""
    findings: list[Finding] = []
    for _service, char in ctx.characteristics():
        risk = risk_for(char["uuid"])
        if not risk or risk.category != "proprietary-protocol":
            continue
        if not (_WRITE_PROPS & set(char["properties"])):
            continue

        has_profile_protocol = bool(ctx.profile and ctx.profile.protocol_config)
        findings.append(
            Finding(
                check="gatt.proprietary-command-channel",
                title=f"{risk.label} accepts commands from an unpaired peer",
                severity=Severity.HIGH if ctx.connected_unpaired else Severity.MEDIUM,
                target=char["uuid"],
                confidence=Confidence.INFERRED,
                description=(
                    "This is a transparent serial channel carrying a vendor protocol. "
                    "GATT-level permissions tell you nothing about whether that "
                    "protocol authenticates its commands - the check has to happen at "
                    "the application layer. "
                    + (
                        "The loaded profile defines this protocol, so `brat impersonate` "
                        "can exercise it."
                        if has_profile_protocol
                        else "No protocol definition is loaded for this device; capture a "
                        "session and add a `protocol:` block to its profile to test it."
                    )
                ),
                evidence={
                    "characteristic": char["uuid"],
                    "properties": char["properties"],
                    "profile_defines_protocol": has_profile_protocol,
                },
                remediation=risk.remediation,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Privacy checks
# ---------------------------------------------------------------------------


@check("privacy")
def check_privacy(ctx: PostureContext) -> list[Finding]:
    findings: list[Finding] = []

    if ctx.scan_result and ctx.scan_result.address_type == AddressType.UNKNOWN:
        # Distinct from "device was not seen advertising at all" (which
        # already gets its own note above) - here the device WAS seen, but
        # BlueZ did not supply an AddressType property, so the static-address
        # privacy check silently produced no finding either way. Without this
        # note, "no privacy.static-address finding" looks identical to
        # "checked, and the address rotates" when the truth is "not checked".
        ctx.skipped.append(
            "Address type could not be determined for this device (BlueZ did not "
            "report it), so the static-address privacy check was skipped - this is "
            "not evidence the address rotates."
        )

    if ctx.scan_result and ctx.scan_result.address_type.is_trackable:
        findings.append(
            Finding(
                check="privacy.static-address",
                title=f"Static, trackable BLE address ({ctx.scan_result.address_type.value})",
                severity=Severity.MEDIUM,
                target=ctx.address,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The device advertises a non-rotating address. Any passive receiver "
                    "in range can log it, so the presence and movement of whoever "
                    "carries the device can be tracked over time by an observer who "
                    "never connects to it and leaves no trace."
                ),
                evidence={
                    "address": ctx.address,
                    "address_type": ctx.scan_result.address_type.value,
                    "advertised_name": ctx.scan_result.name,
                },
                remediation=(
                    "Enable LE Privacy so the device advertises a resolvable private "
                    "address that rotates, resolvable only by bonded peers holding the IRK."
                ),
                references=["Bluetooth Core Spec, Vol 3, Part C, 10.7"],
            )
        )

    if ctx.connected_unpaired:
        identifiers = []
        for _service, char in ctx.characteristics():
            if short_form(char["uuid"]) in _IDENTITY_CHARS and char.get("value"):
                identifiers.append(char)
        if identifiers:
            # 2a25 (Serial Number String) is genuinely text per the GATT
            # spec; 2a23 (System ID) and 2a50 (PnP ID) are fixed binary
            # layouts. Decoding all three as UTF-8 with errors="replace"
            # rendered the binary ones as unusable replacement-character
            # mush - hex is what makes those two readable and round-
            # trippable. A list (not a dict keyed by uuid) also means two
            # identity characteristics sharing a UUID - unusual, but the same
            # class of edge case as elsewhere in this codebase - don't
            # silently collapse into one evidence entry.
            evidence_entries = []
            for c in identifiers:
                raw = bytes.fromhex(c["value"])
                if short_form(c["uuid"]) == "2a25":
                    try:
                        rendered = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        rendered = raw.hex()
                else:
                    rendered = raw.hex()
                evidence_entries.append({"uuid": c["uuid"], "value": rendered})

            findings.append(
                Finding(
                    check="privacy.identity-disclosure",
                    title="Per-unit identifiers readable without authentication",
                    severity=Severity.MEDIUM,
                    target=ctx.address,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "Serial numbers and system IDs are stable per-device values. "
                        "Exposed to unauthenticated readers, they defeat MAC rotation: "
                        "an observer can re-identify the same unit after its address changes."
                    ),
                    evidence={"identifiers": evidence_entries},
                    remediation="Require an encrypted link before serving identifying characteristics.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Pairing checks
# ---------------------------------------------------------------------------


@check("pairing")
def check_pairing(ctx: PostureContext) -> list[Finding]:
    if not ctx.pairing_result:
        return []

    result = ctx.pairing_result
    if not result.get("paired"):
        return [
            Finding(
                check="pairing.rejected",
                title="Pairing attempt was rejected",
                severity=Severity.INFO,
                target=ctx.address,
                description="The device did not complete pairing with an unauthenticated agent.",
                evidence={"error": result.get("error", "")},
            )
        ]

    return [
        Finding(
            check="pairing.just-works",
            title="Accepts Just Works pairing (no MITM protection)",
            severity=Severity.HIGH,
            target=ctx.address,
            confidence=Confidence.CONFIRMED,
            description=(
                "Pairing completed with an agent that has no input and no display, so "
                "no passkey or numeric comparison was performed. Just Works produces an "
                "encrypted link with no authentication of the peer, which means it "
                "encrypts against a passive eavesdropper but not against an active "
                "attacker-in-the-middle who simply pairs with both sides."
            ),
            evidence={"agent": "NoInputNoOutput", "bonded": result.get("bonded")},
            remediation=(
                "Require LE Secure Connections with MITM protection - passkey entry, "
                "numeric comparison, or out-of-band - for any device carrying sensitive "
                "data or accepting commands."
            ),
            references=["Bluetooth Core Spec, Vol 3, Part H, 2.3.5.1"],
        )
    ]


# ---------------------------------------------------------------------------
# Profile expectations
# ---------------------------------------------------------------------------


@check("profile")
def check_profile_expectations(ctx: PostureContext) -> list[Finding]:
    if not ctx.profile:
        return []

    findings: list[Finding] = []
    security = ctx.profile.security

    if security.expect_encryption and ctx.connected_unpaired:
        read_ok = any(
            c.get("read_result") == "success" for _s, c in ctx.characteristics()
        )
        if read_ok:
            findings.append(
                Finding(
                    check="profile.encryption-expected",
                    title=f"Device does not meet the security posture declared in profile "
                    f"'{ctx.profile.slug}'",
                    severity=Severity.HIGH,
                    target=ctx.address,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"The profile for {ctx.profile.name} declares "
                        "expect_encryption: true, but data was read over an unpaired, "
                        "unencrypted link."
                    ),
                    evidence={"profile": ctx.profile.slug, "expect_encryption": True},
                    remediation="Either the device is misconfigured or the profile's expectation is wrong.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _looks_like_unrecognised_control_point(uuid: str, props: set[str]) -> bool:
    """True for a write+notify/indicate, non-readable characteristic BRAT cannot name.

    `risk_for` only knows a handful of vendors' DFU UUIDs (Nordic, TI, Silicon
    Labs, Telink). A firmware-update control point from any other vendor is
    unrecognised and would otherwise get a live zero-length write - on exactly
    the device class BRAT has the least basis for assuming that is safe. This
    is a shape heuristic, not a UUID match: write-plus-acknowledgement-channel
    with no read is the general pattern for any control point, DFU or not.
    """
    if risk_for(uuid) is not None:
        return False  # already handled by the known-UUID skip list
    if "read" in props:
        return False  # a plain data characteristic, not control-point-shaped
    return bool(_WRITE_PROPS & props) and bool({"notify", "indicate"} & props)


async def _probe_writes(
    client: BleakClient,
    ctx: PostureContext,
    console: Console | None,
    probe_unknown: bool = False,
) -> None:
    """Zero-length write to each writable characteristic, recording the outcome.

    A zero-length write is the least invasive probe that still exercises the
    permission check. Firmware-update characteristics are skipped regardless -
    writing to a DFU control point reboots the device. Characteristics that
    merely *look* like an unrecognised control point are also skipped unless
    the caller explicitly opts in, since BRAT cannot tell them apart from a
    firmware-update endpoint from a vendor it does not know.
    """
    for service in client.services:
        for char in service.characteristics:
            props = set(char.properties)
            if not (_WRITE_PROPS & props):
                continue

            risk = risk_for(char.uuid)
            if risk and risk.category in _NEVER_PROBE_CATEGORIES:
                ctx.skipped.append(
                    f"write-probe skipped for {char.uuid} ({risk.label}) - "
                    "writing to a firmware-update interface can reboot or brick the device"
                )
                continue

            if not probe_unknown and _looks_like_unrecognised_control_point(char.uuid, props):
                ctx.skipped.append(
                    f"write-probe skipped for {char.uuid} (unrecognised vendor, "
                    "write+notify/indicate with no read) - this is the shape of a "
                    "firmware-update control point BRAT does not have a UUID for; "
                    "pass --probe-unknown-writes to probe it anyway"
                )
                continue

            response = "write" in props
            try:
                await client.write_gatt_char(char, b"", response=response)
                if response:
                    ctx.write_probes[norm_uuid(char.uuid)] = GattResult.SUCCESS.value
                    if console:
                        console.warn(f"zero-length write ACCEPTED by {char.uuid}")
                else:
                    # Write Command has no acknowledgement - BlueZ returning
                    # without error only means the packet was queued, not that
                    # the peripheral accepted it.
                    ctx.write_probes[norm_uuid(char.uuid)] = _UNVERIFIED_NO_RESPONSE
                    if console:
                        console.step(
                            f"zero-length write-without-response sent to {char.uuid} "
                            "(no acknowledgement possible - not confirmed)"
                        )
            except Exception as exc:  # noqa: BLE001
                result, _detail = ble.classify_error(exc)
                ctx.write_probes[norm_uuid(char.uuid)] = result.value


async def _try_pairing(
    client: BleakClient, ctx: PostureContext, console: Console | None
) -> None:
    """Attempt Just Works pairing, then undo it.

    BlueZ's default agent for a non-interactive process is effectively
    NoInputNoOutput, so success here means the device accepted an association
    model with no MITM protection.

    bleak >=1.0 changed `pair()` to return None unconditionally on success
    (it used to return a bool) - the only signal left is whether it raised.
    Treating a falsy return value as failure silently inverts this check.
    """
    try:
        await client.pair()
        ctx.pairing_result = {"paired": True, "bonded": True}
        if console:
            console.warn("Just Works pairing succeeded - no passkey was required.")
    except Exception as exc:  # noqa: BLE001
        _result, detail = ble.classify_error(exc)
        ctx.pairing_result = {"paired": False, "error": detail}
        return

    try:
        await client.unpair()
    except Exception:  # noqa: BLE001
        ctx.skipped.append(
            "Pairing succeeded but unpair failed - remove the bond manually "
            f"with: bluetoothctl remove {ctx.address}"
        )


async def execute(args, console: Console) -> Report:
    report = Report(command="posture", target=args.address)
    verbose = args.output == "text"

    profile: Profile | None = None
    if args.profile:
        profile = load_profile(args.profile)
        if verbose:
            console.info(f"Loaded profile '{profile.slug}' ({profile.name})")

    ctx = PostureContext(address=args.address, profile=profile)

    # Scan first - address type is only observable from advertising.
    if verbose:
        console.info("Observing advertisements ...")
    try:
        seen = await ble.scan(timeout=min(args.timeout, 6.0), adapter=args.adapter)
        ctx.scan_result = next(
            (r for r in seen if r.address.lower() == args.address.lower()), None
        )
        if ctx.scan_result is None:
            report.note(
                "Device was not seen advertising during the scan window; address-type "
                "and advertising findings were skipped."
            )
    except Exception as exc:  # noqa: BLE001
        report.note(f"Advertising scan failed ({exc}); privacy checks were skipped.")

    if profile is None:
        # Auto-fingerprint so posture picks up sensitivity hints for free.
        if ctx.scan_result:
            from .scan import fingerprint_all

            ranked = fingerprint_all(ctx.scan_result, load_all_profiles())
            tied = len(ranked) > 1 and ranked[0][1] == ranked[1][1]
            if ranked and not tied:
                ctx.profile = profile = ranked[0][0]
                if verbose:
                    console.info(
                        f"Auto-matched profile '{profile.slug}' from advertising data."
                    )
            elif tied:
                # Applying either candidate's security.expect_pairing /
                # expect_encryption expectations would be a coin flip - most
                # concretely, two units of the same product family (a patched
                # and an unpatched device, say) cloned as separate profiles
                # tying here and one being silently applied to the other.
                candidates = ", ".join(
                    f"{p.slug} (score {s})" for p, s in ranked if s == ranked[0][1]
                )
                report.note(
                    f"Advertising data matched more than one profile with an equal "
                    f"score ({candidates}); none was auto-applied. Profile-dependent "
                    f"findings below were skipped - pass --profile explicitly to pick one."
                )

    # Connect and probe.
    if verbose:
        console.info(f"Connecting to {args.address} with no pairing ...")

    try:
        device = await ble.find_device(args.address, timeout=10.0, adapter=args.adapter)
    except Exception:  # noqa: BLE001 - fall back to connecting by address directly
        device = None
    target = device or args.address
    client_kwargs = {"timeout": args.timeout}
    if args.adapter:
        client_kwargs["adapter"] = args.adapter
    client = BleakClient(target, **client_kwargs)

    # bleak's `timeout=` kwarg races the D-Bus reply but does not reliably
    # abort an underlying D-Bus call that never replies - a stuck Connect()
    # can block far longer than requested, notably against a device enforcing
    # a link-layer filter accept list (silently drops CONNECT_IND from
    # addresses outside its whitelist rather than answering with an ATT
    # error). Wrap the whole probe in a hard wall-clock deadline so this
    # command always returns instead of hanging indefinitely.
    hard_deadline = args.timeout + 15.0

    async def _probe() -> None:
        await client.connect()
        ctx.connected_unpaired = True
        ctx.mtu = getattr(client, "mtu_size", None)
        if verbose:
            console.ok("Connected. No pairing was required.")

        services = await ble.enumerate_gatt(client, read_values=True)
        ctx.services = [s.to_dict() for s in services]

        if args.probe_writes:
            if verbose:
                console.step("Probing writable characteristics (zero-length writes) ...")
            await _probe_writes(
                client,
                ctx,
                console if verbose else None,
                probe_unknown=getattr(args, "probe_unknown_writes", False),
            )

        if args.check_pairing:
            if verbose:
                console.step("Attempting Just Works pairing ...")
            await _try_pairing(client, ctx, console if verbose else None)

    try:
        await asyncio.wait_for(_probe(), timeout=hard_deadline)
    except asyncio.TimeoutError:
        # A connect that never succeeded is a real (if slow) refusal signal.
        # A connect that DID succeed before a later step hung must not be
        # reported as a failed connection - that would flip the verdict.
        if not ctx.connected_unpaired:
            ctx.connect_error = f"operation exceeded hard deadline of {hard_deadline:g}s"
            ctx.connect_error_class = GattResult.TIMEOUT
            if verbose:
                console.error(
                    f"Connection attempt exceeded the hard deadline "
                    f"({hard_deadline:g}s) and was aborted."
                )
        else:
            report.note(
                f"Connected without pairing, but a later step exceeded the hard "
                f"deadline ({hard_deadline:g}s) and was aborted; results may be partial."
            )
    except Exception as exc:  # noqa: BLE001
        result, detail = ble.classify_error(exc)
        if not ctx.connected_unpaired:
            ctx.connect_error = detail
            ctx.connect_error_class = result
            if verbose:
                if result.is_security_refusal:
                    console.ok(f"Device demanded authentication: {detail}")
                else:
                    console.error(f"Connection failed: {detail}")
        else:
            report.note(
                f"Connected without pairing, but a later step failed ({detail}); "
                "results may be partial."
            )
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=5.0)
        except Exception:  # noqa: BLE001
            pass

    # Run every check.
    for _name, fn in CHECKS:
        report.findings.extend(fn(ctx))

    report.data = {
        "address": ctx.address,
        "adapter": args.adapter,
        "connected_unpaired": ctx.connected_unpaired,
        "connect_error": ctx.connect_error or None,
        "connect_error_class": (
            ctx.connect_error_class.value if ctx.connect_error_class else None
        ),
        "mtu": ctx.mtu,
        "profile": ctx.profile.slug if ctx.profile else None,
        "address_type": ctx.scan_result.address_type.value if ctx.scan_result else None,
        "advertised_name": ctx.scan_result.name if ctx.scan_result else None,
        "service_count": len(ctx.services),
        "characteristic_count": sum(len(s["characteristics"]) for s in ctx.services),
        "write_probes": ctx.write_probes,
        "pairing": ctx.pairing_result,
        "services": ctx.services,
    }

    for note in ctx.skipped:
        report.note(note)
    if not args.probe_writes:
        report.note(
            "Write permissions were not exercised (--probe-writes does that). "
            "Write findings are marked inferred."
        )
    if not args.check_pairing:
        report.note(
            "Pairing was not attempted (--check-pairing does that). No verdict on "
            "association model or MITM protection."
        )

    return report


def render(report: Report, console: Console) -> None:
    data = report.data
    console.header("TARGET")
    console.kv("address", data["address"])
    if data.get("advertised_name"):
        console.kv("name", data["advertised_name"])
    if data.get("address_type"):
        console.kv("address type", data["address_type"])
    if data.get("profile"):
        console.kv("profile", data["profile"])

    console.write()
    if data["connected_unpaired"]:
        any_read_succeeded = any(
            c.get("read_result") == "success"
            for s in data.get("services", [])
            for c in s.get("characteristics", [])
        )
        if any_read_succeeded:
            console.write(
                "  " + console.red("VERDICT: ") +
                "connected and read data with no pairing, no authentication, no encryption."
            )
        else:
            console.write(
                "  " + console.yellow("VERDICT: ") +
                "connected with no pairing, no authentication, no encryption - but no "
                "characteristic read succeeded (either none were readable, or every "
                "read was refused)."
            )
            console.write(
                "           The link itself required nothing; whether that matters "
                "depends on what accepting an unauthenticated GATT connection exposes "
                "on this device. See the findings below for what was and was not "
                "reachable."
            )
    elif data.get("connect_error"):
        error_class = data.get("connect_error_class")
        if error_class in ("authentication-required", "encryption-required", "authorization-required"):
            console.write(
                "  " + console.green("VERDICT: ") +
                f"the device refused an unauthenticated peer ({data['connect_error']})."
            )
        else:
            console.write(
                "  " + console.yellow("VERDICT: ") +
                f"inconclusive - connection failed without a security-specific reason "
                f"({data['connect_error']})."
            )
            console.write(
                "           This can mean the device is out of range, its address "
                "rotated, or its link layer is silently dropping connections from "
                "this address (e.g. a filter accept list populated by a prior bond "
                "with another device). It is not evidence the device enforces "
                "authentication - rerun closer to the device, or after clearing any "
                "stale bond, before treating this as a pass."
            )

    if data["connected_unpaired"]:
        console.write()
        console.kv(
            "exposed", f"{data['service_count']} services, "
            f"{data['characteristic_count']} characteristics"
        )
        if data.get("mtu"):
            console.kv("ATT MTU", data["mtu"])
