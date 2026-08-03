"""`brat impersonate` - become the device.

Stands up the GATT tree from a profile as a live peripheral and logs everything
a connecting central sends. If the profile defines a `protocol:` block, frames
are decoded as they arrive and answered per the profile's emulation rules.

This is where a clone stops being a document and starts being a device. It is
also the practical way to learn an undocumented protocol: let the real client
connect to your clone and read what it says.

Transmits. Gated behind --confirm.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.console import Console
from ..core.consent import require_confirm
from ..core.findings import Confidence, Finding, Severity
from ..core.peripheral import RoguePeripheral, run_until_interrupt
from ..core.profile import load_profile
from ..core.report import Report


def load_blobs(specs: list[str] | None) -> dict[str, bytes]:
    """Parse --payload NAME=FILE arguments into named binary blobs."""
    blobs: dict[str, bytes] = {}
    for spec in specs or []:
        if "=" not in spec:
            raise ValueError(
                f"--payload expects NAME=FILE, got {spec!r} "
                "(the name is what {blob.NAME} refers to in a profile)"
            )
        name, _, path = spec.partition("=")
        data = Path(path).expanduser().read_bytes()
        blobs[name.strip()] = data
    return blobs


async def execute(args, console: Console) -> Report:
    profile = load_profile(args.profile)
    report = Report(command="impersonate", target=profile.slug)

    blobs = load_blobs(getattr(args, "payload", None))

    problems = profile.validate()
    if problems:
        console.warn(f"Profile '{profile.slug}' has issues:")
        for p in problems:
            console.bullet(p, indent=4)
        console.write()

    # Built before the confirmation prompt (construction does no I/O) so the
    # name quoted in the prompt is the one the radio will actually broadcast,
    # rather than a second, separately-computed guess at it.
    peripheral = RoguePeripheral(
        profile=profile,
        console=console,
        name_override=args.name,
        blobs=blobs,
        quiet=args.output != "text",
        adapter=args.adapter,
    )
    name = peripheral.advertised_name

    if not require_confirm(
        console,
        args.confirm,
        action="impersonate",
        detail=(
            f"advertise as {name!r} and serve {sum(len(s.characteristics) for s in profile.services)} "
            f"characteristic(s) from profile '{profile.slug}'"
        ),
        consequences=[
            f"put this machine on the air advertising the name {name!r}",
            "accept connections from any central in range, including devices "
            "belonging to other people",
            "log every byte those centrals send, which may include their "
            "credentials, identifiers, and personal data",
        ]
        + (
            ["answer connecting clients using the profile's emulation rules"]
            if profile.protocol_config
            else []
        ),
    ):
        report.data = {"confirmed": False, "profile": profile.slug}
        return report

    console.header("ROGUE PERIPHERAL")
    console.kv("profile", f"{profile.name} ({profile.slug})")
    console.kv("advertising as", name)
    # "contains", not "serving": this prints before the GATT server is built,
    # so it is the profile's inventory and not evidence anything registered.
    # BlueZ refuses Generic Access/Attribute, so the two genuinely differ on
    # almost every cloned profile - and labelling this "serving" made a
    # peripheral that registered only some of its services look healthy.
    # What was actually served is reported in the session summary.
    console.kv(
        "profile contains",
        f"{len(profile.services)} services, "
        f"{sum(len(s.characteristics) for s in profile.services)} characteristics",
    )
    if profile.protocol_config:
        engine = profile.protocol
        console.kv("protocol", f"{engine.name} ({len(engine.rules)} emulation rule(s))")
    else:
        console.kv("protocol", "none defined - frames will be logged raw")
    if blobs:
        console.kv("payloads", ", ".join(f"{k} ({len(v)}B)" for k, v in blobs.items()))

    await peripheral.build()
    for warning in peripheral.warnings:
        console.warn(warning)

    await peripheral.start()

    console.write()
    console.ok(f"Advertising as {name!r}. Waiting for a central to connect.")
    if args.duration:
        console.info(f"Will stop automatically after {args.duration:g}s.")
    console.info("Ctrl-C to stop.")
    console.write()
    console.rule("SESSION")

    await run_until_interrupt(peripheral, console, duration=args.duration)

    summary = peripheral.summary()
    report.data = {"confirmed": True, **summary}
    _add_findings(report, peripheral, profile)

    if args.session_log:
        path = Path(args.session_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary["session"], indent=2))
        console.write()
        console.ok(f"Session log written to {path}")
        report.data["session_log"] = str(path)
        report.note(
            "The session log contains raw bytes sent by the connecting client. "
            "Treat it as sensitive and review before sharing."
        )

    return report


def _add_findings(report: Report, peripheral: RoguePeripheral, profile) -> None:
    for err in peripheral.errors:
        report.note(
            "A response failed to build or send, so this session is incomplete "
            "and any absence of client activity below may be our fault rather "
            f"than the client's:\n{err}"
        )

    if not peripheral.ever_connected:
        report.note(
            "No central connected during this session, so nothing was demonstrated. "
            "If you expected a connection: make sure the real device is powered off "
            "or out of range, since clients generally prefer a known bonded peer."
        )
        return

    rx = peripheral.log.rx

    if not rx:
        # A central connected (service discovery, or a plain read) but never
        # wrote anything. That is still worth recording, but "sent data" would
        # be a false claim - keep this distinct from the write-confirmed case.
        report.findings.add(
            Finding(
                check="peripheral.impersonation-connected-only",
                title="A central connected to an impersonated device but sent nothing",
                severity=Severity.MEDIUM,
                target=peripheral.advertised_name,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"A client connected to a peripheral advertising the name "
                    f"{peripheral.advertised_name!r} and performed GATT operations "
                    "(discovery and/or reads) but never wrote anything, so no protocol "
                    "exchange was observed this session."
                ),
                evidence={"advertised_name": peripheral.advertised_name, "profile": profile.slug},
                remediation=(
                    "Re-run with the real client driving a normal interaction if a "
                    "write-based finding is needed."
                ),
            )
        )
        return

    report.findings.add(
        Finding(
            check="peripheral.impersonation-accepted",
            title="A central connected to an impersonated device and sent data",
            severity=Severity.CRITICAL,
            target=peripheral.advertised_name,
            confidence=Confidence.CONFIRMED,
            description=(
                f"A client connected to a peripheral advertising the name "
                f"{peripheral.advertised_name!r} and proceeded to interact with it, "
                f"sending {len(rx)} write(s). The client had no way to distinguish this "
                "machine from the real device, which means the advertised name and GATT "
                "structure are being treated as identity. They are not credentials - "
                "anyone can broadcast them."
            ),
            evidence={
                "advertised_name": peripheral.advertised_name,
                "profile": profile.slug,
                "writes_received": len(rx),
                "bytes_received": sum(len(e.data) for e in rx),
            },
            remediation=(
                "Authenticate the peripheral to the central cryptographically - bond "
                "with LE Secure Connections and verify the bond on reconnect, or carry "
                "a challenge-response in the application protocol keyed to a secret "
                "provisioned per device."
            ),
        )
    )

    # `frame_ok` requires both a successful protocol decode AND a valid
    # checksum - a protocol error or a bad-CRC frame is not "the client sent
    # a valid command", so it must not count toward this finding.
    decoded = [e for e in rx if e.frame_ok]
    if decoded and profile.protocol_config:
        report.findings.add(
            Finding(
                check="protocol.no-peripheral-authentication",
                title="Client sends protocol commands to an unauthenticated peripheral",
                severity=Severity.HIGH,
                target=profile.slug,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"{len(decoded)} frame(s) of the device's application protocol were "
                    "received and decoded. The client transmitted these without "
                    "establishing that the peripheral was genuine, so the application "
                    "protocol provides no peripheral authentication either."
                ),
                evidence={
                    "frames_decoded": len(decoded),
                    "first_frames": [e.decoded for e in decoded[:5]],
                },
                remediation=(
                    "Add mutual authentication to the application protocol so a client "
                    "can detect an impostor peripheral."
                ),
            )
        )

    # Only count entries that actually came from the emulation engine - a
    # plain GATT read reply (`origin == "read-reply"`) is not a protocol
    # response and must not inflate this finding.
    protocol_tx = [e for e in peripheral.log.tx if e.origin == "protocol-response"]

    # A notification BlueZ never transmitted, because no central had written
    # the CCCD, is not evidence of anything the client did. `update_value()`
    # cannot distinguish the two, so `delivered` is the only honest filter.
    undelivered = [e for e in protocol_tx if e.delivered is False]
    if undelivered and len(undelivered) == len(protocol_tx):
        report.note(
            f"All {len(protocol_tx)} protocol response(s) were built but never "
            "transmitted - no central had subscribed to the notify characteristic, "
            "so BlueZ dropped them. No claim can be made about how the client "
            "treats our responses until it subscribes."
        )
        protocol_tx = []
    else:
        protocol_tx = [e for e in protocol_tx if e.delivered is not False]

    if protocol_tx and profile.protocol_config:
        report.findings.add(
            Finding(
                check="protocol.attacker-responses-accepted",
                title="Peripheral's fabricated protocol responses were sent to the client",
                severity=Severity.HIGH,
                target=profile.slug,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The rogue peripheral answered the client using the profile's "
                    "emulation rules. Whether the client accepted and acted on these "
                    "responses was not verified this session - that requires observing "
                    "the client. What is confirmed is that the peripheral could produce "
                    "well-formed responses without the client ever authenticating it, so "
                    "responses are not authenticated or integrity-protected against a "
                    "peer that knows the frame format."
                ),
                evidence={"responses_sent": len(protocol_tx)},
                remediation=(
                    "Sign or MAC protocol responses with a key the peripheral proves it "
                    "holds, and bind them to a client-supplied nonce."
                ),
            )
        )


def render(report: Report, console: Console) -> None:
    data = report.data
    if not data.get("confirmed"):
        return

    session = data.get("session", {})
    console.header("SESSION SUMMARY")
    # Served counts, not profile counts - a mismatch against the header is the
    # signal that something did not register.
    if data.get("services_served") is not None:
        console.kv(
            "served",
            f"{data['services_served']} services, "
            f"{data.get('characteristics_served', 0)} characteristics",
        )
    console.kv("central connected", "yes" if data.get("connected") else "no")
    if session.get("connected_at"):
        console.kv("first activity", session["connected_at"])
    # A client that reconnects repeatedly and one that stays put are very
    # different sessions, and the timestamps alone do not distinguish them.
    if (count := data.get("connections", 0)) > 1:
        console.kv("connections", count)
    console.kv("frames received", session.get("received", 0))
    console.kv("frames sent", session.get("sent", 0))

    entries = session.get("entries", [])
    if entries:
        console.write()
        console.table(
            ["TIME", "DIR", "LEN", "DECODED"],
            [
                [
                    e["timestamp"],
                    "->" if e["direction"] == "rx" else "<-",
                    str(e["length"]),
                    (e["decoded"] or e["label"] or "")[:60],
                ]
                for e in entries
            ],
        )
