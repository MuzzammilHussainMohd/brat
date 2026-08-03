"""`brat drive` - connect to a real device and issue protocol commands.

The mirror image of `impersonate`/`inject`. Those become the device and wait
for a client; this becomes the *client* - a rogue central - and drives the real
device directly. No app, no phone, no pairing: connect, write a correctly
framed command, read what comes back.

This is where a missing authentication requirement stops being a property of a
GATT permission table and becomes a thing the device does. `posture` can tell
you the command characteristic is writable by anyone; only this can tell you
what the device does when someone writes to it.

What it can prove, and how:

* The device *processed* a command from an unauthenticated peer - established
  when it answers with a well-formed frame of its own protocol. A device that
  ignores unauthorised input does not reply to it.

* The device *changed state* because of that command - established by sending
  the same read-back command before and after and comparing the two replies.
  Nothing here knows which command is a read and which is a write, so it does
  not guess: it reports a state change only when it has a before and an after
  that differ, and names the command that ran between them.

The second is the finding worth having, and it is why the sequence form exists:

    brat drive -p dev -a AA:.. --send 30 --send 20:00 --send 30 --confirm
                                        ^read      ^act    ^read again

Transmits, and unlike `impersonate` it transmits *at a specific device you
named*. Gated behind --confirm.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bleak import BleakClient

from ..core import ble
from ..core.ble import GattResult
from ..core.console import Console
from ..core.consent import require_confirm
from ..core.findings import Confidence, Finding, Severity
from ..core.profile import load_profile
from ..core.protocol import Frame, ProtocolEngine, as_int, parse_hex
from ..core.report import Report

# A peripheral that requires bonding does not necessarily answer an unpaired
# operation with an ATT error. Against BlueZ the usual outcome is that the host
# starts pairing on the peripheral's behalf, cannot finish it without a
# passkey, and the call simply never returns - the connection stays up and the
# operation hangs indefinitely. Every BlueZ call here is therefore bounded, or
# a correctly-secured device would hang the tool instead of being reported as
# secure. `posture` treats the same stall as enforcement evidence for the same
# reason; see `_reads_stalled_on_a_live_link` there.
_OP_DEADLINE = 10.0


def _stalled(result: GattResult | None) -> bool:
    """Whether an operation neither succeeded nor gave a reason for failing."""
    return result in (GattResult.TIMEOUT, GattResult.DISCONNECTED)


@dataclass
class Step:
    """One command to send, and whatever came back."""

    cmd: int
    payload: bytes
    label: str

    sent: bytes = b""
    write_result: GattResult | None = None
    write_detail: str = ""
    replies: list[bytes] = field(default_factory=list)
    decoded: list[Frame | None] = field(default_factory=list)

    @property
    def answered(self) -> bool:
        return bool(self.replies)

    def reply_payloads(self) -> list[bytes]:
        """Payload of every reply that decoded as this protocol."""
        return [f.payload for f in self.decoded if f is not None]

    def to_dict(self, engine: ProtocolEngine) -> dict:
        return {
            "cmd": f"0x{self.cmd:02X}",
            "cmd_name": engine.command_name(self.cmd),
            "payload": self.payload.hex(),
            "sent": self.sent.hex(),
            "write_result": self.write_result.value if self.write_result else None,
            "write_detail": self.write_detail or None,
            "replies": [r.hex() for r in self.replies],
            "decoded": [
                {
                    "cmd": f"0x{f.cmd:02X}" if f.cmd is not None else None,
                    "cmd_name": engine.command_name(f.cmd),
                    "payload": f.payload.hex(),
                    "checksum_ok": f.checksum_ok,
                    "summary": engine.describe(f),
                }
                for f in self.decoded
                if f is not None
            ],
            "undecodable_replies": sum(1 for f in self.decoded if f is None),
        }


def parse_steps(args) -> list[Step]:
    """Build the command sequence from the CLI options.

    Two forms, because the common case deserves to read well and the
    interesting case needs ordering:

        --cmd 0x20 --payload 00          one command
        --send 30 --send 20:00 --send 30 a sequence, in order
    """
    steps: list[Step] = []

    for spec in args.send or []:
        cmd_text, _, payload_text = str(spec).partition(":")
        if not cmd_text.strip():
            raise ValueError(f"--send {spec!r}: no command byte before the ':'")
        steps.append(
            Step(
                cmd=as_int(cmd_text.strip()),
                payload=parse_hex(payload_text),
                label=str(spec),
            )
        )

    if args.cmd is not None:
        cmd = as_int(args.cmd)
        payload = parse_hex(args.payload)
        steps.append(
            Step(
                cmd=cmd,
                payload=payload,
                label=f"{args.cmd}" + (f":{payload.hex()}" if payload else ""),
            )
        )
    elif args.payload:
        raise ValueError("--payload needs --cmd to say which command carries it")

    if not steps:
        raise ValueError(
            "nothing to send: pass --cmd HEX [--payload HEX], or --send CMD[:PAYLOAD] "
            "one or more times to run a sequence"
        )
    return steps


def diff_bytes(before: bytes, after: bytes) -> list[dict]:
    """Which byte offsets differ, and how.

    A state change usually moves one or two bytes in a payload of eight, and
    which ones they are is the whole story - it is the difference between "the
    reading changed" and "the alarm flag changed while the reading did not".
    Nothing here knows what any offset means; naming the offset is enough for
    a reader with the payload layout in front of them, and it is what turns two
    hex blobs into a finding someone can act on.
    """
    changed: list[dict] = []
    for offset in range(max(len(before), len(after))):
        old = before[offset : offset + 1]
        new = after[offset : offset + 1]
        if old != new:
            changed.append(
                {
                    "offset": offset,
                    "before": old.hex() if old else None,
                    "after": new.hex() if new else None,
                }
            )
    return changed


def find_state_changes(steps: list[Step], engine: ProtocolEngine) -> list[dict]:
    """Commands whose replies changed after some other command ran.

    A device that answers the same question with two different answers changed
    state in between. That is the whole inference, and it is why this needs no
    knowledge of what any particular command means: the device's own read-back
    is the witness.

    Only the *first* differing pair is reported per command, and only when at
    least one other command ran between them - two consecutive identical reads
    that differ are a device whose value drifts on its own (a sensor, a
    counter, a clock), which is not evidence that anything we sent did it.
    """
    changes: list[dict] = []

    by_cmd: dict[int, list[int]] = {}
    for i, step in enumerate(steps):
        by_cmd.setdefault(step.cmd, []).append(i)

    for cmd, indexes in by_cmd.items():
        if len(indexes) < 2:
            continue
        for first, second in zip(indexes, indexes[1:]):
            between = [s for s in steps[first + 1 : second] if s.cmd != cmd]
            if not between:
                continue
            before = steps[first].reply_payloads()
            after = steps[second].reply_payloads()
            if not before or not after:
                continue
            if before[-1] == after[-1]:
                continue
            changes.append(
                {
                    "probe_cmd": f"0x{cmd:02X}",
                    "probe_cmd_name": engine.command_name(cmd),
                    "before": before[-1].hex(),
                    "after": after[-1].hex(),
                    "changed_bytes": diff_bytes(before[-1], after[-1]),
                    "caused_by": [
                        {
                            "cmd": f"0x{s.cmd:02X}",
                            "cmd_name": engine.command_name(s.cmd),
                            "payload": s.payload.hex(),
                        }
                        for s in between
                    ],
                }
            )
            break  # one witness per command is enough

    return changes


async def run_sequence(
    client: BleakClient,
    engine: ProtocolEngine,
    steps: list[Step],
    console: Console,
    wait: float,
    gap: float,
    quiet: bool,
    op_timeout: float = _OP_DEADLINE,
) -> bool:
    """Write each frame in turn, collecting whatever the device notifies back.

    Returns whether the notify subscription was established. A device that
    demands encryption will stall it, which is a result rather than an error:
    the sequence still runs so the writes get their own verdicts.
    """
    inbox: list[bytes] = []
    listening = False

    def on_notify(_char, data: bytearray) -> None:
        inbox.append(bytes(data))

    if engine.notify_uuid:
        try:
            await asyncio.wait_for(
                client.start_notify(engine.notify_uuid, on_notify), timeout=op_timeout
            )
            listening = True
        except (TimeoutError, asyncio.TimeoutError):
            if not quiet:
                console.warn(
                    f"subscribing to {engine.notify_uuid} stalled after {op_timeout:g}s "
                    "- the device is most likely demanding pairing to enable "
                    "notifications."
                )
        except Exception as exc:  # noqa: BLE001
            result, detail = ble.classify_error(exc)
            if not quiet:
                console.warn(f"could not subscribe for replies: {result.value}: {detail}")
    elif not quiet:
        console.warn(
            "profile declares no protocol.transport.notify_uuid, so replies cannot be "
            "collected - commands will be sent blind"
        )

    for index, step in enumerate(steps):
        # A peripheral that refuses an unauthenticated operation may answer by
        # dropping the link rather than returning an ATT error - failed pairing
        # tears the connection down. Once that has happened every later call
        # fails for a reason that describes our dead client rather than the
        # device ("Service Discovery has not been performed yet"), which is how
        # a device enforcing correctly ends up reported as an unknown error.
        # Check liveness first so the disconnect is recorded as what it is.
        if not client.is_connected:
            step.write_result = GattResult.DISCONNECTED
            step.write_detail = "link was already down before this command was sent"
            if not quiet:
                console.write()
                console.warn(
                    f"[{index + 1}/{len(steps)}] skipped - the device closed the "
                    "connection, which is how a peripheral demanding pairing "
                    "commonly refuses."
                )
            continue

        frame = engine.codec.build(
            {
                engine.codec.command_field: step.cmd,
                engine.codec.payload_field: step.payload,
            }
        )
        step.sent = frame
        inbox.clear()

        if not quiet:
            console.write()
            console.step(
                f"[{index + 1}/{len(steps)}] "
                f"0x{step.cmd:02X} {engine.command_name(step.cmd)}"
                + (f"  payload={step.payload.hex()}" if step.payload else "")
            )
            console.kv("write", frame.hex(), 6)

        try:
            await asyncio.wait_for(
                client.write_gatt_char(engine.write_uuid, frame, response=True),
                timeout=op_timeout,
            )
            step.write_result = GattResult.SUCCESS
        except (TimeoutError, asyncio.TimeoutError):
            step.write_result = GattResult.TIMEOUT
            step.write_detail = (
                f"no response within {op_timeout:g}s on a live connection"
            )
            if not quiet:
                console.kv("stalled", step.write_detail, 6)
            continue
        except Exception as exc:  # noqa: BLE001
            step.write_result, step.write_detail = ble.classify_error(exc)
            # bleak reports operations on a torn-down client as its own internal
            # state problem. Ask the link, not the message: if it is down, the
            # device disconnected us, and that is the finding.
            if not client.is_connected:
                step.write_result = GattResult.DISCONNECTED
                step.write_detail = f"device closed the connection ({step.write_detail})"
            if not quiet:
                console.kv("refused", f"{step.write_result.value}: {step.write_detail}", 6)
            # A security refusal is the device doing its job; keep going so the
            # rest of the sequence still runs and the report covers all of it.
            continue

        if listening:
            await asyncio.sleep(wait)

        step.replies = list(inbox)
        step.decoded = [engine.decode(r) for r in step.replies]

        if not quiet:
            if not step.replies:
                console.kv("reply", "(none)", 6)
            for raw, decoded in zip(step.replies, step.decoded):
                if decoded is None:
                    console.kv("reply", f"{raw.hex()}  (does not decode)", 6)
                else:
                    console.kv("reply", raw.hex(), 6)
                    console.kv("", engine.describe(decoded), 6)
                    if decoded.payload:
                        console.kv("", f"payload={decoded.payload.hex()}", 6)

        if gap and index < len(steps) - 1:
            await asyncio.sleep(gap)

    if listening:
        try:
            await asyncio.wait_for(
                client.stop_notify(engine.notify_uuid), timeout=op_timeout
            )
        except Exception:  # noqa: BLE001, S110
            pass  # the link may already be gone; nothing here depends on it

    return listening


async def execute(args, console: Console) -> Report:
    profile = load_profile(args.profile)
    report = Report(command="drive", target=args.address)

    engine = profile.protocol
    if engine is None:
        raise ValueError(
            f"profile '{profile.slug}' defines no `protocol:` block, so there are no "
            "frames to send. Capture a session with `brat impersonate --session-log`, "
            "draft a block with `brat protocol infer`, and add it to the profile."
        )
    if not engine.write_uuid:
        raise ValueError(
            f"profile '{profile.slug}' declares no protocol.transport.write_uuid, so "
            "there is nowhere to send commands. Add one to the profile's protocol block."
        )

    steps = parse_steps(args)
    quiet = args.output != "text"

    listed = ", ".join(
        f"0x{s.cmd:02X} ({engine.command_name(s.cmd)})" for s in steps
    )
    if not require_confirm(
        console,
        args.confirm,
        action="drive",
        detail=(
            f"connect to {args.address} and send {len(steps)} protocol command(s) "
            f"as an unauthenticated central: {listed}"
        ),
        consequences=[
            f"open a BLE connection to {args.address} without pairing",
            "write attacker-chosen command frames to the device's command "
            "characteristic, which the device may act on",
            "change device state, if any command sent does so - this drives real "
            "hardware, not a simulation of it",
        ],
    ):
        report.data = {"confirmed": False, "profile": profile.slug}
        return report

    if not quiet:
        console.header("ROGUE CENTRAL")
        console.kv("profile", f"{profile.name} ({profile.slug})")
        console.kv("target", args.address)
        console.kv("protocol", engine.name)
        console.kv("write to", engine.write_uuid)
        console.kv("listen on", engine.notify_uuid or "(none declared)")
        console.kv("sequence", f"{len(steps)} command(s)")
        console.write()
        console.info(f"Connecting to {args.address} ...")

    device = await ble.find_device(args.address, timeout=args.timeout, adapter=args.adapter)
    if device is None:
        report.note(
            f"{args.address} was not seen while scanning. It may be out of range, "
            "powered off, or already connected to something else."
        )
        report.data = {"confirmed": True, "profile": profile.slug, "connected": False}
        return report

    paired_before = bool(getattr(device, "details", {}).get("props", {}).get("Paired"))

    async with BleakClient(device, timeout=args.timeout) as client:
        if not quiet:
            console.ok(f"Connected to {args.address} (no pairing performed).")
            console.write()
            console.rule("SEQUENCE")

        listening = await run_sequence(
            client,
            engine,
            steps,
            console,
            wait=args.wait,
            gap=args.gap,
            quiet=quiet,
            op_timeout=args.op_timeout,
        )

    changes = find_state_changes(steps, engine)

    answered = [s for s in steps if s.answered]
    refused = [
        s for s in steps
        if s.write_result is not None and s.write_result.is_security_refusal
    ]
    stalled = [s for s in steps if _stalled(s.write_result)]
    dropped = [s for s in steps if s.write_result is GattResult.DISCONNECTED]

    report.data = {
        "confirmed": True,
        "profile": profile.slug,
        "address": args.address,
        "connected": True,
        "paired_before": paired_before,
        "protocol": engine.name,
        "subscribed_for_replies": listening,
        "commands_sent": len(steps),
        "commands_answered": len(answered),
        "commands_refused": len(refused),
        "commands_stalled": len(stalled) - len(dropped),
        "commands_dropped": len(dropped),
        "state_changes": changes,
        "steps": [s.to_dict(engine) for s in steps],
    }

    _add_findings(
        report, args.address, engine, steps, changes, refused, stalled,
        paired_before, listening,
    )

    if args.session_log:
        path = Path(args.session_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.data, indent=2))
        if not quiet:
            console.write()
            console.ok(f"Session log written to {path}")
        report.data["session_log"] = str(path)

    return report


def _add_findings(
    report: Report,
    address: str,
    engine: ProtocolEngine,
    steps: list[Step],
    changes: list[dict],
    refused: list[Step],
    stalled: list[Step],
    paired_before: bool,
    listening: bool,
) -> None:
    answered = [s for s in steps if s.answered]

    if paired_before:
        report.note(
            "This host already has a bond with the target, so the link may have been "
            "encrypted using stored keys. Remove the pairing "
            "(`bluetoothctl remove <addr>`) and re-run to test what an unbonded "
            "attacker can do."
        )

    if (refused or stalled) and not answered:
        # An explicit ATT security error is proof. A stall is not - it is the
        # signature of BlueZ starting pairing on the peripheral's behalf and
        # being unable to finish it, which is what a device demanding a passkey
        # looks like from here, but it is also what an unresponsive device
        # looks like. Say which one this was rather than flattening both into
        # the same confidence.
        blocked = refused + stalled
        timed_out = [s for s in stalled if s.write_result is GattResult.TIMEOUT]
        dropped = [s for s in stalled if s.write_result is GattResult.DISCONNECTED]
        report.findings.add(
            Finding(
                check="protocol.commands-refused",
                title="Device refused protocol commands from an unauthenticated peer",
                severity=Severity.INFO,
                target=address,
                confidence=Confidence.CONFIRMED if refused else Confidence.INFERRED,
                description=(
                    f"None of the {len(steps)} command(s) sent were accepted. "
                    + (
                        f"{len(refused)} were refused at the ATT layer with an explicit "
                        "security error. "
                        if refused
                        else ""
                    )
                    + (
                        f"{len(dropped)} could not be sent because the device closed the "
                        "connection. Tearing down the link is how a peripheral that "
                        "requires bonding commonly refuses an unauthenticated peer: "
                        "BlueZ begins pairing on the device's behalf, cannot finish it "
                        "without a passkey, and the device drops the connection rather "
                        "than answering. "
                        if dropped
                        else ""
                    )
                    + (
                        f"{len(timed_out)} never completed on a connection that stayed "
                        "up, which is the same refusal seen as a stall rather than a "
                        "disconnect. "
                        if timed_out
                        else ""
                    )
                    + (
                        "That is strong but indirect evidence - an unresponsive or "
                        "out-of-range device looks the same from here. "
                        if not refused
                        else ""
                    )
                    + "The device requires an authenticated or encrypted link before it "
                    "will accept application-layer commands, which is the behaviour you "
                    "want."
                ),
                evidence={
                    "blocked": [
                        {
                            "cmd": f"0x{s.cmd:02X}",
                            "cmd_name": engine.command_name(s.cmd),
                            "result": s.write_result.value if s.write_result else None,
                            "detail": s.write_detail or None,
                        }
                        for s in blocked
                    ],
                    "explicit_att_refusals": len(refused),
                    "device_closed_connection": len(dropped),
                    "stalled_on_live_link": len(timed_out),
                    "subscribed_for_replies": listening,
                },
            )
        )
        if stalled and not refused:
            observed = "a disconnect" if dropped else "a stall"
            report.note(
                f"The refusal was observed as {observed} rather than an ATT error code. "
                "To see the device's own reason, watch the exchange with "
                f"`btmon` while this runs, or pair first (`bluetoothctl` -> "
                "`pair <addr>`) and re-run to confirm the same commands succeed once "
                "bonded."
            )
        return

    # The strong result: the device's own read-back changed after a command we
    # sent. Nothing about this depends on knowing what the command means.
    for change in changes:
        causes = ", ".join(
            f"{c['cmd']} ({c['cmd_name']})" for c in change["caused_by"]
        )
        moved = ", ".join(
            f"byte {b['offset']} {b['before']}->{b['after']}"
            for b in change["changed_bytes"]
        )
        report.findings.add(
            Finding(
                check="protocol.unauthenticated-state-change",
                title="An unauthenticated command changed device state",
                severity=Severity.CRITICAL,
                target=address,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"Reading {change['probe_cmd']} ({change['probe_cmd_name']}) before "
                    f"and after sending {causes} returned different values: "
                    f"{change['before']} became {change['after']} ({moved}). "
                    "No pairing, bonding, or application-layer credential was presented "
                    "at any point. The device accepted a state-changing command purely "
                    "because it was correctly framed, so anyone in radio range can "
                    "issue it."
                ),
                evidence=change,
                remediation=(
                    "Require an encrypted, authenticated link (LE Secure Connections "
                    "with MITM protection) before accepting any command that changes "
                    "state, and enforce it at the ATT layer via characteristic "
                    "permissions rather than in application code."
                ),
                references=[
                    "Bluetooth Core Spec, Vol 3, Part C, 10.3 (Security Modes)",
                ],
            )
        )

    if answered and not changes:
        report.findings.add(
            Finding(
                check="protocol.unauthenticated-command-accepted",
                title="Device answers protocol commands from an unauthenticated peer",
                severity=Severity.HIGH,
                target=address,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"{len(answered)} of {len(steps)} command(s) were answered with a "
                    "well-formed frame of the device's own protocol, over a link that "
                    "was never paired or encrypted. Replying means the device parsed "
                    "and processed the command rather than discarding it, so the "
                    "command channel is reachable by anyone in radio range. This run "
                    "did not demonstrate a state change - send a read-back command "
                    "before and after a state-changing one to establish that."
                ),
                evidence={
                    "commands_answered": [
                        {
                            "cmd": f"0x{s.cmd:02X}",
                            "cmd_name": engine.command_name(s.cmd),
                            "replies": len(s.replies),
                        }
                        for s in answered
                    ]
                },
                remediation=(
                    "Require an encrypted, authenticated link before accepting "
                    "application-layer commands, enforced through characteristic "
                    "permissions."
                ),
            )
        )

    accepted = [s for s in steps if s.write_result is GattResult.SUCCESS]
    if not answered and accepted:
        # Only claim the writes landed for the ones that actually returned
        # success. Saying "the writes were accepted" about a run where every
        # write errored inverts the result of the test.
        report.note(
            f"{len(accepted)} of {len(steps)} command(s) were written successfully but "
            "nothing came back"
            + ("" if listening else " (no notify subscription was established)")
            + ". The device may not reply on the notify characteristic this profile "
            "declares, or may need a longer --wait."
        )
    elif not answered and not accepted and not refused and not stalled:
        report.note(
            "No command was accepted, and none failed for a reason that indicates the "
            "device refused it. Check that the write characteristic in the profile's "
            "protocol.transport block is the one this device actually uses."
        )

    report.note(
        "Findings describe what the device did on the radio. Where a physical effect "
        "is claimed (an alarm silenced, a valve opened), confirm it by observing the "
        "device itself - the reply frame is the device's own account of its state."
    )


def render(report: Report, console: Console) -> None:
    data = report.data
    if not data.get("confirmed"):
        return
    if not data.get("connected"):
        console.header("ROGUE CENTRAL")
        console.warn(f"{data.get('address')} was not reachable.")
        return

    console.header("RESULT")
    console.kv("target", data["address"])
    console.kv("commands sent", data["commands_sent"])
    console.kv("answered", data["commands_answered"])
    if data["commands_refused"]:
        console.kv("refused (security)", data["commands_refused"])
    if data.get("commands_stalled"):
        console.kv("stalled on live link", data["commands_stalled"])
    if data.get("commands_dropped"):
        console.kv("device closed the link", data["commands_dropped"])

    rows = []
    for step in data["steps"]:
        reply = step["decoded"][0]["payload"] if step["decoded"] else "-"
        rows.append(
            [
                step["cmd"],
                step["cmd_name"],
                step["payload"] or "-",
                step["write_result"] or "-",
                reply or "(empty)",
            ]
        )
    console.write()
    console.table(["CMD", "NAME", "SENT", "WRITE", "REPLY PAYLOAD"], rows)

    if data["state_changes"]:
        console.header("STATE CHANGE PROVEN")
        for change in data["state_changes"]:
            console.write()
            causes = ", ".join(
                f"{c['cmd']} ({c['cmd_name']})" for c in change["caused_by"]
            )
            console.kv("probe", f"{change['probe_cmd']} ({change['probe_cmd_name']})")
            console.kv("before", change["before"])
            console.kv("after", console.bold(change["after"]))
            for b in change["changed_bytes"]:
                console.kv(
                    f"  byte {b['offset']}",
                    f"{b['before']} -> {console.bold(str(b['after']))}",
                )
            console.kv("caused by", causes)
