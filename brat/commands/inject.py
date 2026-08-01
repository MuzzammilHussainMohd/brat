"""`brat inject` - feed a client data it did not ask for.

Runs the same rogue peripheral as `brat impersonate`, plus an injection rule:
when the client sends a chosen command, reply with attacker-controlled content
instead of (or in addition to) whatever the profile's normal rules would send.

Injection is expressed as an extra emulation rule built at runtime, so it goes
through exactly the same framing and checksum machinery as any profile rule.
Nothing here is device-specific.

An important honesty constraint: this command can prove a client *accepted and
parsed* injected data. It cannot, from the peripheral side, prove what the
client then did with it - whether it was displayed, stored, or forwarded to a
backend. Findings are worded to that limit. To establish downstream effects you
need to observe the client, which is a separate exercise.

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
from ..core.protocol import EmulationRule, ResponseSpec, as_int
from ..core.report import Report
from .impersonate import load_blobs


def build_injection_rule(args, profile) -> EmulationRule:
    """Turn the injection CLI options into an emulation rule."""
    engine = profile.protocol
    if engine is None:
        raise ValueError(
            f"profile '{profile.slug}' defines no `protocol:` block, so there are no "
            "frames to react to. Use `brat impersonate` to capture a session first, "
            "then add a protocol block."
        )

    on_cmd = as_int(args.on_cmd) if args.on_cmd is not None else None
    if on_cmd is None and not args.push:
        raise ValueError("choose a trigger: --on-cmd HEX, or --push to send unprompted")

    responses: list[ResponseSpec] = []

    if args.inject_raw is not None:
        responses.append(
            ResponseSpec(delay=args.delay, raw=args.inject_raw, label="injected-raw")
        )
    elif args.inject is not None:
        cmd = as_int(args.as_cmd) if args.as_cmd is not None else on_cmd
        if cmd is None:
            raise ValueError("--inject needs --as-cmd when used with --push")
        # Use whatever field names this profile's frame actually declares for
        # command/payload (default "cmd"/"payload", but a profile can rename
        # them via `protocol.roles`) - hardcoding "cmd"/"payload" here would
        # silently build a frame with the wrong fields set to None for any
        # profile that renamed them.
        fields = {
            engine.codec.command_field: cmd,
            engine.codec.payload_field: args.inject,
        }
        if args.direction is not None:
            fields["direction"] = as_int(args.direction)
        responses.append(
            ResponseSpec(delay=args.delay, fields=fields, label="injected")
        )
    else:
        raise ValueError("nothing to inject: pass --inject TEMPLATE or --inject-raw TEMPLATE")

    if args.repeat > 1:
        base = responses[0]
        responses = [
            ResponseSpec(
                delay=base.delay if i == 0 else args.interval,
                raw=base.raw,
                fields=dict(base.fields),
                label=f"{base.label}[{i + 1}/{args.repeat}]",
            )
            for i in range(args.repeat)
        ]

    return EmulationRule(
        name="injection",
        on_cmd=on_cmd,
        on_any=bool(args.push and on_cmd is None),
        responses=responses,
        description="runtime injection rule from brat inject",
    )


async def execute(args, console: Console) -> Report:
    profile = load_profile(args.profile)
    report = Report(command="inject", target=profile.slug)

    blobs = load_blobs(args.payload)
    rule = build_injection_rule(args, profile)

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
    engine = profile.protocol

    trigger = (
        f"command 0x{rule.on_cmd:02X} ({engine.command_name(rule.on_cmd)})"
        if rule.on_cmd is not None
        else "any decoded frame"
    )

    if not require_confirm(
        console,
        args.confirm,
        action="inject",
        detail=(
            f"advertise as {name!r} from profile '{profile.slug}' and, on {trigger}, "
            f"send {len(rule.responses)} attacker-controlled frame(s)"
        ),
        consequences=[
            f"put this machine on the air advertising the name {name!r}",
            "accept connections from any central in range",
            "send fabricated protocol data to whatever connects, which that client "
            "may parse, display, store, or forward to a backend",
            "log everything the client sends, including any personal data in it",
        ],
    ):
        report.data = {"confirmed": False, "profile": profile.slug}
        return report

    # Injection is appended, so the profile's own handshake rules still run and
    # the client reaches the state where the injected frame makes sense.
    engine.rules.append(rule)

    console.header("ROGUE PERIPHERAL + INJECTION")
    console.kv("profile", f"{profile.name} ({profile.slug})")
    console.kv("advertising as", name)
    console.kv("protocol", engine.name)
    console.kv("normal rules", len(engine.rules) - 1)
    console.kv("injection trigger", trigger)
    console.kv("injected frames", len(rule.responses))
    if blobs:
        console.kv("payloads", ", ".join(f"{k} ({len(v)}B)" for k, v in blobs.items()))

    await peripheral.build()
    for warning in peripheral.warnings:
        console.warn(warning)
    await peripheral.start()

    console.write()
    console.ok(f"Advertising as {name!r}. Waiting for a client.")
    console.info("Ctrl-C to stop.")
    console.write()
    console.rule("SESSION")

    await run_until_interrupt(peripheral, console, duration=args.duration)

    summary = peripheral.summary()
    injected = [e for e in peripheral.log.tx if (e.label or "").startswith("injected")]

    report.data = {
        "confirmed": True,
        "trigger": trigger,
        "injected_frames": len(injected),
        "injected_bytes": sum(len(e.data) for e in injected),
        **summary,
    }

    _add_findings(report, peripheral, profile, injected)

    if args.session_log:
        path = Path(args.session_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary["session"], indent=2))
        console.write()
        console.ok(f"Session log written to {path}")
        report.data["session_log"] = str(path)

    return report


def _add_findings(report: Report, peripheral, profile, injected: list) -> None:
    if not peripheral.connected:
        report.note("No client connected; nothing was injected.")
        return

    if not injected:
        report.note(
            "A client connected but the trigger never fired, so no data was injected. "
            "Check that the trigger command matches what the client actually sends - "
            "the session log above shows every frame received."
        )
        return

    # What we can prove: the client stayed in the exchange after receiving
    # fabricated data. What we cannot prove from here: what it did with it.
    # Compare by `seq` (insertion order), not `timestamp` - the timestamp is a
    # bare HH:MM:SS string with no date, so a session crossing midnight would
    # make every post-injection frame compare as earlier and silently drop
    # this to a false "client sent nothing further".
    frames_after = [e for e in peripheral.log.rx if e.seq > injected[0].seq]

    report.findings.add(
        Finding(
            check="protocol.data-injection-accepted",
            title="Client accepted fabricated data from an unauthenticated peripheral",
            severity=Severity.CRITICAL if frames_after else Severity.HIGH,
            target=profile.slug,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{len(injected)} attacker-controlled frame(s) were sent to the client. "
                + (
                    f"The client continued the exchange afterwards, sending {len(frames_after)} "
                    "further frame(s), which shows the data was parsed and accepted rather "
                    "than rejected."
                    if frames_after
                    else "The client did not visibly reject the data, though it also sent "
                    "nothing further, so acceptance is not conclusively established."
                )
                + " The protocol carries no integrity or origin authentication that would "
                "let a client tell fabricated readings from genuine ones."
            ),
            evidence={
                "injected_frames": len(injected),
                "injected_bytes": sum(len(e.data) for e in injected),
                "client_frames_after_injection": len(frames_after),
            },
            remediation=(
                "Authenticate the peripheral and integrity-protect every data frame - "
                "sign readings with a per-device key, and bind them to a client nonce so "
                "they cannot be replayed."
            ),
        )
    )

    report.note(
        "This command observes the radio only. It establishes that the client accepted "
        "the injected frames; it does not establish what the client did with them "
        "afterwards - display, local storage, or upload to a backend must be confirmed "
        "by observing the client itself."
    )


def render(report: Report, console: Console) -> None:
    from .impersonate import render as render_impersonate

    data = report.data
    if not data.get("confirmed"):
        return

    console.header("INJECTION")
    console.kv("trigger", data.get("trigger"))
    console.kv("frames injected", data.get("injected_frames", 0))
    console.kv("bytes injected", data.get("injected_bytes", 0))

    render_impersonate(report, console)
