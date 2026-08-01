"""`brat enum` - connect and walk the full GATT tree.

Recon, not judgement: this prints what is there. Anything it notices that is
security-relevant is emitted as INFO or LOW and pointed at `brat posture`,
which is the command that actually decides whether a device is doing its job.

The one thing worth stating loudly here is whether the connection succeeded
without pairing at all, because everything below it in the output is a
consequence of that.
"""

from __future__ import annotations

import asyncio

from bleak import BleakClient

from ..core import ble
from ..core import secrets as secret_scan
from ..core.console import Console
from ..core.findings import Confidence, Finding, Severity
from ..core.report import Report
from ..core.uuids import label as uuid_label
from ..core.uuids import risk_for

# Properties that let a peer change device state.
_WRITE_PROPS = {"write", "write-without-response", "authenticated-signed-writes"}

# See core/ble.py - a stated timeout does not reliably bound a stuck D-Bus
# call, so connect+enumerate gets its own hard wall-clock deadline here too.
_HARD_DEADLINE_MARGIN = 15.0


async def collect(
    address: str,
    read_values: bool = False,
    timeout: float = 20.0,
    adapter: str | None = None,
    console: Console | None = None,
) -> dict:
    """Connect, enumerate, disconnect."""
    try:
        device = await ble.find_device(address, timeout=min(timeout, 15.0), adapter=adapter)
    except Exception:  # noqa: BLE001 - fall back to connecting by address directly
        device = None
    target = device or address

    if console:
        console.info(f"Connecting to {address} ...")

    client_kwargs = {"timeout": timeout}
    if adapter:
        client_kwargs["adapter"] = adapter
    client = BleakClient(target, **client_kwargs)

    async def _collect() -> dict:
        await client.connect()
        if console:
            console.ok("Connected without pairing.")

        services = await ble.enumerate_gatt(client, read_values=read_values)

        return {
            "address": address,
            "connected_unpaired": True,
            "mtu": getattr(client, "mtu_size", None),
            "services": [s.to_dict() for s in services],
        }

    try:
        return await asyncio.wait_for(_collect(), timeout=timeout + _HARD_DEADLINE_MARGIN)
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=5.0)
        except Exception:  # noqa: BLE001 - teardown must not mask the result
            pass


async def execute(args, console: Console) -> Report:
    report = Report(command="enum", target=args.address)

    try:
        info = await collect(
            args.address,
            read_values=args.read_values,
            timeout=args.timeout,
            adapter=args.adapter,
            console=console if args.output == "text" else None,
        )
    except Exception as exc:  # noqa: BLE001
        result, detail = ble.classify_error(exc)
        report.data = {
            "address": args.address,
            "connected_unpaired": False,
            "error": detail,
            "error_class": result.value,
            "services": [],
        }
        if result.is_security_refusal:
            report.findings.add(
                Finding(
                    check="link.connect-refused",
                    title="Device refused an unauthenticated connection",
                    severity=Severity.INFO,
                    target=args.address,
                    description=(
                        "The peripheral required authentication before allowing GATT "
                        "access. That is the correct behaviour."
                    ),
                    evidence={"error": detail},
                )
            )
        report.note(f"Enumeration did not complete: {detail}")
        return report

    counts = _summarize(info)
    info.update(counts)
    report.data = info
    _add_findings(report, info)

    if not args.read_values:
        report.note(
            "Characteristic values were not read (pass --read-values to read them). "
            "Findings about readability are based on declared properties only."
        )

    return report


def _summarize(info: dict) -> dict:
    chars = [c for s in info["services"] for c in s["characteristics"]]
    return {
        "service_count": len(info["services"]),
        "characteristic_count": len(chars),
        "writable_count": sum(1 for c in chars if _WRITE_PROPS & set(c["properties"])),
        "readable_count": sum(1 for c in chars if "read" in c["properties"]),
        "notifiable_count": sum(
            1 for c in chars if {"notify", "indicate"} & set(c["properties"])
        ),
    }


def _add_findings(report: Report, info: dict) -> None:
    for service in info["services"]:
        risk = risk_for(service["uuid"])
        if risk:
            report.findings.add(
                Finding(
                    check=f"gatt.service.{risk.category}",
                    title=f"{risk.label} present",
                    severity=Severity.INFO,
                    target=service["uuid"],
                    confidence=Confidence.CONFIRMED,
                    description=risk.rationale,
                    evidence={"service_uuid": service["uuid"]},
                    remediation=risk.remediation,
                )
            )

        for char in service["characteristics"]:
            crisk = risk_for(char["uuid"])
            if crisk:
                report.findings.add(
                    Finding(
                        check=f"gatt.characteristic.{crisk.category}",
                        title=f"{crisk.label} present",
                        severity=Severity.INFO,
                        target=char["uuid"],
                        confidence=Confidence.CONFIRMED,
                        description=crisk.rationale,
                        evidence={
                            "characteristic_uuid": char["uuid"],
                            "properties": char["properties"],
                            "service": service["uuid"],
                        },
                        remediation=crisk.remediation,
                    )
                )

            if char.get("read_result") == "success" and char.get("value"):
                try:
                    raw = bytes.fromhex(char["value"])
                except ValueError:
                    raw = b""
                for match in secret_scan.scan(raw):
                    report.findings.add(
                        Finding(
                            check=(
                                "gatt.credential-in-value"
                                if match.confidence == "high"
                                else "gatt.possible-credential-in-value"
                            ),
                            title=(
                                f"Characteristic value looks like a credential ({match.kind})"
                            ),
                            severity=(
                                Severity.CRITICAL
                                if match.confidence == "high"
                                else Severity.MEDIUM
                            ),
                            target=char["uuid"],
                            confidence=Confidence.CONFIRMED,
                            description=match.detail,
                            evidence={
                                "characteristic_uuid": char["uuid"],
                                "service": service["uuid"],
                                "kind": match.kind,
                            },
                            remediation=(
                                "Do not expose live credentials in a GATT characteristic "
                                "readable without authentication."
                                if match.confidence == "high"
                                else "Inspect the value by hand to confirm before acting."
                            ),
                        )
                    )


def render(report: Report, console: Console) -> None:
    data = report.data

    if not data.get("connected_unpaired"):
        console.header("CONNECTION")
        console.error(f"Could not enumerate: {data.get('error')}")
        return

    console.header("CONNECTION")
    console.kv("address", data["address"])
    console.kv("paired", "no - connected without pairing")
    if data.get("mtu"):
        console.kv("ATT MTU", data["mtu"])
    console.kv(
        "totals",
        f"{data['service_count']} services, {data['characteristic_count']} characteristics "
        f"({data['readable_count']} readable, {data['writable_count']} writable, "
        f"{data['notifiable_count']} notify/indicate)",
    )

    console.header("GATT TREE")
    for service in data["services"]:
        console.write()
        srisk = risk_for(service["uuid"])
        marker = console.yellow(" <-- " + srisk.label) if srisk else ""
        console.write(
            f"  {console.bold(uuid_label(service['uuid'], 'service'))}{marker}"
        )
        console.write(f"  {console.dim(service['uuid'])}")

        for char in service["characteristics"]:
            crisk = risk_for(char["uuid"])
            props = ",".join(char["properties"])
            name = uuid_label(char["uuid"], "characteristic")
            handle = f"0x{char['handle']:04X}" if char.get("handle") is not None else "  ?   "

            line = f"    {console.dim(handle)}  {name}"
            if crisk:
                line += console.yellow(f"  <-- {crisk.label}")
            console.write(line)
            console.write(f"            {console.dim(char['uuid'])}  {console.cyan(props)}")

            if char.get("value") is not None:
                raw = bytes.fromhex(char["value"])
                decoded = ble.decode_value(char["uuid"], raw)
                shown = decoded if decoded else (raw.hex(" ").upper() or "(empty)")
                console.write(f"            {console.dim('value:')} {shown}")
            elif char.get("read_result") and char["read_result"] != "success":
                console.write(
                    f"            {console.dim('read:')} {console.red(char['read_result'])}"
                )

            for desc in char.get("descriptors", []):
                console.write(
                    f"            {console.dim('desc')} {desc['name']} {console.dim(desc['uuid'])}"
                )
