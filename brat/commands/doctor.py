"""`brat doctor` - is this machine able to do what you are about to ask?

Peripheral-mode BLE on Linux fails in a dozen boring ways: bluetoothd stopped,
adapter down, no LEAdvertisingManager1, a dongle flashed to sniffer firmware,
another tool holding the adapter. Each produces a different unhelpful error
several minutes into a live demo.

This command checks all of it up front and says which commands will work.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

from ..core.console import Console
from ..core.report import Report


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    fix: str = ""
    fatal_for: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "fix": self.fix,
            "blocks": self.fatal_for,
        }


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    if not shutil.which(cmd[0]):
        return 127, f"{cmd[0]} not installed"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as exc:
        return 1, str(exc)


async def _bluez_adapters() -> tuple[list[dict], str | None]:
    """Query BlueZ over D-Bus for adapters and their capabilities.

    Returns (adapters, error). The LEAdvertisingManager1 interface is the
    authoritative answer to "can this adapter be a peripheral".
    """
    try:
        from dbus_fast import BusType
        from dbus_fast.aio import MessageBus
    except ImportError:
        return [], "dbus-fast not installed"

    try:
        bus = await asyncio.wait_for(
            MessageBus(bus_type=BusType.SYSTEM).connect(), timeout=5.0
        )
    except Exception as exc:  # noqa: BLE001
        return [], f"cannot reach the system bus: {exc}"

    try:
        intro = await asyncio.wait_for(bus.introspect("org.bluez", "/"), timeout=5.0)
        obj = bus.get_proxy_object("org.bluez", "/", intro)
        manager = obj.get_interface("org.freedesktop.DBus.ObjectManager")
        managed = await asyncio.wait_for(manager.call_get_managed_objects(), timeout=5.0)
    except Exception as exc:  # noqa: BLE001
        return [], f"org.bluez unavailable: {exc}"
    finally:
        try:
            bus.disconnect()
        except Exception:  # noqa: BLE001
            pass

    adapters: list[dict] = []
    for path, ifaces in managed.items():
        if "org.bluez.Adapter1" not in ifaces:
            continue
        props = ifaces["org.bluez.Adapter1"]

        def _v(key, default=None):
            item = props.get(key)
            return item.value if hasattr(item, "value") else (item or default)

        adv_props = ifaces.get("org.bluez.LEAdvertisingManager1", {})

        def _av(key, default=None):
            item = adv_props.get(key)
            return item.value if hasattr(item, "value") else (item or default)

        adapters.append(
            {
                "path": path,
                "name": path.rsplit("/", 1)[-1],
                "address": _v("Address", "?"),
                "powered": bool(_v("Powered", False)),
                "discoverable": bool(_v("Discoverable", False)),
                "can_advertise": "org.bluez.LEAdvertisingManager1" in ifaces,
                "can_serve_gatt": "org.bluez.GattManager1" in ifaces,
                "active_instances": _av("ActiveInstances", 0),
                "supported_instances": _av("SupportedInstances", 0),
            }
        )
    return adapters, None


async def run_checks() -> tuple[list[Check], list[dict]]:
    checks: list[Check] = []

    # -- platform -----------------------------------------------------------
    is_linux = platform.system() == "Linux"
    checks.append(
        Check(
            "platform",
            is_linux,
            detail=f"{platform.system()} {platform.release()}",
            fix="BRAT's peripheral commands require Linux with BlueZ."
            if not is_linux
            else "",
            fatal_for=["impersonate", "inject"] if not is_linux else [],
        )
    )

    # -- python libraries ---------------------------------------------------
    try:
        import bleak

        from importlib.metadata import version

        checks.append(Check("bleak", True, detail=f"version {version('bleak')}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(
            Check(
                "bleak",
                False,
                detail=str(exc),
                fix="pip install bleak",
                fatal_for=["scan", "enum", "posture", "clone"],
            )
        )

    try:
        import bless  # noqa: F401
        from importlib.metadata import version

        checks.append(Check("bless", True, detail=f"version {version('bless')}"))
    except Exception:  # noqa: BLE001
        checks.append(
            Check(
                "bless",
                False,
                detail="not installed",
                fix="pip install 'brat-ble[peripheral]'  (or: pip install bless)",
                fatal_for=["impersonate", "inject"],
            )
        )

    # -- privileges ---------------------------------------------------------
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    checks.append(
        Check(
            "privileges",
            is_root,
            detail="running as root" if is_root else "not root",
            fix="Peripheral mode and some scans need raw HCI access. Re-run with sudo."
            if not is_root
            else "",
        )
    )

    if not is_linux:
        return checks, []

    # -- bluetoothd ---------------------------------------------------------
    rc, out = _run(["systemctl", "is-active", "bluetooth"])
    active = out.strip() == "active"
    checks.append(
        Check(
            "bluetoothd",
            active,
            detail=out.strip() or "unknown",
            fix="sudo systemctl start bluetooth" if not active else "",
            fatal_for=["scan", "enum", "posture", "clone", "impersonate", "inject"]
            if not active
            else [],
        )
    )

    rc, out = _run(["bluetoothctl", "--version"])
    if rc == 0:
        checks.append(Check("bluez", True, detail=out.strip()))
    else:
        checks.append(
            Check("bluez", False, detail=out.strip(), fix="Install the bluez package.")
        )

    # -- adapters -----------------------------------------------------------
    adapters, error = await _bluez_adapters()

    if error and not adapters:
        checks.append(
            Check(
                "adapter",
                False,
                detail=error,
                fix="Start bluetoothd and plug in a BLE adapter.",
                fatal_for=["scan", "enum", "posture", "clone", "impersonate", "inject"],
            )
        )
        return checks, []

    if not adapters:
        checks.append(
            Check(
                "adapter",
                False,
                detail="no Bluetooth adapters found",
                fix="Plug in a BLE adapter. If using an nRF dongle, flash it to "
                "HCI firmware first - sniffer firmware does not present an HCI device.",
                fatal_for=["scan", "enum", "posture", "clone", "impersonate", "inject"],
            )
        )
        return checks, []

    powered = [a for a in adapters if a["powered"]]
    checks.append(
        Check(
            "adapter",
            bool(powered),
            detail=f"{len(adapters)} found, {len(powered)} powered "
            f"({', '.join(a['name'] + '=' + a['address'] for a in adapters)})",
            fix="sudo bluetoothctl power on" if not powered else "",
            fatal_for=["scan", "enum", "posture", "clone", "impersonate", "inject"]
            if not powered
            else [],
        )
    )

    # -- peripheral capability ---------------------------------------------
    advertisers = [a for a in adapters if a["can_advertise"] and a["can_serve_gatt"]]
    checks.append(
        Check(
            "peripheral-mode",
            bool(advertisers),
            detail=(
                f"{', '.join(a['name'] for a in advertisers)} can advertise and serve GATT"
                if advertisers
                else "no adapter exposes LEAdvertisingManager1 + GattManager1"
            ),
            fix="Peripheral mode needs a BlueZ adapter with LE advertising support. "
            "Some USB dongles and most VM passthrough setups do not provide it."
            if not advertisers
            else "",
            fatal_for=["impersonate", "inject"] if not advertisers else [],
        )
    )

    # A nonzero ActiveInstances *before* BRAT has registered anything means
    # something is already occupying an advertising slot - almost always a
    # previous `impersonate`/`inject` session that was killed abruptly
    # (SIGKILL bypasses the graceful unregister path entirely) rather than
    # stopped with Ctrl-C. On a controller with few advertising slots this
    # can starve or destabilize a fresh registration attempt, surfacing as a
    # confusing "Failed to register advertisement" / "Memory Capacity
    # Exceeded" error with no obvious cause. This check exists so that
    # diagnosis doesn't require manually querying LEAdvertisingManager1 over
    # D-Bus, as this session had to.
    dangling = [
        a for a in advertisers if a.get("active_instances", 0) > 0
    ]
    if dangling:
        dangling_desc = ", ".join(
            f"{a['name']} ({a['active_instances']}/{a['supported_instances']})"
            for a in dangling
        )
        checks.append(
            Check(
                "advertising-slots",
                False,
                detail=f"{dangling_desc} already has an active advertisement registered",
                fix="Likely a prior impersonate/inject session that was killed rather "
                "than stopped with Ctrl-C, leaving BlueZ's registration in place. Stop "
                "any lingering `brat impersonate`/`inject` process, then if problems "
                "persist: sudo systemctl restart bluetooth (clears BlueZ's own state) "
                "or power-cycle the adapter itself (unplug/replug a USB dongle) if "
                "restarting bluetoothd alone doesn't clear it - the failure can live in "
                "the controller's own firmware state, not just the host daemon.",
            )
        )

    # A zeroed address means the controller booted without one - common on
    # freshly flashed nRF dongles, and it breaks advertising silently.
    zero_addr = [a for a in adapters if a["address"] in ("00:00:00:00:00:00", "?")]
    if zero_addr:
        checks.append(
            Check(
                "adapter-address",
                False,
                detail=f"{', '.join(a['name'] for a in zero_addr)} has no valid address",
                fix="Set a static address on the controller before advertising "
                "(e.g. via btmgmt public-addr, or your dongle's flashing script).",
                fatal_for=["impersonate", "inject"],
            )
        )

    return checks, adapters


COMMANDS = ["scan", "enum", "posture", "clone", "impersonate", "inject"]


def _text(report: Report, console: Console) -> None:
    data = report.data
    console.header("ENVIRONMENT")
    for c in data["checks"]:
        mark = console.green("ok  ") if c["ok"] else console.red("FAIL")
        console.write(f"  [{mark}] {console.bold(c['name']):<24} {c['detail']}")
        if not c["ok"] and c["fix"]:
            console.write(f"          {console.dim('fix:')} {c['fix']}")

    if data.get("adapters"):
        console.header("ADAPTERS")
        console.table(
            ["NAME", "ADDRESS", "POWERED", "ADVERTISE", "GATT SERVER", "ADV SLOTS"],
            [
                [
                    a["name"],
                    a["address"],
                    "yes" if a["powered"] else "no",
                    "yes" if a["can_advertise"] else "no",
                    "yes" if a["can_serve_gatt"] else "no",
                    f"{a.get('active_instances', 0)}/{a.get('supported_instances', 0)}"
                    if a["can_advertise"]
                    else "-",
                ]
                for a in data["adapters"]
            ],
        )

    console.header("COMMAND READINESS")
    for cmd, blockers in data["readiness"].items():
        if blockers:
            console.write(
                f"  {console.red('blocked')}  {console.bold(cmd):<22} "
                f"{console.dim('needs: ' + ', '.join(blockers))}"
            )
        else:
            console.write(f"  {console.green('ready')}    {console.bold(cmd)}")


async def execute(args, console: Console) -> Report:
    report = Report(command="doctor")
    checks, adapters = await run_checks()

    readiness: dict[str, list[str]] = {}
    for cmd in COMMANDS:
        readiness[cmd] = [c.name for c in checks if not c.ok and cmd in c.fatal_for]

    report.data = {
        "checks": [c.to_dict() for c in checks],
        "adapters": adapters,
        "readiness": readiness,
        "python": sys.version.split()[0],
    }
    return report


def render(report: Report, console: Console) -> None:
    _text(report, console)
