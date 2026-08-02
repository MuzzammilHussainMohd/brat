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
    # Something is wrong but nothing is blocked by it - a broken adapter
    # sitting next to a working one, or a working one that needs a flag.
    # Rendering these as FAIL alongside a READY verdict is the same kind of
    # misleading output this command exists to prevent, so they get their own
    # level: still shown, still carrying their fix, but not red.
    warn: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "fix": self.fix,
            "blocks": self.fatal_for,
            "warn": self.warn,
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

        caps = _av("SupportedCapabilities", {}) or {}

        def _cap(key, default=None):
            item = caps.get(key)
            return item.value if hasattr(item, "value") else (item or default)

        name = path.rsplit("/", 1)[-1]
        adapters.append(
            {
                "path": path,
                "name": name,
                "address": _v("Address", "?"),
                # What the controller itself reports, read independently of
                # BlueZ - see controller_address() for why that matters.
                "controller_address": controller_address(name),
                "address_type": _v("AddressType", "?"),
                "manufacturer": _v("Manufacturer", None),
                "modalias": _v("Modalias", ""),
                "powered": bool(_v("Powered", False)),
                "discoverable": bool(_v("Discoverable", False)),
                "can_advertise": "org.bluez.LEAdvertisingManager1" in ifaces,
                "can_serve_gatt": "org.bluez.GattManager1" in ifaces,
                "active_instances": _av("ActiveInstances", 0),
                "supported_instances": _av("SupportedInstances", 0),
                "supported_features": list(_av("SupportedFeatures", []) or []),
                "min_tx_power": _cap("MinTxPower", None),
                "max_tx_power": _cap("MaxTxPower", None),
                "max_adv_len": _cap("MaxAdvLen", None),
            }
        )
    return adapters, None


# BlueZ reports this as the adapter's Manufacturer for a controller running
# Zephyr's hci_usb sample - the nRF52840 dongle firmware. See the
# adapter-firmware check for why that matters for peripheral mode.
_ZEPHYR_MANUFACTURER = 1521
_NORDIC_USB_VID = "2fe3"


def controller_address(adapter: str) -> str | None:
    """The BD address the controller itself reports, or None if unreadable.

    Deliberately not BlueZ's `Adapter1.Address`. When a controller boots
    without an address - which the nRF52840's Zephyr hci_usb firmware does -
    BlueZ invents a static random one and reports that instead, so its D-Bus
    view says the adapter is fine while the controller cannot advertise at
    all. `bluetoothctl show` is not evidence here, and neither is anything
    else that reads the same property.
    """
    import re
    import shutil
    import subprocess

    if not shutil.which("hciconfig"):
        return None
    try:
        proc = subprocess.run(
            ["hciconfig", adapter], capture_output=True, text=True, timeout=5, check=False
        )
    except Exception:  # noqa: BLE001
        return None
    match = re.search(r"BD Address:\s*([0-9A-Fa-f:]{17})", proc.stdout)
    return match.group(1).upper() if match else None


def _is_zephyr_hci(adapter: dict) -> bool:
    """Whether this looks like an nRF dongle running Zephyr's hci_usb sample."""
    if adapter.get("manufacturer") == _ZEPHYR_MANUFACTURER:
        return True
    if _NORDIC_USB_VID in str(adapter.get("modalias", "")).lower():
        return True
    # Fallback signature for a controller that reports no identity at all:
    # no advertising features, no TX power range, and no address of its own.
    return (
        not adapter.get("supported_features")
        and adapter.get("min_tx_power") == 0
        and adapter.get("max_tx_power") == 0
        and adapter.get("controller_address") == "00:00:00:00:00:00"
    )


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

    # A controller that booted without an address cannot advertise. BlueZ
    # hides this: when the controller has none it synthesises a static random
    # address and reports that through Adapter1.Address, so the old version of
    # this check - which read that property - could never fire on the very
    # dongle it was written for, and doctor cheerfully declared impersonate
    # ready on hardware that provably could not do it.
    # The one gate that matters for peripheral mode: an adapter with the
    # interfaces that can actually use them. `peripheral-mode` above only
    # proves the interfaces exist, which the Zephyr dongle satisfies while
    # being unusable. Computed here rather than at its own check below because
    # the two checks that follow need to know whether anything covers them: a
    # dead dongle is only a *blocker* when it is the only radio in the machine.
    usable = [
        a
        for a in advertisers
        if a["powered"]
        and a["controller_address"] != "00:00:00:00:00:00"
        and not _is_zephyr_hci(a)
    ]
    covered = (
        f" - not usable for peripheral mode, but {usable[0]['name']} is"
        if usable
        else ""
    )

    zero_addr = [a for a in adapters if a["controller_address"] == "00:00:00:00:00:00"]
    unreadable = [a for a in adapters if a["controller_address"] is None]
    if zero_addr:
        checks.append(
            Check(
                "adapter-address",
                bool(usable),
                warn=bool(usable),
                detail="; ".join(
                    f"{a['name']}: controller reports 00:00:00:00:00:00 "
                    f"(BlueZ reports {a['address']}, which it invented)"
                    for a in zero_addr
                )
                + covered,
                fix="The controller booted with no BD address, so it cannot advertise. "
                "BlueZ synthesises a random static address when this happens, which is "
                "why `bluetoothctl show` looks fine - it is not evidence. Set an address "
                "on the controller (btmgmt public-addr, or your dongle's flashing "
                "script), or use an adapter that has one.",
                fatal_for=[] if usable else ["impersonate", "inject"],
            )
        )
    elif unreadable and adapters:
        checks.append(
            Check(
                "adapter-address",
                True,
                detail=f"could not read the controller address for "
                f"{', '.join(a['name'] for a in unreadable)}",
                fix="Install bluez's hciconfig so the controller's own address can be "
                "checked. BlueZ's reported address is not evidence: it invents one when "
                "the controller has none.",
            )
        )
    elif adapters:
        checks.append(
            Check(
                "adapter-address",
                True,
                detail="; ".join(
                    f"{a['name']} {a['controller_address']}" for a in adapters
                ),
            )
        )

    # The nRF52840 running Zephyr's hci_usb sample presents a working-looking
    # HCI interface - BlueZ shows Roles: peripheral and both manager
    # interfaces - while being unable to sustain advertising. It boots with no
    # BD address, reports no LE advertising features, and leaks advertising
    # resources across start/stop cycles until the controller answers LE Set
    # Advertise Enable with "Memory Capacity Exceeded". Restarting bluetoothd
    # does not clear that: the exhausted state lives on the chip.
    zephyr = [a for a in adapters if _is_zephyr_hci(a)]
    if zephyr:
        checks.append(
            Check(
                "adapter-firmware",
                bool(usable),
                warn=bool(usable),
                detail="; ".join(
                    f"{a['name']} is an nRF/Zephyr hci_usb controller" for a in zephyr
                )
                + (covered or " - detected, but not supported for peripheral mode"),
                fix="Use a generic USB Bluetooth adapter (Intel, Realtek, CSR) for "
                "impersonate and inject; keep this dongle for sniffing. This firmware "
                "boots with no BD address, reports no LE advertising features, and "
                "exhausts its own advertising resources across sessions - a failure a "
                "bluetoothd restart cannot clear, because it lives on the chip. "
                "`hciconfig <adapter> down && up` clears it; power-cycling always does.",
                fatal_for=[] if usable else ["impersonate", "inject"],
            )
        )

    checks.append(
        Check(
            "usable-peripheral-adapter",
            bool(usable),
            detail=(
                ", ".join(f"{a['name']} ({a['controller_address']})" for a in usable)
                if usable
                else "no adapter can both advertise and is fit to do so"
            ),
            fix="Plug in a generic USB Bluetooth adapter. Every adapter present either "
            "lacks the BlueZ interfaces, is powered off, has no controller address, or "
            "runs firmware that cannot sustain advertising."
            if not usable
            else "",
            fatal_for=["impersonate", "inject"] if not usable else [],
        )
    )

    # Two adapters in one machine is the obvious way to check impersonate
    # without a phone - advertise on one, scan with the other - and it does not
    # work. The packets do arrive: a btmon capture on the scanning adapter
    # shows both the ADV_IND and the SCAN_RSP. But both adapters answer to the
    # same bluetoothd, which will not raise a Device1 object for an address
    # belonging to one of its own controllers, so nothing built on the BlueZ
    # API - brat scan, bluetoothctl, any bleak program - ever sees it.
    #
    # The session then ends with "central connected: no" and every layer looks
    # broken while being entirely correct. Worth a line here, because the
    # obvious reading of that silence is that the tool does not transmit.
    if usable and len(adapters) > 1:
        advertiser = usable[0]["name"]
        others = [a["name"] for a in adapters if a["name"] != advertiser]
        checks.append(
            Check(
                "local-adapter-selftest",
                True,
                warn=True,
                detail=f"a scan from {', '.join(others)} cannot see {advertiser} "
                "advertising - they share one bluetoothd",
                fix="This is BlueZ behaviour, not a fault, and it is not evidence "
                f"that nothing was transmitted. To confirm an advertisement really "
                f"reached the air, capture below BlueZ on the scanning adapter with "
                f"`btmon --index {others[0].removeprefix('hci')}` and look for "
                "LE Advertising Report, or use an off-host central such as a phone "
                "running nRF Connect.",
            )
        )

    # bless resolves its adapter with a literal substring match on "hci0", not
    # "first available", so a usable adapter that enumerated as hci1 fails with
    # "No adapter named hci0 found" unless --adapter is passed. Worth one line
    # here rather than a confusing exception at start-up.
    if usable and not any(a["name"] == "hci0" for a in usable):
        first = usable[0]["name"]
        checks.append(
            Check(
                "default-adapter",
                True,
                warn=True,
                detail=f"the usable adapter is {first}, not hci0",
                fix=f"Pass --adapter {first} to impersonate and inject. bless looks for "
                'an adapter whose name contains "hci0" and fails outright otherwise, '
                "rather than falling back to whatever is available.",
            )
        )

    # An empty feature list or a zero TX power range means the controller
    # cannot honour the advertising hints bless sets unconditionally.
    featureless = [
        a
        for a in advertisers
        if not a["supported_features"] or a["max_tx_power"] in (0, None)
    ]
    if featureless and not zephyr:
        checks.append(
            Check(
                "advertising-features",
                True,
                detail="; ".join(
                    f"{a['name']} reports no LE advertising features" for a in featureless
                ),
                fix="Advertising may still work, but TX power and interval hints will "
                "be ignored or rejected by this controller.",
            )
        )

    return checks, adapters


COMMANDS = ["scan", "enum", "posture", "clone", "impersonate", "inject"]


def _peripheral_verdict(adapter: dict) -> str:
    """Whether this adapter can be impersonated from, and if not, why not."""
    if not adapter["can_advertise"] or not adapter["can_serve_gatt"]:
        return "no (no iface)"
    if not adapter["powered"]:
        return "no (off)"
    if adapter.get("controller_address") == "00:00:00:00:00:00":
        return "no (no addr)"
    if _is_zephyr_hci(adapter):
        return "no (zephyr)"
    return "yes"


def _text(report: Report, console: Console) -> None:
    data = report.data
    console.header("ENVIRONMENT")
    for c in data["checks"]:
        if not c["ok"]:
            mark = console.red("FAIL")
        elif c.get("warn"):
            mark = console.yellow("warn")
        else:
            mark = console.green("ok  ")
        console.write(f"  [{mark}] {console.bold(c['name']):<24} {c['detail']}")
        if (not c["ok"] or c.get("warn")) and c["fix"]:
            console.write(f"          {console.dim('fix:')} {c['fix']}")

    if data.get("adapters"):
        console.header("ADAPTERS")
        # BLUEZ ADDR and CTRL ADDR are shown side by side deliberately: when
        # they disagree, BlueZ invented one because the controller has none,
        # and that single fact explains an otherwise baffling inability to
        # advertise. A rejection reason belongs here, not only in the checks.
        console.table(
            ["NAME", "BLUEZ ADDR", "CTRL ADDR", "POWERED", "GATT SERVER", "ADV SLOTS", "PERIPHERAL"],
            [
                [
                    a["name"],
                    a["address"],
                    a.get("controller_address") or "unreadable",
                    "yes" if a["powered"] else "no",
                    "yes" if a["can_serve_gatt"] else "no",
                    f"{a.get('active_instances', 0)}/{a.get('supported_instances', 0)}"
                    if a["can_advertise"]
                    else "-",
                    _peripheral_verdict(a),
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
