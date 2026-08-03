"""Peripheral-mode engine.

Builds a live BLE GATT server from a `Profile` and serves it. This is the half
of BLE security testing that the central-side tools do not cover: instead of
asking a device questions, you become the device and record what talks to you.

Everything here is profile-driven. The engine has no knowledge of any specific
vendor - it serves whatever tree the profile describes, decodes whatever frames
arrive using the profile's `protocol:` block if one exists, and replies with
whatever the profile's emulation rules say.

Requires bless, which is Linux/BlueZ only for practical purposes. Imported
lazily so the recon half of BRAT works without it.
"""

from __future__ import annotations

import asyncio
import re
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from .console import Console, hexstr
from .profile import CharacteristicSpec, Profile
from .protocol import Frame, ProtocolEngine, ProtocolError
from .uuids import is_sig
from .uuids import label as uuid_label
from .uuids import normalize as norm_uuid
from .uuids import short_form


class PeripheralError(RuntimeError):
    pass


def _require_bless():
    try:
        from bless import BlessServer  # noqa: F401
        from bless.backends.characteristic import (  # noqa: F401
            GATTAttributePermissions,
            GATTCharacteristicProperties,
        )
        from bless.backends.descriptor import GATTDescriptorProperties  # noqa: F401
    except ImportError as exc:
        raise PeripheralError(
            "peripheral mode needs bless.\n"
            "  pip install 'brat-ble[peripheral]'   (or: pip install bless)"
        ) from exc
    return (
        BlessServer,
        GATTCharacteristicProperties,
        GATTAttributePermissions,
        GATTDescriptorProperties,
    )


# bleak/profile property strings -> bless flag names.
_PROPERTY_MAP: dict[str, str] = {
    "broadcast": "broadcast",
    "read": "read",
    "write": "write",
    "write-without-response": "write_without_response",
    "write_without_response": "write_without_response",
    "notify": "notify",
    "indicate": "indicate",
    "authenticated-signed-writes": "authenticated_signed_writes",
    "authenticated_signed_writes": "authenticated_signed_writes",
    "reliable-write": "reliable_write",
    "reliable_write": "reliable_write",
    "writable-auxiliaries": "writable_auxiliaries",
    "writable_auxiliaries": "writable_auxiliaries",
}


# Properties a real device can advertise but a BlueZ GATT server cannot
# express, mapped to why. These are deliberately kept out of _PROPERTY_MAP:
# bless's GATTCharacteristicProperties *does* define extended_properties, so
# the lookup succeeds and the failure only surfaces later, when bless converts
# the flag set for D-Bus and finds no matching member in its Flags enum. That
# raises StopIteration from inside a coroutine, which Python re-raises as
# "RuntimeError: coroutine raised StopIteration" - an error naming neither the
# characteristic nor the property. `brat clone` writes this property straight
# into profiles, so any cloned device carrying it was unservable.
_UNSERVABLE_PROPERTIES: dict[str, str] = {
    "extended-properties": (
        "BlueZ has no GattCharacteristic1 flag for it - it is implied by the "
        "Characteristic Extended Properties descriptor (0x2900) instead"
    ),
}
_UNSERVABLE_PROPERTIES["extended_properties"] = _UNSERVABLE_PROPERTIES[
    "extended-properties"
]


def build_properties(properties: list[str], props_enum) -> Any:
    """Translate profile property strings into a bless property flag set.

    Returns (flags, unknown, unservable). `unknown` is a property nobody
    recognises; `unservable` is one that is perfectly valid on a real device
    but cannot be served through BlueZ, paired with the reason. Reporting the
    second as the first would be a lie, and an unhelpful one.
    """
    flags = None
    unknown: list[str] = []
    unservable: list[tuple[str, str]] = []
    for name in properties:
        key = str(name).lower()
        reason = _UNSERVABLE_PROPERTIES.get(key)
        if reason is not None:
            unservable.append((str(name), reason))
            continue
        attr = _PROPERTY_MAP.get(key)
        if attr is None:
            unknown.append(name)
            continue
        flag = getattr(props_enum, attr, None)
        if flag is None:
            unknown.append(name)
            continue
        flags = flag if flags is None else (flags | flag)

    if flags is None:
        # A characteristic with no usable properties is still worth serving as
        # readable so the tree shape matches the original device.
        flags = props_enum.read
    return flags, unknown, unservable


def build_permissions(char: CharacteristicSpec, perms_enum) -> Any:
    """Attribute permissions for a served characteristic.

    Deliberately mirrors the cloned device: if the original served a
    characteristic without requiring encryption, the clone does too. Serving it
    *more* securely than the original would defeat the point - the client would
    behave differently against the clone than against the real device.
    """
    perms = None
    if char.readable or char.subscribable or not char.properties:
        perms = perms_enum.readable
    if char.writable:
        perms = perms_enum.writeable if perms is None else (perms | perms_enum.writeable)
    if perms is None:
        perms = perms_enum.readable
    return perms


# ---------------------------------------------------------------------------
# Session log
# ---------------------------------------------------------------------------


@dataclass
class LogEntry:
    timestamp: str
    direction: str          # "rx" (central -> us) or "tx" (us -> central)
    uuid: str
    data: bytes
    decoded: str = ""
    label: str = ""
    # What produced a "tx" entry: a plain GATT read reply vs an actual
    # protocol-emulation response. Findings that claim "the peripheral
    # answered using emulation rules" must not count a read reply as one -
    # relying on `label` text for this was fragile, so it is explicit.
    origin: str = "protocol-response"
    # Whether the bytes were understood as a genuine, checksum-valid frame of
    # this profile's protocol (only meaningful for "rx" entries). A protocol
    # error or a failed checksum must not count as "the client sent a valid
    # command" - keeping this a plain bool instead of substring-matching
    # `decoded` text is what makes that distinction reliable.
    frame_ok: bool = False
    # For "tx" entries: whether a central had actually subscribed to the
    # characteristic at the moment we handed the bytes to BlueZ. `update_value`
    # cannot tell us - it returns True whether or not anyone is listening - so
    # without this a session log of unheard notifications is indistinguishable
    # from one the client received. None means unknowable (no bless app).
    delivered: bool | None = None
    # Insertion order, stamped by SessionLog.add(). `timestamp` is a bare
    # HH:MM:SS.ffffff string with no date - a session that runs past midnight
    # makes string/time comparison on it silently wrong (every post-midnight
    # entry compares as "earlier"). Anything that needs "did X happen after
    # Y" should compare `seq`, not `timestamp`, which exists for display only.
    seq: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "uuid": self.uuid,
            "length": len(self.data),
            "hex": self.data.hex(),
            "decoded": self.decoded or None,
            "label": self.label or None,
            "origin": self.origin,
            "frame_ok": self.frame_ok,
            "delivered": self.delivered,
            "seq": self.seq,
        }


@dataclass
class SessionLog:
    entries: list[LogEntry] = field(default_factory=list)
    connected_at: str | None = None
    _next_seq: int = 0

    def add(self, entry: LogEntry) -> LogEntry:
        entry.seq = self._next_seq
        self._next_seq += 1
        self.entries.append(entry)
        return entry

    @property
    def rx(self) -> list[LogEntry]:
        return [e for e in self.entries if e.direction == "rx"]

    @property
    def tx(self) -> list[LogEntry]:
        return [e for e in self.entries if e.direction == "tx"]

    def to_dict(self) -> dict:
        return {
            "connected_at": self.connected_at,
            "received": len(self.rx),
            "sent": len(self.tx),
            "entries": [e.to_dict() for e in self.entries],
        }


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# ---------------------------------------------------------------------------
# The rogue peripheral
# ---------------------------------------------------------------------------


class RoguePeripheral:
    """Serves a profile's GATT tree and answers according to its rules."""

    def __init__(
        self,
        profile: Profile,
        console: Console,
        name_override: str | None = None,
        blobs: dict[str, bytes] | None = None,
        quiet: bool = False,
        on_frame: Callable[[Frame, LogEntry], None] | None = None,
        adapter: str | None = None,
    ) -> None:
        self.profile = profile
        self.console = console
        self.blobs = blobs or {}
        self.quiet = quiet
        self.on_frame = on_frame
        self.adapter = adapter
        self._warnings: list[str] = []

        # Deliberately does NOT fall back to profile.match.name: that field is
        # a glob (see MatchSpec in profile.py), matched with fnmatch. Putting
        # it on the air would broadcast a literal "Mira-*", and bless derives
        # its D-Bus object path from the name by stripping every character
        # outside [A-Za-z0-9_] - so a name made only of glob punctuation
        # yields the invalid path "/org/bluez//advertisement1" and a failure
        # that points nowhere near the profile. Kept identical to the chain in
        # commands/impersonate.py so the printed banner cannot disagree with
        # what is actually broadcast.
        self.advertised_name = (
            name_override or profile.advertising.local_name or profile.name
        )
        self._check_advertised_name()

        self.log = SessionLog()
        self.connected = False
        # How many separate centrals attached over the session. A reconnect
        # loop and a single steady client are very different results, and the
        # summary otherwise cannot tell them apart.
        self.connections = 0
        self.central_address: str | None = None
        self._watch_bus = None
        self._watch_task: asyncio.Task | None = None
        self._sub_task: asyncio.Task | None = None
        # Profile-declared characteristic values, served from `_on_read`.
        # Held here rather than in the characteristic's own cached D-Bus
        # property so that BlueZ has to call us for every read.
        self._char_values: dict[str, bytes] = {}
        self._server = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._notify_uuids: list[str] = []
        # Registered-characteristic objects, keyed by (service_uuid, char_uuid).
        # bless's own `get_characteristic(uuid)` is a server-wide, first-match
        # lookup with no service scoping - if the same characteristic UUID
        # appears in two different services (a duplicated vendor control
        # point across an app service and a DFU service, say), it can resolve
        # to the wrong object relative to the service `notify()` tells BlueZ
        # to signal on, so the value gets set on one object while the
        # subscribed central is notified via the other and nothing is sent.
        # Keeping our own registry, built from exactly what `build()`
        # registered, removes the ambiguity.
        self._char_registry: dict[tuple[str, str], Any] = {}
        # What `build()` actually registered - not the same as the profile's
        # full tree, since services BlueZ owns (GAP, GATT) are skipped. The
        # session summary must report what was really served, or it silently
        # overstates the served tree by however many services got skipped.
        self._served_service_count = 0
        self._served_characteristic_count = 0
        # Serializes notify()'s value-set + update_value pair. Multiple
        # inbound writes each schedule their own `_respond` coroutine (e.g. a
        # pipelining client, or `--repeat`/`--interval` on inject); without
        # this lock two concurrent responses can interleave their
        # `char.value = X` assignment before either calls update_value, and
        # the central receives the wrong (or duplicate) payload.
        self._notify_lock = asyncio.Lock()
        # In-flight response coroutines, so stop() can let them finish rather
        # than cutting them off mid-delay, and so their exceptions are seen.
        self._pending: set[asyncio.Task] = set()
        # Formatted tracebacks from the response path. Without somewhere for
        # these to go they were discarded with the Future that carried them,
        # and a profile bug looked exactly like a silent client.
        self._errors: list[str] = []

    def _check_advertised_name(self) -> None:
        name = self.advertised_name or ""
        if not re.sub(r"[^A-Za-z0-9_]", "", name):
            raise PeripheralError(
                f"advertised name {name!r} contains no [A-Za-z0-9_] characters.\n"
                "  bless builds its D-Bus object path from the name "
                '(base_path = "/org/bluez/" + the name with everything else\n'
                '  stripped), so this produces the invalid path '
                '"/org/bluez//advertisement1" and an unattributable\n'
                "  registration failure. Set advertising.local_name in the profile, "
                "or pass --name."
            )
        if any(c in name for c in "*?["):
            self._warnings.append(
                f"advertised name {name!r} looks like a glob - it will be broadcast "
                "literally, wildcards and all. match.name is a pattern for finding a "
                "device; advertising.local_name is the name to broadcast."
            )

    # -- protocol -----------------------------------------------------------

    @property
    def protocol(self) -> ProtocolEngine | None:
        return self.profile.protocol

    def _decode(self, data: bytes) -> tuple[Frame | None, str]:
        engine = self.protocol
        if engine is None:
            return None, ""
        try:
            frame = engine.decode(data)
        except ProtocolError as exc:
            return None, f"(protocol error: {exc})"
        if frame is None:
            return None, "(not a recognised frame for this profile's protocol)"
        return frame, engine.describe(frame)

    # -- build --------------------------------------------------------------

    def _force_primary(self, service: "ServiceSpec") -> None:
        """Mark a just-added service primary when the profile says it is.

        bless decides this for us and gets it wrong for any device with more
        than one service: `BlueZGattApplication.add_service` sets
        `primary = (index == 1)`, so only the first service added is primary
        and every later one is registered as a *secondary* service.

        A secondary service is not a lesser primary one - the spec says it is
        not returned by primary service discovery at all, because it exists
        only to be included by a primary service. So the second and subsequent
        services are served, exported on D-Bus, and completely invisible to a
        client doing ordinary discovery.

        That produced a silent, near-undebuggable failure: a real client
        connects to the impersonated device and cannot find a service the
        profile plainly contains, while BRAT reports the session as fine.
        Whichever service happened to be listed first worked, which made it
        look like the *characteristic* was at fault rather than the ordering.

        `Primary` is a read-only D-Bus property read by BlueZ during
        RegisterApplication, and that happens later in `start()`, so amending
        the flag here - before registration - is enough. Reaching into bless's
        internals is not lovely; the alternative is shipping a peripheral that
        can only ever serve one service.
        """
        if not getattr(service, "primary", True):
            return

        bless_service = self._server.get_service(service.uuid)
        gatt = getattr(bless_service, "gatt", None)
        if gatt is None or getattr(gatt, "_primary", None) is not False:
            # Nothing to correct, or bless's internals have moved. Either way
            # this is best-effort: say so rather than failing the session.
            if gatt is None and bless_service is not None:
                self._warnings.append(
                    f"could not confirm {service.uuid} is registered as a primary "
                    "service; if a client cannot discover it, this is why"
                )
            return

        gatt._primary = True

    async def build(self) -> None:
        BlessServer, props_enum, perms_enum, desc_props_enum = _require_bless()

        self._loop = asyncio.get_running_loop()
        server_kwargs: dict[str, Any] = {"name": self.advertised_name}
        if self.adapter:
            server_kwargs["adapter"] = self.adapter
        self._server = BlessServer(**server_kwargs)
        self._server.write_request_func = self._on_write
        self._server.read_request_func = self._on_read

        for service in self.profile.services:
            # BlueZ owns these and rejects attempts to register them.
            if service.uuid in (
                norm_uuid("1800"),
                norm_uuid("1801"),
            ):
                self._warnings.append(
                    f"skipped {uuid_label(service.uuid, 'service')} - BlueZ provides it automatically"
                )
                continue

            await self._server.add_new_service(service.uuid)
            self._force_primary(service)
            self._served_service_count += 1

            for char in service.characteristics:
                flags, unknown, unservable = build_properties(char.properties, props_enum)
                if unknown:
                    self._warnings.append(
                        f"{char.uuid}: ignored unknown properties {', '.join(unknown)}"
                    )
                for prop, reason in unservable:
                    self._warnings.append(
                        f"{char.uuid}: cannot serve the {prop!r} property - {reason}. "
                        "The characteristic is served without it; a client that "
                        "reads properties will see a slightly different device."
                    )
                perms = build_permissions(char, perms_enum)

                # Register with no value, and keep the profile's value here
                # instead. bless exposes a cached `Value` D-Bus property on
                # each characteristic; when that is populated BlueZ answers
                # reads from it directly and never calls ReadValue(), so the
                # read never reaches our handler and the session log shows
                # nothing while a client is plainly reading. Registering
                # empty forces BlueZ to ask us, and `_on_read` serves the
                # value from this map - so the client still gets the right
                # bytes, and we get to see that it asked.
                if char.value:
                    self._char_values[char.uuid] = bytes(char.value_bytes)

                try:
                    await self._server.add_new_characteristic(
                        service.uuid, char.uuid, flags, None, perms
                    )
                except Exception as exc:  # noqa: BLE001
                    # bless converts the flag set for D-Bus in here, and a flag
                    # it cannot express raises from inside a coroutine - which
                    # Python reports as a bare "RuntimeError: coroutine raised
                    # StopIteration" naming neither the characteristic nor the
                    # property. Attribute it before it escapes.
                    raise PeripheralError(
                        f"could not register characteristic {char.uuid} "
                        f"({uuid_label(char.uuid, 'characteristic')}) with properties "
                        f"{list(char.properties)}: {type(exc).__name__}: {exc}"
                    ) from exc
                self._served_characteristic_count += 1

                # Resolve the characteristic object scoped to THIS service
                # right now, while there is no ambiguity, rather than via a
                # server-wide UUID lookup later when a second service sharing
                # this UUID may also be registered.
                bless_service = self._server.get_service(service.uuid)
                if bless_service is not None:
                    self._char_registry[(service.uuid, char.uuid)] = (
                        bless_service.get_characteristic(char.uuid)
                    )

                if char.subscribable:
                    self._notify_uuids.append(char.uuid)

                for desc in char.descriptors:
                    if desc.uuid == norm_uuid("2902"):
                        # The Client Characteristic Configuration Descriptor
                        # is auto-managed by BlueZ for any characteristic with
                        # notify/indicate properties - registering it again
                        # here would conflict with, not add to, that. Any
                        # other descriptor (User Description, Characteristic
                        # Extended Properties, a vendor one) has no such
                        # automatic handling, so a clone that captured one and
                        # silently dropped it would behave differently
                        # against a client that reads it to identify an
                        # endpoint. Serve those explicitly.
                        continue
                    try:
                        desc_value = (
                            bytes.fromhex(desc.value) if desc.value else None
                        )
                        await self._server.add_new_descriptor(
                            service.uuid,
                            char.uuid,
                            desc.uuid,
                            desc_props_enum.read,
                            desc_value,
                            perms_enum.readable,
                        )
                    except Exception as exc:  # noqa: BLE001
                        self._warnings.append(
                            f"{char.uuid}: could not serve descriptor {desc.uuid} "
                            f"({desc.name or 'unnamed'}) - {exc}"
                        )

    # -- callbacks ----------------------------------------------------------

    def _on_read(self, characteristic, **kwargs) -> bytearray:
        uuid = norm_uuid(getattr(characteristic, "uuid", ""))
        # Prefer whatever the characteristic currently holds (a notify may
        # have just set it); otherwise serve the profile's declared value,
        # which build() deliberately kept out of the cached D-Bus property.
        value = characteristic.value or bytearray(self._char_values.get(uuid, b""))
        self._mark_connected()
        if not self.quiet:
            self.console.write(
                f"  {self.console.dim('[' + _ts() + ']')} "
                f"{self.console.cyan('READ  <-')} {uuid_label(uuid, 'characteristic')} "
                f"{self.console.dim(uuid)}"
            )
            if value:
                self.console.write(f"         {hexstr(bytes(value))}")
        self.log.add(
            LogEntry(
                _ts(), "tx", uuid, bytes(value), label="read-response", origin="read-reply"
            )
        )
        return value

    def _on_write(self, characteristic, value, **kwargs) -> None:
        data = bytes(value)
        uuid = norm_uuid(getattr(characteristic, "uuid", ""))
        self._mark_connected()

        frame, decoded = self._decode(data)
        frame_ok = frame is not None and getattr(frame, "checksum_ok", True)
        entry = self.log.add(
            LogEntry(_ts(), "rx", uuid, data, decoded=decoded, frame_ok=frame_ok)
        )

        if not self.quiet:
            self.console.write()
            self.console.write(
                f"  {self.console.dim('[' + entry.timestamp + ']')} "
                f"{self.console.yellow('WRITE ->')} {uuid_label(uuid, 'characteristic')} "
                f"{self.console.dim(uuid)}  ({len(data)}B)"
            )
            self.console.hexdump(data, indent=9)
            if decoded:
                self.console.write(f"         {self.console.bold(decoded)}")

        if self.on_frame and frame is not None:
            self.on_frame(frame, entry)

        if frame is not None:
            self._schedule_response(
                self._respond(frame, uuid),
                f"response to {self.protocol.command_name(frame.cmd) if self.protocol else 'frame'}",
            )

    def _schedule_response(self, coro, what: str) -> None:
        """Run a response coroutine, keeping hold of it and of its failures.

        The previous version handed the coroutine to `run_coroutine_threadsafe`
        and dropped the Future, so every exception raised while building or
        sending a response - a bad template, a missing blob, an unregistered
        characteristic - vanished with no traceback and no output. Combined
        with a profile that has no emulation rules, that made "the profile
        cannot answer" and "the client asked for nothing" look identical.
        """
        loop = self._loop
        if loop is None:
            coro.close()
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is loop:
            # The normal path: bless dispatches write_request_func on the
            # asyncio loop thread via dbus_next, so we are already on it.
            task: asyncio.Future = loop.create_task(coro)
        else:
            task = asyncio.ensure_future(
                asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coro, loop)),
                loop=loop,
            )

        self._pending.add(task)
        task.add_done_callback(lambda t: self._response_finished(t, what))

    def _response_finished(self, task, what: str) -> None:
        self._pending.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        self._errors.append(f"{what}: {detail}")
        # Reported even when quiet. An error suppressed because the operator
        # asked for JSON output is exactly the failure this exists to prevent.
        self.console.error(f"{what} failed: {type(exc).__name__}: {exc}")

    @property
    def ever_connected(self) -> bool:
        """Whether any central attached at any point this session.

        Distinct from `connected`, which is live state and goes back to False
        on disconnect. Reporting must use this: a client that connects, does
        its business and disconnects before the operator stops the tool - the
        normal way a session ends - would otherwise be summarised as "no
        central connected", turning the single most important result the
        peripheral commands can produce into a claim that nothing happened.
        """
        return self.log.connected_at is not None

    def _mark_connected(self, address: str | None = None) -> None:
        """Record that a central is attached.

        `address` is set when BlueZ told us directly (see
        `_start_connection_watch`); without it this is an inference from a
        GATT operation having arrived at all.
        """
        if address:
            self.central_address = address
        if self.connected:
            return
        self.connected = True

        now = _ts()
        # Set once, not per connection. `connected` returns to False on
        # disconnect, so the guard above does not stop a reconnect from
        # reaching here - and reassigning would leave the session record
        # holding the *most recent* attach while it is reported as the first.
        # A session with four connections showed the fourth one's timestamp.
        self.connections += 1
        if self.log.connected_at is None:
            self.log.connected_at = now

        if not self.quiet:
            self.console.write()
            if address:
                self.console.ok(f"Central connected: {address} (at {now})")
            else:
                self.console.ok(
                    f"Central connected (inferred from first GATT operation at {now})"
                )

    def _mark_disconnected(self, address: str | None = None) -> None:
        if not self.connected:
            return
        self.connected = False
        # Anything the protocol captured belonged to the connection that just
        # ended. Carrying it into the next one would answer a second client
        # using the first client's identifiers.
        if self.protocol is not None:
            self.protocol.reset_session()
        if not self.quiet:
            self.console.write()
            self.console.info(
                f"Central disconnected{f' ({address})' if address else ''} at {_ts()}"
            )

    async def _subscription_poll_loop(self, interval: float = 0.25) -> None:
        """Report centrals subscribing to / unsubscribing from notifications.

        A CCCD write is the moment a client says "start sending me things",
        and for many devices it is what triggers the client's first command -
        so seeing it, or not seeing it, is the fastest way to tell a working
        session from a stalled one. It is also what decides whether a notify
        actually goes on the air, since `update_value()` reports success
        either way.

        Polled rather than hooked because bless calls `app.StartNotify(None)`
        *before* appending the UUID to `subscribed_characteristics`, so the
        hook cannot tell which characteristic was subscribed. Reading the list
        is in-process state - no D-Bus, no adapter - so this runs regardless
        of whether the connection watch managed to start.
        """
        seen: set[str] = set()
        while True:
            await asyncio.sleep(interval)
            current = self._subscribed()
            if current is None:
                continue
            for uuid in sorted(current - seen):
                if not self.quiet:
                    self.console.ok(
                        f"Central subscribed to {uuid_label(uuid, 'characteristic')} "
                        f"{self.console.dim(uuid)}"
                    )
            for uuid in sorted(seen - current):
                if not self.quiet:
                    self.console.info(
                        f"Central unsubscribed from {uuid_label(uuid, 'characteristic')}"
                    )
            seen = current

    async def _start_connection_watch(self) -> None:
        """Poll BlueZ for real link-layer connect/disconnect events.

        bless cannot report this. Its `is_connected()` only says whether a
        characteristic has been *subscribed*, and its read/write callbacks
        fire only for characteristic **value** operations. A central that
        connects and performs service discovery - which is everything nRF
        Connect does on connect, and the first thing most real clients do -
        is answered entirely inside BlueZ and never reaches our handlers. The
        session therefore looked completely empty while a phone was plainly
        connected, which reads as "impersonation failed" when it in fact
        succeeded.

        BlueZ's `org.bluez.Device1.Connected` property is the ground truth.
        This polls `GetManagedObjects` rather than subscribing to signals:
        when a central connects to us, BlueZ may either flip `Connected` on
        an existing device object (a PropertiesChanged signal) or create the
        object outright (an InterfacesAdded signal), and which one you get
        depends on whether that central has been seen before. Polling
        observes the resulting state either way, which is worth more here
        than shaving a second off the notification.

        Fail-soft by design: if the watch cannot start, the existing
        infer-from-first-GATT-operation behaviour still applies, because a
        missing convenience must never stop the peripheral running.
        """
        try:
            from dbus_fast import BusType
            from dbus_fast.aio import MessageBus
        except ImportError:
            self._warnings.append(
                "connection watch unavailable (dbus-fast not installed) - "
                "connections will only be noticed once the client reads or writes "
                "a characteristic"
            )
            return

        try:
            bus = await asyncio.wait_for(
                MessageBus(bus_type=BusType.SYSTEM).connect(), timeout=5.0
            )
            intro = await asyncio.wait_for(
                bus.introspect("org.bluez", "/"), timeout=5.0
            )
            obj = bus.get_proxy_object("org.bluez", "/", intro)
            manager = obj.get_interface("org.freedesktop.DBus.ObjectManager")
        except Exception as exc:  # noqa: BLE001
            self._warnings.append(
                f"connection watch could not start ({exc}) - connections will only "
                "be noticed once the client reads or writes a characteristic"
            )
            return

        self._watch_bus = bus
        self._watch_task = asyncio.create_task(self._connection_poll_loop(manager))

    async def _connection_poll_loop(self, manager, interval: float = 1.0) -> None:
        """Report centrals appearing in / disappearing from BlueZ's device list."""
        seen: set[str] = set()
        while True:
            try:
                await asyncio.sleep(interval)
                managed = await asyncio.wait_for(
                    manager.call_get_managed_objects(), timeout=5.0
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a transient D-Bus error must not kill the watch
                continue

            current: set[str] = set()
            for path, ifaces in managed.items():
                props = ifaces.get("org.bluez.Device1")
                if not props:
                    continue
                connected = props.get("Connected")
                if not bool(getattr(connected, "value", connected)):
                    continue
                addr = props.get("Address")
                current.add(str(getattr(addr, "value", addr) or path))

            for addr in current - seen:
                self._mark_connected(addr)
            for addr in seen - current:
                self._mark_disconnected(addr)
            seen = current

    # -- responses ----------------------------------------------------------

    async def _respond(self, frame: Frame, source_uuid: str | None = None) -> None:
        engine = self.protocol
        if engine is None:
            return
        try:
            responses = engine.responses_for(frame, blobs=self.blobs)
        except ProtocolError as exc:
            self.console.error(f"could not build response: {exc}")
            return

        channel = self._response_channel(source_uuid)
        for delay, data, label in responses:
            if delay:
                await asyncio.sleep(delay)
            await self.notify(data, uuid=channel, label=label)

    def _response_channel(self, source_uuid: str | None) -> str | None:
        """Pick the characteristic to answer on.

        Order of preference:
          1. an explicit `protocol.transport.notify_uuid` in the profile,
          2. a notify characteristic in the same service the client wrote to,
          3. the first notify characteristic in the tree.

        Rule 2 matters: a device may expose notify/indicate characteristics
        that have nothing to do with its command protocol - a DFU control point
        indicates, for instance - and answering on one of those would send
        every response to the wrong endpoint.
        """
        engine = self.protocol
        if engine is not None and engine.notify_uuid:
            return norm_uuid(engine.notify_uuid)

        if source_uuid:
            service_uuid = self._service_for(norm_uuid(source_uuid))
            if service_uuid:
                for service in self.profile.services:
                    if service.uuid != service_uuid:
                        continue
                    for char in service.characteristics:
                        if char.subscribable:
                            return char.uuid

        return self._default_notify_uuid()

    async def notify(self, data: bytes, uuid: str | None = None, label: str = "") -> None:
        """Push bytes to the connected central over a notify characteristic."""
        target = norm_uuid(uuid) if uuid else self._default_notify_uuid()
        if target is None:
            self.console.error("no notify characteristic in this profile - cannot send")
            return

        service_uuid = self._service_for(target)
        if service_uuid is None:
            self.console.error(f"{target} is not in the served tree")
            return

        # Resolve via the (service, char) registry built at registration time
        # rather than bless's server-wide `get_characteristic(uuid)`, which
        # returns the first match across every registered service - the wrong
        # object when the same characteristic UUID is registered under more
        # than one service.
        char = self._char_registry.get((service_uuid, target))
        if char is None:
            char = self._server.get_characteristic(target)
        if char is None:
            self.console.error(f"characteristic {target} was not registered")
            return

        # Serialize the value-set + update_value pair: two concurrently
        # scheduled responses (pipelined writes, or --repeat) must not
        # interleave their writes to the same characteristic object.
        async with self._notify_lock:
            char.value = bytearray(data)
            sent = self._server.update_value(service_uuid, target)

        if sent is False:
            # bless returns False only when it cannot find the service, so
            # this is a registration problem, not a delivery one.
            self.console.error(
                f"notify on {target} failed: bless could not resolve service "
                f"{service_uuid}, so the characteristic was never updated"
            )
            return

        subscribed = self._subscribed()
        delivered = None if subscribed is None else (target in subscribed)

        self.log.add(
            LogEntry(_ts(), "tx", target, data, label=label, delivered=delivered)
        )
        if delivered is False:
            # update_value() returns True whether or not anyone is listening,
            # so without saying this the log looks like the client was
            # answered when in fact BlueZ dropped the notification.
            self.console.warn(
                f"notify on {uuid_label(target, 'characteristic')}: no central has "
                "subscribed to it (no CCCD write seen), so BlueZ will not transmit "
                "this. The bytes were built correctly but nobody received them."
            )
        if not self.quiet:
            self.console.write(
                f"  {self.console.dim('[' + _ts() + ']')} "
                f"{self.console.green('NOTIFY <-')} {label or 'response'}  ({len(data)}B)"
            )
            self.console.hexdump(data, indent=9)

    def _subscribed(self) -> set[str] | None:
        """Characteristic UUIDs a central has actually written the CCCD for.

        None when it cannot be known (the stubbed server in tests). bless
        maintains this in `app.subscribed_characteristics`, appended by
        BlueZGattCharacteristic.StartNotify - the only trustworthy signal,
        since `update_value()` reports success whether or not anyone is
        listening.
        """
        app = getattr(self._server, "app", None)
        subs = getattr(app, "subscribed_characteristics", None)
        if subs is None:
            return None
        return {norm_uuid(u) for u in subs}

    def _default_notify_uuid(self) -> str | None:
        """Last-resort response channel.

        Firmware-update characteristics indicate too, so they are ranked last -
        picking one as the default would send protocol responses to a bootloader
        endpoint.
        """
        if not self._notify_uuids:
            return None

        from .uuids import risk_for

        def rank(uuid: str) -> int:
            risk = risk_for(uuid)
            if risk and risk.category == "firmware-update":
                return 2
            if risk and risk.category == "proprietary-protocol":
                return 0
            return 1

        return sorted(self._notify_uuids, key=rank)[0]

    def _service_for(self, char_uuid: str) -> str | None:
        for service in self.profile.services:
            for char in service.characteristics:
                if char.uuid == char_uuid:
                    return service.uuid
        return None

    # -- lifecycle ----------------------------------------------------------

    def _advertised_uuids(self) -> list[str]:
        """Which service UUIDs the advertisement should carry.

        The profile's `advertising.service_uuids` is authoritative when set -
        that block exists precisely to say what goes on the air, which is not
        necessarily the whole served tree. Falling back to the first served
        service only matters for hand-written profiles that omit the block.
        """
        declared = [norm_uuid(u) for u in (self.profile.advertising.service_uuids or [])]
        if declared:
            return declared
        for service in self.profile.services:
            if service.uuid in (norm_uuid("1800"), norm_uuid("1801")):
                continue
            return [service.uuid]
        return []

    def _fitted_advertised_uuids(self) -> list[str]:
        """Declared UUIDs trimmed to what legacy advertising data can hold.

        Legacy advertising data is 31 bytes, of which BlueZ reserves 3 for the
        flags structure. UUIDs are carried on the wire at their *native* width,
        not the normalized 128-bit form BRAT stores internally: a SIG-assigned
        UUID (Battery, Heart Rate, ...) is 2 bytes, a vendor 128-bit UUID is
        16. Costing every UUID as 16 bytes would drop SIG UUIDs that fit
        comfortably - one 128-bit UUID uses 18 of the 28 available bytes, but
        fourteen SIG UUIDs would also fit.

        UUIDs of the same width share one AD structure (one 2-byte
        length+type header for the whole group), which is why this budgets per
        width-group rather than per UUID.
        """
        by_width: dict[int, list[str]] = {}
        for uuid in self._advertised_uuids():
            if short_form(uuid):
                width = 2       # 16-bit SIG UUID
            elif is_sig(uuid):
                width = 4       # 32-bit SIG UUID (base suffix, nonzero high half)
            else:
                width = 16      # vendor 128-bit
            by_width.setdefault(width, []).append(uuid)

        budget = 31 - 3  # BlueZ reserves the flags AD structure
        fitted: list[str] = []
        # Cheapest width first, so a 16-byte vendor UUID cannot crowd out
        # several 2-byte SIG ones that would all have fit.
        for width in sorted(by_width):
            group = by_width[width]
            if budget < 2 + width:
                for uuid in group:
                    self._warnings.append(
                        f"advertising: dropped service UUID {uuid} - legacy "
                        "advertising data is limited to 31 bytes and it does not "
                        "fit alongside the UUIDs already included"
                    )
                continue
            budget -= 2  # this group's length+type header
            for uuid in group:
                if width > budget:
                    self._warnings.append(
                        f"advertising: dropped service UUID {uuid} - legacy "
                        "advertising data is limited to 31 bytes and it does not "
                        "fit alongside the UUIDs already included"
                    )
                    continue
                budget -= width
                fitted.append(uuid)

        # The Complete Local Name shares the same 31-byte allowance, but BlueZ
        # carries it in the scan response when it does not fit alongside the
        # UUIDs - which is why a 13-character name and a 128-bit UUID (36 bytes
        # together) both make it onto the air. So it is deliberately NOT
        # charged against the UUID budget above; doing that would drop the very
        # UUID a client filters on, to fix a problem that does not exist.
        #
        # It is worth saying out loud though, because a client that reads only
        # the advertising packet and never scan-requests will not see the name.
        name_bytes = len(self.advertised_name.encode("utf-8", "replace"))
        used = (31 - 3) - budget
        if fitted and 3 + 2 + name_bytes + used > 31:
            self._warnings.append(
                f"advertising: the name {self.advertised_name!r} ({name_bytes}B) and "
                f"{len(fitted)} service UUID(s) ({used}B) exceed the 31-byte "
                "advertising packet, so BlueZ will carry the name in the scan "
                "response. A client that filters on name without scan-requesting "
                "will not match. Shorten the name, or advertise fewer UUIDs, if "
                "that turns out to matter."
            )
        if name_bytes + 2 > 31:
            self._warnings.append(
                f"advertising: the name {self.advertised_name!r} is {name_bytes}B and "
                "does not fit in a scan response either - it will be truncated, and a "
                "client matching on the full name will not recognise it."
            )
        return fitted

    def _manufacturer_data(self) -> dict:
        """The profile's manufacturer data, marshalled for BlueZ.

        The D-Bus signature is a{qv}, so each value has to be wrapped in a
        Variant - handing bless bare bytes fails at registration time with an
        opaque marshalling error rather than anything mentioning this field.

        Also the place where fields the profile declares but bless cannot carry
        get reported. Silently dropping a declared field is precisely how a
        clone ends up describing a device it does not actually impersonate.
        """
        advertising = self.profile.advertising

        if advertising.appearance is not None:
            self._warnings.append(
                f"advertising.appearance ({advertising.appearance}) is declared but "
                "bless's advertisement exposes no Appearance property, so it will not "
                "go on the air. A client fingerprinting on appearance will see a "
                "difference between this and the real device."
            )
        if getattr(advertising, "tx_power", None) is not None:
            self._warnings.append(
                f"advertising.tx_power ({advertising.tx_power}) is declared but cannot "
                "be set per-advertisement here; bless sends a fixed value, which most "
                "controllers ignore."
            )

        raw = advertising.manufacturer_data or {}
        if not raw:
            return {}
        try:
            from dbus_next.signature import Variant
        except ImportError:
            self._warnings.append(
                "advertising.manufacturer_data is declared but dbus-next is not "
                "installed, so it cannot be marshalled - advertising without it."
            )
            return {}

        # as_int reads strings as hex, matching how company ids are written
        # everywhere else (0x004C, or bare 004C), and passes real ints through.
        from .protocol import as_int, parse_hex

        out = {}
        for key, value in raw.items():
            try:
                out[as_int(key)] = Variant("ay", parse_hex(value))
            except Exception as exc:  # noqa: BLE001
                self._warnings.append(
                    f"advertising.manufacturer_data[{key!r}] is not a company id "
                    f"mapped to hex bytes ({exc}) - skipping it"
                )
        return out

    def _apply_advertised_uuids(self) -> None:
        """Force the advertisement to carry the profile's declared UUIDs.

        bless hardcodes `advertisement._service_uuids.append(self.services[0].UUID)`
        - it advertises whichever service happens to be registered first and
        ignores every other one, including anything the caller asked for.

        That is wrong for any profile whose first *served* service is not the
        one clients scan for. BRAT skips GAP/GATT (BlueZ owns them), so a
        profile listing a firmware-update service before its data service
        ends up advertising the firmware-update UUID. A client that filters
        its scan by the service it expects then never matches, even though
        the advertised name is correct - the device looks absent rather than
        wrong, which is a difficult failure to attribute.
        """
        # Computed first, and unconditionally: it is also where fields the
        # profile declares but bless cannot carry get reported, and those
        # warnings must not be skipped just because no UUID made it on.
        mfg = self._manufacturer_data()

        fitted = self._fitted_advertised_uuids()
        if not fitted:
            return

        app = getattr(self._server, "app", None)
        if app is None or not hasattr(app, "app_name"):  # stubbed server in tests
            return

        # bless constructs the advertisement, appends `services[0].UUID` to it,
        # and registers it all inside `start_advertising` - there is no hook
        # between those steps, and patching the advertisement's __init__ would
        # be clobbered by the append that follows it. So replace the method on
        # this one app instance, mirroring bless's own implementation except
        # for which UUIDs go on.
        from bless.backends.bluezdbus.dbus.advertisement import (
            BlueZLEAdvertisement,
            Type,
        )

        async def start_advertising(adapter):
            await app.set_name(adapter, app.app_name)

            advertisement = BlueZLEAdvertisement(
                Type.PERIPHERAL, len(app.advertisements) + 1, app
            )
            app.advertisements.append(advertisement)
            advertisement._service_uuids = list(fitted)
            if mfg:
                advertisement._manufacturer_data = mfg

            app.bus.export(advertisement.path, advertisement)
            iface = adapter.get_interface("org.bluez.LEAdvertisingManager1")
            await iface.call_register_advertisement(advertisement.path, {})

        app.start_advertising = start_advertising

    async def start(self) -> None:
        if self._server is None:
            raise PeripheralError("build() must run before start()")
        self._apply_advertised_uuids()
        await self._start_connection_watch()
        self._sub_task = asyncio.create_task(self._subscription_poll_loop())
        try:
            await self._server.start()
        except Exception as exc:  # noqa: BLE001
            # The nRF52840's Zephyr hci_usb firmware leaks advertising
            # resources across start/stop cycles: after enough sessions the
            # controller answers LE Set Advertise Enable with "Memory
            # Capacity Exceeded" and BlueZ surfaces that as an opaque
            # registration failure. Restarting bluetoothd does NOT clear it -
            # the exhausted state lives on the controller - but cycling the
            # adapter down and up does. Recover once automatically rather
            # than making the operator diagnose this mid-session.
            recovered, detail = self._recover_adapter()
            if not recovered:
                raise PeripheralError(self._explain_start_failure(exc, detail)) from exc
            self.console.warn(
                f"advertising registration failed; {detail} and retrying"
            )
            # bless exports the GATT application on the bus and registers it
            # *before* it registers the advertisement, so a failure at the
            # advertising step leaves those two behind. Retrying without
            # undoing them fails differently and more confusingly ("An
            # interface with this name is already exported on this bus").
            await self._undo_partial_registration()
            await asyncio.sleep(1.0)
            try:
                await self._server.start()
            except Exception as exc2:  # noqa: BLE001
                raise PeripheralError(self._explain_start_failure(exc2)) from exc2

    async def _undo_partial_registration(self) -> None:
        """Best-effort teardown of whatever bless's `start()` managed before failing."""
        app = getattr(self._server, "app", None)
        adapter = getattr(self._server, "adapter", None)
        if app is None:
            return

        # Advertisements first. The patched start_advertising appends to
        # app.advertisements and exports the object *before* the registration
        # that failed, so without this the object stays on the bus forever and
        # the retry creates advertisement2 - bless derives the index from
        # len(advertisements) + 1. Clearing the list also puts the retry back
        # at advertisement1. bless's own stop_advertising only pops, never
        # unexports, so this compensates for that too.
        for adv in list(getattr(app, "advertisements", [])):
            if adapter is not None:
                try:
                    iface = adapter.get_interface("org.bluez.LEAdvertisingManager1")
                    await asyncio.wait_for(
                        iface.call_unregister_advertisement(adv.path), timeout=5.0
                    )
                except Exception:  # noqa: BLE001 - it may never have registered
                    pass
            try:
                self._server.bus.unexport(adv.path, adv)
            except Exception:  # noqa: BLE001
                pass
        try:
            app.advertisements.clear()
        except Exception:  # noqa: BLE001
            pass

        if adapter is not None:
            try:
                await asyncio.wait_for(app.unregister(adapter), timeout=5.0)
            except Exception:  # noqa: BLE001
                pass
        try:
            self._server.bus.unexport(app.path, app)
        except Exception:  # noqa: BLE001
            pass

    def _recover_adapter(self) -> tuple[bool, str]:
        """Cycle the HCI adapter down and up. Returns (ran, detail).

        This is the only thing observed to clear the controller-side
        advertising exhaustion described in `start()`; a bluetoothd restart
        leaves it in place.

        The return codes are checked because the previous version reported
        success whenever `hciconfig` merely *existed*: without root both calls
        fail silently, and the operator was told the adapter had been reset
        and the failure retried when neither had happened.
        """
        import os
        import shutil
        import subprocess

        if not shutil.which("hciconfig"):
            return False, "hciconfig is not installed (it is in the bluez package)"
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False, "resetting the adapter needs root - re-run under sudo"

        adapter = self.adapter or "hci0"
        for action in ("down", "up"):
            try:
                proc = subprocess.run(
                    ["hciconfig", adapter, action],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except Exception as exc:  # noqa: BLE001
                return False, f"hciconfig {adapter} {action} could not run: {exc}"
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()
                return False, (
                    f"hciconfig {adapter} {action} failed "
                    f"(exit {proc.returncode}){': ' + detail if detail else ''}"
                )
        return True, f"cycled {adapter} down and up"

    @staticmethod
    def _explain_start_failure(exc: Exception, recovery_detail: str = "") -> str:
        """Turn BlueZ's opaque registration errors into an actionable message.

        `org.bluez.Error.Failed: Failed to register advertisement` is what
        BlueZ returns for several unrelated conditions, and on its own tells
        the operator nothing about which one they hit. The two that actually
        occur in practice - a previous session's advertisement still
        registered, and the controller having exhausted its own advertising
        resources - have different fixes, and the second one is not solved by
        restarting bluetoothd, which is the obvious thing to try first.
        """
        text = str(exc)
        if "advertisement" not in text.lower():
            return text
        # Say whether the automatic reset actually ran. Without this the
        # message asserts "resetting the adapter did not clear it" even when
        # the reset never happened - which sends the operator past the one
        # step that would have worked.
        preamble = (
            f"  The automatic adapter reset did not run: {recovery_detail}.\n"
            if recovery_detail
            else "  Resetting the adapter did not clear it.\n"
        )
        return (
            f"{text}\n"
            "  BlueZ refused to register the advertisement.\n"
            f"{preamble}"
            "  Try, in order:\n"
            "    1. sudo hciconfig <adapter> down && sudo hciconfig <adapter> up\n"
            "       (clears controller-side advertising exhaustion - the usual cause)\n"
            "    2. Check `brat doctor` (ADV SLOTS column) for a leftover advertisement\n"
            "       from a previous session, and stop any lingering brat process.\n"
            "    3. sudo systemctl restart bluetooth  (clears BlueZ's own state)\n"
            "    4. Power-cycle the adapter - unplug and replug a USB dongle."
        )

    async def stop(self, timeout: float = 5.0) -> None:
        # Let in-flight responses finish before tearing the server down. Rules
        # routinely stagger their frames with delays of a second or more to
        # match real device timing, so cutting them off here would truncate a
        # handshake that was working and make it look like the client was
        # ignored.
        if self._pending:
            try:
                await asyncio.wait(set(self._pending), timeout=min(timeout, 3.0))
            except Exception:  # noqa: BLE001 - teardown is best-effort
                pass
            for task in list(self._pending):
                task.cancel()

        for attr in ("_watch_task", "_sub_task"):
            task = getattr(self, attr)
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            setattr(self, attr, None)
        if self._watch_bus is not None:
            try:
                self._watch_bus.disconnect()
            except Exception:  # noqa: BLE001 - teardown is best-effort
                pass
            self._watch_bus = None
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.stop(), timeout=timeout)
            except Exception:  # noqa: BLE001 - teardown is best-effort, including timeout
                pass

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)

    def summary(self) -> dict:
        return {
            "advertised_name": self.advertised_name,
            "profile": self.profile.slug,
            "services_served": self._served_service_count,
            "characteristics_served": self._served_characteristic_count,
            "notify_characteristics": self._notify_uuids,
            "protocol": self.protocol.name if self.protocol else None,
            # Deliberately `ever_connected`, not the live `connected` flag -
            # a summary is a record of the session, not a snapshot of the
            # instant it was torn down.
            "connected": self.ever_connected,
            "connected_now": self.connected,
            "connections": self.connections,
            "central_address": self.central_address,
            "warnings": self._warnings,
            "errors": list(self._errors),
            "session": self.log.to_dict(),
        }

    @property
    def errors(self) -> list[str]:
        """Tracebacks from the response path, if any responses failed to build."""
        return list(self._errors)


async def run_until_interrupt(
    peripheral: RoguePeripheral,
    console: Console,
    duration: float | None = None,
) -> None:
    """Advertise until Ctrl-C or `duration` seconds elapse."""
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    import signal

    installed_handlers = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
            installed_handlers.append(sig)
        except (NotImplementedError, RuntimeError):
            pass

    if duration:
        loop.call_later(duration, stop.set)

    started = time.monotonic()
    try:
        await stop.wait()
    finally:
        # Restore default signal handling before returning - otherwise a
        # second Ctrl-C after this function returns just re-sets an already-
        # set Event with nothing left listening, instead of behaving like a
        # normal interrupt, and a leaked handler can also affect whatever
        # runs next in the same process (e.g. a second command in a script).
        for sig in installed_handlers:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass
        elapsed = time.monotonic() - started
        console.write()
        console.info(f"Stopping after {elapsed:.1f}s ...")
        await peripheral.stop()
