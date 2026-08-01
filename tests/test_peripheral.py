"""Peripheral engine tests.

These exercise everything up to the radio: property translation, the write
handler's decode path, emulation dispatch, and session logging. The bless
server itself is stubbed, so the suite runs without a Bluetooth adapter.
"""

import asyncio
from pathlib import Path

import pytest

from brat.core.console import Console
from brat.core.peripheral import (
    LogEntry,
    RoguePeripheral,
    SessionLog,
    build_permissions,
    build_properties,
    run_until_interrupt,
)
from brat.core.profile import (
    AdvertisingSpec,
    CharacteristicSpec,
    MatchSpec,
    Profile,
    ServiceSpec,
    load_profile,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"   # central writes here
NUS_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"   # peripheral notifies here

pytest.importorskip("bless", reason="peripheral mode requires bless")

from bless.backends.characteristic import (  # noqa: E402
    GATTAttributePermissions,
    GATTCharacteristicProperties,
)
from bless.backends.descriptor import GATTDescriptorProperties  # noqa: E402


@pytest.fixture
def mira(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    return load_profile("mira_ultra4")


@pytest.fixture
def console():
    return Console(force_color=False)


# ---------------------------------------------------------------------------
# Property translation
# ---------------------------------------------------------------------------


def test_property_strings_map_to_bless_flags():
    flags, unknown = build_properties(
        ["read", "write", "write-without-response", "notify"],
        GATTCharacteristicProperties,
    )
    assert unknown == []
    assert flags & GATTCharacteristicProperties.read
    assert flags & GATTCharacteristicProperties.write
    assert flags & GATTCharacteristicProperties.write_without_response
    assert flags & GATTCharacteristicProperties.notify
    assert not flags & GATTCharacteristicProperties.indicate


def test_underscore_and_hyphen_spellings_both_accepted():
    hyphen, _ = build_properties(["write-without-response"], GATTCharacteristicProperties)
    underscore, _ = build_properties(
        ["write_without_response"], GATTCharacteristicProperties
    )
    assert hyphen == underscore


def test_unknown_properties_reported_not_raised():
    flags, unknown = build_properties(
        ["read", "telepathy"], GATTCharacteristicProperties
    )
    assert unknown == ["telepathy"]
    assert flags & GATTCharacteristicProperties.read


def test_empty_properties_default_to_readable():
    flags, _ = build_properties([], GATTCharacteristicProperties)
    assert flags & GATTCharacteristicProperties.read


def test_permissions_mirror_the_cloned_device(mira):
    """A clone must not be served more securely than the original.

    Serving it with encryption required would make the client behave
    differently against the clone than against the real device.
    """
    nus_rx = mira.characteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
    perms = build_permissions(nus_rx, GATTAttributePermissions)
    assert perms & GATTAttributePermissions.writeable
    assert not perms & GATTAttributePermissions.write_encryption_required

    nus_tx = mira.characteristic("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
    assert build_permissions(nus_tx, GATTAttributePermissions) & (
        GATTAttributePermissions.readable
    )


# ---------------------------------------------------------------------------
# Session log
# ---------------------------------------------------------------------------


def test_session_log_separates_directions():
    log = SessionLog()
    log.add(LogEntry("00:00:01", "rx", "uuid", b"\x01"))
    log.add(LogEntry("00:00:02", "tx", "uuid", b"\x02\x03"))
    assert len(log.rx) == 1
    assert len(log.tx) == 1
    doc = log.to_dict()
    assert doc["received"] == 1
    assert doc["sent"] == 1
    assert doc["entries"][1]["hex"] == "0203"


# ---------------------------------------------------------------------------
# Write handling and emulation dispatch
# ---------------------------------------------------------------------------


class FakeCharacteristic:
    def __init__(self, uuid):
        self.uuid = uuid
        self.value = bytearray()


class FakeService:
    """Mirrors bless's BlessGATTService.get_characteristic - scoped to one service."""

    def __init__(self, chars: dict):
        self._chars = chars

    def get_characteristic(self, uuid):
        return self._chars.get(uuid)


class FakeApp:
    """Stand-in for bless's BlueZGattApplication.

    Only `subscribed_characteristics` matters here: it is where bless records
    CCCD writes, and therefore the only way to know whether a notification
    would actually be transmitted.
    """

    def __init__(self):
        self.subscribed_characteristics = []


class FakeServer:
    """Minimal stand-in for BlessServer."""

    # `adapter` is accepted because the real BlessServer takes it as a kwarg
    # and RoguePeripheral.build() passes it whenever --adapter was given. A
    # stub without it silently forces every test down the no-adapter path.
    def __init__(self, name, adapter=None):
        self.name = name
        self.adapter = adapter
        self.chars = {}
        self.updates = []
        self.descriptors = []
        self.started = False
        self.app = FakeApp()

    async def add_new_service(self, uuid):
        self.chars.setdefault(uuid, {})

    async def add_new_characteristic(self, svc, char, props, value, perms):
        c = FakeCharacteristic(char)
        c.value = bytearray(value or b"")
        self.chars[svc][char] = c

    async def add_new_descriptor(self, svc, char, desc_uuid, props, value, perms):
        self.descriptors.append((svc, char, desc_uuid, value))

    def get_service(self, uuid):
        chars = self.chars.get(uuid)
        return FakeService(chars) if chars is not None else None

    def get_characteristic(self, uuid):
        for chars in self.chars.values():
            if uuid in chars:
                return chars[uuid]
        return None

    def update_value(self, svc, char):
        self.updates.append((svc, char))
        return True

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False


@pytest.fixture
def peripheral(mira, console, monkeypatch):
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    return RoguePeripheral(profile=mira, console=console, quiet=True)


def test_build_serves_the_profile_tree(peripheral):
    asyncio.run(peripheral.build())
    server = peripheral._server

    # BlueZ owns GAP and GATT, so those are skipped with a warning.
    assert any("Generic Access" in w for w in peripheral.warnings)
    assert "6e400001-b5a3-f393-e0a9-e50e24dcca9e" in server.chars
    nus = server.chars["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]
    assert "6e400002-b5a3-f393-e0a9-e50e24dcca9e" in nus
    assert "6e400003-b5a3-f393-e0a9-e50e24dcca9e" in nus

    # The notify characteristic is registered as the default response channel.
    assert peripheral._default_notify_uuid() == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"


def test_write_is_decoded_and_logged(peripheral, mira):
    asyncio.run(peripheral.build())
    engine = mira.protocol

    payload = b"IDENT001" + bytes.fromhex("69C1B4B0") + bytes.fromhex("014A")
    frame = engine.codec.build({"direction": 0, "cmd": 0xA3, "payload": payload})

    char = FakeCharacteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
    peripheral._loop = None  # suppress response scheduling; tested separately
    peripheral._on_write(char, bytearray(frame))

    assert peripheral.connected
    assert len(peripheral.log.rx) == 1
    entry = peripheral.log.rx[0]
    assert entry.data == frame
    assert "CMD=0xA3 (AUTH)" in entry.decoded


def test_unrecognised_frame_is_logged_not_dropped(peripheral):
    asyncio.run(peripheral.build())
    char = FakeCharacteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
    peripheral._loop = None
    peripheral._on_write(char, bytearray(b"\xde\xad\xbe\xef"))

    entry = peripheral.log.rx[0]
    assert entry.data == b"\xde\xad\xbe\xef"
    assert "not a recognised frame" in entry.decoded
    assert entry.frame_ok is False


def test_valid_frame_is_marked_frame_ok(peripheral, mira):
    asyncio.run(peripheral.build())
    engine = mira.protocol
    payload = b"IDENT001" + bytes.fromhex("69C1B4B0") + bytes.fromhex("014A")
    frame = engine.codec.build({"direction": 0, "cmd": 0xA3, "payload": payload})

    char = FakeCharacteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
    peripheral._loop = None
    peripheral._on_write(char, bytearray(frame))

    assert peripheral.log.rx[0].frame_ok is True


def test_corrupt_checksum_frame_is_not_marked_frame_ok(peripheral, mira):
    """A structurally valid frame with a bad CRC must not count as a genuine command."""
    asyncio.run(peripheral.build())
    engine = mira.protocol
    payload = b"IDENT001" + bytes.fromhex("69C1B4B0") + bytes.fromhex("014A")
    frame = bytearray(engine.codec.build({"direction": 0, "cmd": 0xA3, "payload": payload}))
    frame[-2] ^= 0xFF  # corrupt one CRC byte, leaving framing intact

    char = FakeCharacteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
    peripheral._loop = None
    peripheral._on_write(char, bytearray(frame))

    entry = peripheral.log.rx[0]
    assert entry.frame_ok is False


def test_read_reply_is_tagged_and_marks_connected_even_when_quiet(mira, console, monkeypatch):
    """Regression: a read-only session must be visible even in quiet/JSON mode."""
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    rogue = RoguePeripheral(profile=mira, console=console, quiet=True)
    asyncio.run(rogue.build())

    char = FakeCharacteristic("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
    char.value = bytearray(b"\x01\x02")
    rogue._on_read(char)

    assert rogue.connected is True
    entry = rogue.log.tx[0]
    assert entry.origin == "read-reply"


def test_notify_response_is_tagged_protocol_response(peripheral, mira):
    async def scenario():
        await peripheral.build()
        await peripheral.notify(b"\x01\x02", uuid="6e400003-b5a3-f393-e0a9-e50e24dcca9e")

    asyncio.run(scenario())
    entry = peripheral.log.tx[0]
    assert entry.origin == "protocol-response"


def test_emulation_responses_are_sent_on_notify_channel(peripheral, mira):
    async def scenario():
        await peripheral.build()
        engine = mira.protocol
        payload = b"IDENT001" + bytes.fromhex("69C1B4B0") + bytes.fromhex("014A")
        frame = engine.decode(
            engine.codec.build({"direction": 0, "cmd": 0xA3, "payload": payload})
        )
        # Zero out the profile's delays so the test does not sleep.
        for rule in engine.rules:
            for response in rule.responses:
                response.delay = 0
        await peripheral._respond(frame)

    asyncio.run(scenario())

    sent = peripheral.log.tx
    assert len(sent) == 2
    assert [e.label for e in sent] == ["A3-ack", "A4-confirm"]

    engine = mira.protocol
    ack = engine.decode(sent[0].data)
    assert ack.checksum_ok and ack.cmd == 0xA3
    assert ack.payload == b"IDENT001\x01"

    confirm = engine.decode(sent[1].data)
    assert confirm.checksum_ok and confirm.cmd == 0xA4
    assert confirm.payload[8:16] == bytes.fromhex("DEADBEEFCAFE0001")

    # Both went out over the NUS notify characteristic.
    assert all(u[1] == "6e400003-b5a3-f393-e0a9-e50e24dcca9e" for u in peripheral._server.updates)


def test_dfu_indicate_is_never_the_response_channel(peripheral, mira):
    """Regression: an indicating DFU characteristic must not win the default.

    The Mira tree exposes a Buttonless DFU characteristic with `indicate`,
    which is subscribable and appears before NUS TX in the profile. Ranking by
    tree order alone sent every protocol response to the bootloader endpoint.
    """
    asyncio.run(peripheral.build())

    assert "8ec90003-f315-4f60-9fb8-838830daea50" in peripheral._notify_uuids
    assert peripheral._default_notify_uuid() != "8ec90003-f315-4f60-9fb8-838830daea50"
    assert (
        peripheral._response_channel("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
        == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
    )


def test_explicit_transport_overrides_inference(peripheral, mira):
    assert mira.protocol.notify_uuid == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
    asyncio.run(peripheral.build())
    # Even given a nonsense source characteristic, the declared channel wins.
    assert (
        peripheral._response_channel("8ec90003-f315-4f60-9fb8-838830daea50")
        == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
    )


def test_response_channel_prefers_same_service(monkeypatch, console, tmp_path):
    """With no explicit transport, answer on the service the client wrote to."""
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    monkeypatch.chdir(tmp_path)
    profile = load_profile("mira_ultra4")
    profile.protocol_config = {
        **profile.protocol_config,
        "transport": {},  # drop the explicit declaration
    }
    profile._engine = None
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    asyncio.run(rogue.build())

    assert (
        rogue._response_channel("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
        == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
    )


def test_summary_reports_the_session(peripheral):
    asyncio.run(peripheral.build())
    summary = peripheral.summary()
    assert summary["advertised_name"] == "Mira-Analyzer"
    assert summary["profile"] == "mira_ultra4"
    assert summary["protocol"] == "mira-a5"
    assert summary["connected"] is False


def test_summary_counts_only_what_was_actually_served(peripheral, mira):
    """Regression: services_served/characteristics_served must not count
    services build() skipped (BlueZ owns Generic Access/Generic Attribute).

    The Mira profile declares GAP + GATT + NUS, so the served count must be
    fewer services/characteristics than the profile's full tree.
    """
    asyncio.run(peripheral.build())
    summary = peripheral.summary()

    profile_service_count = len(mira.services)
    profile_char_count = sum(len(s.characteristics) for s in mira.services)

    assert summary["services_served"] < profile_service_count
    assert summary["characteristics_served"] < profile_char_count
    # And the served count is exactly what's left after GAP/GATT are dropped.
    skipped_service_uuids = {
        "00001800-0000-1000-8000-00805f9b34fb",
        "00001801-0000-1000-8000-00805f9b34fb",
    }
    expected_services = [s for s in mira.services if s.uuid not in skipped_service_uuids]
    assert summary["services_served"] == len(expected_services)
    assert summary["characteristics_served"] == sum(
        len(s.characteristics) for s in expected_services
    )


def test_name_override_changes_advertised_identity(mira, console):
    rogue = RoguePeripheral(profile=mira, console=console, name_override="BRAT-Demo")
    assert rogue.advertised_name == "BRAT-Demo"


def test_profile_without_protocol_still_serves(monkeypatch, console):  # noqa: D103
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    profile = Profile.load(REPO_ROOT / "brat" / "profiles" / "example_wearable.yaml")
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    asyncio.run(rogue.build())

    assert rogue.protocol is None
    char = FakeCharacteristic("00002a19-0000-1000-8000-00805f9b34fb")
    rogue._loop = None
    rogue._on_write(char, bytearray(b"\x01\x02"))
    # Logged raw, with no decode attempted and no crash.
    assert rogue.log.rx[0].data == b"\x01\x02"
    assert rogue.log.rx[0].decoded == ""


def _duplicate_uuid_profile() -> Profile:
    """Same characteristic UUID registered under two different services.

    A duplicated vendor control-point UUID across an app service and a
    firmware-update service is the kind of tree a real device can legitimately
    have. Regression fixture for notify() resolving the wrong object.
    """
    shared_char_uuid = "abcd0001-0000-1000-8000-00805f9b34fb"
    return Profile(
        slug="dup_uuid_device",
        name="Dup-UUID-Device",
        services=[
            ServiceSpec(
                uuid="abcd1111-0000-1000-8000-00805f9b34fb",
                characteristics=[
                    CharacteristicSpec(
                        uuid=shared_char_uuid, properties=["write", "notify"]
                    )
                ],
            ),
            ServiceSpec(
                uuid="abcd2222-0000-1000-8000-00805f9b34fb",
                characteristics=[
                    CharacteristicSpec(
                        uuid=shared_char_uuid, properties=["write", "notify"]
                    )
                ],
            ),
        ],
    )


@pytest.fixture
def dup_peripheral(console, monkeypatch):
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    return RoguePeripheral(profile=_duplicate_uuid_profile(), console=console, quiet=True)


def test_notify_resolves_the_object_from_the_stated_service(dup_peripheral):
    """Regression: a UUID shared by two services must notify the RIGHT one.

    Before the (service, char) registry, notify() resolved the characteristic
    via a server-wide, first-match lookup independent of which service_uuid
    it was told to signal on - the value could be set on one service's
    characteristic object while BlueZ was told to notify the other.
    """
    asyncio.run(dup_peripheral.build())

    char_uuid = "abcd0001-0000-1000-8000-00805f9b34fb"
    service_2 = "abcd2222-0000-1000-8000-00805f9b34fb"

    asyncio.run(dup_peripheral.notify(b"\xaa\xbb", uuid=char_uuid))

    # The object actually mutated must be the one registered under whichever
    # service _response_channel/_service_for resolved to (the first service,
    # since _service_for returns the first match in profile order) - and
    # update_value must have been called with that SAME service_uuid, not a
    # mismatched pair.
    server = dup_peripheral._server
    updated_svc, updated_char = server.updates[-1]
    resolved_obj = dup_peripheral._char_registry[(updated_svc, updated_char)]
    assert resolved_obj.value == bytearray(b"\xaa\xbb")

    # And the object under the OTHER service must be untouched.
    other_svc = service_2 if updated_svc != service_2 else "abcd1111-0000-1000-8000-00805f9b34fb"
    other_obj = dup_peripheral._char_registry[(other_svc, char_uuid)]
    assert other_obj.value != bytearray(b"\xaa\xbb")


def test_concurrent_notify_calls_do_not_interleave(peripheral):
    """Two responses scheduled back-to-back must not corrupt each other's value.

    Without the lock, task A could set char.value = X, task B could then set
    char.value = Y before A calls update_value, and the log/central would
    both see Y sent twice - never X.
    """
    asyncio.run(peripheral.build())

    async def scenario():
        results = await asyncio.gather(
            peripheral.notify(b"\x01" * 20, uuid="6e400003-b5a3-f393-e0a9-e50e24dcca9e", label="first"),
            peripheral.notify(b"\x02" * 20, uuid="6e400003-b5a3-f393-e0a9-e50e24dcca9e", label="second"),
        )
        return results

    asyncio.run(scenario())

    # Both notifications must appear in the log distinctly (not one dropped,
    # not both showing the same bytes for both labels).
    tx = peripheral.log.tx
    assert len(tx) == 2
    payloads = {e.label: e.data for e in tx}
    assert payloads["first"] == b"\x01" * 20
    assert payloads["second"] == b"\x02" * 20


def test_notify_not_logged_when_update_value_reports_failure(peripheral, monkeypatch):
    """update_value returning False must not be logged as a sent notification."""
    asyncio.run(peripheral.build())
    monkeypatch.setattr(peripheral._server, "update_value", lambda svc, char: False)

    asyncio.run(peripheral.notify(b"\x01\x02", uuid="6e400003-b5a3-f393-e0a9-e50e24dcca9e"))

    assert len(peripheral.log.tx) == 0


def _profile_with_user_description(monkeypatch, console):
    """A characteristic with a non-CCCD descriptor (User Description, 2901).

    Regression fixture for descriptors that a clone captured being silently
    dropped: a client that reads 2901 to identify an endpoint would behave
    differently against the served clone than against the real device.
    """
    import brat.core.peripheral as mod
    from brat.core.profile import CharacteristicSpec, DescriptorSpec, Profile, ServiceSpec

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    profile = Profile(
        slug="desc_device",
        name="Desc-Device",
        services=[
            ServiceSpec(
                uuid="abcd1111-0000-1000-8000-00805f9b34fb",
                characteristics=[
                    CharacteristicSpec(
                        uuid="abcd0001-0000-1000-8000-00805f9b34fb",
                        properties=["read", "notify"],
                        descriptors=[
                            # CCCD - must be skipped, BlueZ auto-manages it.
                            DescriptorSpec(uuid="00002902-0000-1000-8000-00805f9b34fb"),
                            # User Description - has no automatic handling,
                            # must be explicitly served.
                            DescriptorSpec(
                                uuid="00002901-0000-1000-8000-00805f9b34fb",
                                name="Characteristic User Description",
                                value="53656e736f72",  # "Sensor" in hex
                            ),
                        ],
                    )
                ],
            )
        ],
    )
    return RoguePeripheral(profile=profile, console=console, quiet=True)


def test_non_cccd_descriptor_is_served(console, monkeypatch):
    rogue = _profile_with_user_description(monkeypatch, console)
    asyncio.run(rogue.build())

    served = [d for d in rogue._server.descriptors if d[2] == "00002901-0000-1000-8000-00805f9b34fb"]
    assert len(served) == 1
    assert served[0][3] == bytes.fromhex("53656e736f72")


def test_cccd_descriptor_is_not_registered(console, monkeypatch):
    """BlueZ auto-manages the CCCD - registering it again would conflict, not add."""
    rogue = _profile_with_user_description(monkeypatch, console)
    asyncio.run(rogue.build())

    served_uuids = [d[2] for d in rogue._server.descriptors]
    assert "00002902-0000-1000-8000-00805f9b34fb" not in served_uuids


def test_characteristics_register_empty_so_reads_reach_the_handler(console, monkeypatch):
    """Regression: BlueZ answers reads from bless's cached `Value` D-Bus
    property without ever calling ReadValue(), so a populated registration
    made every client read invisible to BRAT. Confirmed on hardware: a phone
    performed 2 ATT Read Requests and the session log recorded nothing.

    Registering empty forces BlueZ to ask us; `_on_read` still serves the
    profile's value, so the client gets the correct bytes either way.
    """
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    profile = Profile(
        slug="valued_char",
        name="Valued",
        services=[
            ServiceSpec(
                uuid="abcd1111-0000-1000-8000-00805f9b34fb",
                characteristics=[
                    CharacteristicSpec(
                        uuid="abcd0001-0000-1000-8000-00805f9b34fb",
                        properties=["read"],
                        value="48656c6c6f",  # "Hello"
                    )
                ],
            )
        ],
    )
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    asyncio.run(rogue.build())

    registered = rogue._server.chars["abcd1111-0000-1000-8000-00805f9b34fb"][
        "abcd0001-0000-1000-8000-00805f9b34fb"
    ]
    assert bytes(registered.value) == b""  # nothing for BlueZ to serve from cache

    # ...but a read still returns the profile's value, and gets logged.
    served = rogue._on_read(registered)
    assert bytes(served) == b"Hello"
    assert len(rogue.log.tx) == 1
    assert rogue.log.tx[0].origin == "read-reply"


def test_advertised_uuids_come_from_the_profile_not_registration_order(peripheral, mira):
    """Regression: bless advertises `services[0].UUID` and ignores everything else.

    BRAT skips GAP/GATT (BlueZ owns them), so the Mira profile's first
    *served* service is Nordic Secure DFU - meaning bless advertised the
    firmware-update UUID while the profile plainly declared NUS in its
    `advertising.service_uuids`. A client filtering its scan on the service
    it expects never matched, so the device looked absent rather than
    misconfigured. Confirmed on real hardware via btmon: the advertisement
    carried 0xfe59 (Nordic DFU) instead of the 128-bit NUS UUID.
    """
    nus = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
    dfu = "0000fe59-0000-1000-8000-00805f9b34fb"

    advertised = peripheral._advertised_uuids()
    assert advertised == [nus]
    assert dfu not in advertised


def test_advertised_uuids_fall_back_to_first_served_service(console, monkeypatch):
    """A hand-written profile with no advertising block still advertises
    something sensible - and still never GAP/GATT, which BlueZ owns."""
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    profile = Profile(
        slug="no_adv_block",
        name="No-Adv-Block",
        services=[
            ServiceSpec(uuid="00001800-0000-1000-8000-00805f9b34fb"),  # GAP, skipped
            ServiceSpec(uuid="abcd1234-0000-1000-8000-00805f9b34fb"),
        ],
    )
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    assert rogue._advertised_uuids() == ["abcd1234-0000-1000-8000-00805f9b34fb"]


def test_oversized_advertised_uuid_set_is_dropped_with_a_warning(console, monkeypatch):
    """Legacy advertising data caps at 31 bytes - two 128-bit UUIDs cannot both
    fit, and silently overflowing gets the whole registration rejected by the
    controller with an opaque error."""
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    # Genuinely vendor-range UUIDs (16 bytes each on the wire). Note these
    # must NOT end in the SIG base suffix, or they are carried as 2/4-byte
    # short forms and two of them fit comfortably.
    a = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
    b = "8ec90001-f315-4f60-9fb8-838830daea50"
    profile = Profile(
        slug="too_many_uuids",
        name="Too-Many",
        advertising=AdvertisingSpec(local_name="Too-Many", service_uuids=[a, b]),
        services=[ServiceSpec(uuid=a)],
    )
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    asyncio.run(rogue.build())

    fitted = rogue._fitted_advertised_uuids()
    assert fitted == [a]  # only the first fits in 28 usable bytes
    assert any("dropped service UUID" in w and b in w for w in rogue.warnings)


def test_sig_uuids_are_costed_at_their_wire_width_not_128_bit(console, monkeypatch):
    """Regression: SIG UUIDs are 2 bytes on the wire, not 16.

    BRAT normalizes every UUID to full 128-bit form internally, so costing by
    string length dropped SIG UUIDs that fit easily - observed on hardware as
    example_wearable advertising Heart Rate but silently omitting Battery,
    even though both fit in a single 4-byte AD structure.
    """
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    heart_rate = "0000180d-0000-1000-8000-00805f9b34fb"
    battery = "0000180f-0000-1000-8000-00805f9b34fb"
    profile = Profile(
        slug="two_sig_uuids",
        name="Two-SIG",
        advertising=AdvertisingSpec(
            local_name="Two-SIG", service_uuids=[heart_rate, battery]
        ),
        services=[ServiceSpec(uuid=heart_rate)],
    )
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)

    assert rogue._fitted_advertised_uuids() == [heart_rate, battery]
    assert not rogue.warnings


def test_run_until_interrupt_removes_its_signal_handlers(peripheral, console):
    """Regression: a leaked SIGINT/SIGTERM handler affects whatever runs next
    in the same process, and makes a second Ctrl-C behave like a no-op
    instead of a normal interrupt.
    """
    import signal

    asyncio.run(peripheral.build())

    async def scenario():
        loop = asyncio.get_running_loop()
        await run_until_interrupt(peripheral, console, duration=0.01)
        # After returning, the loop must have no handler installed for
        # either signal - remove_signal_handler returns False if there was
        # nothing to remove, which is exactly what "cleaned up" looks like.
        for sig in (signal.SIGINT, signal.SIGTERM):
            assert loop.remove_signal_handler(sig) is False

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Response-path failures must be visible
#
# These pin the defect that made every other bug in this file hard to find:
# the response coroutine's Future was discarded, so a broken emulation rule
# produced no output, no traceback, and no finding - indistinguishable from a
# client that simply never said anything.
# ---------------------------------------------------------------------------


def _a3_frame(mira):
    return mira.protocol.codec.build({"cmd": 0xA3, "payload": b"IDENT001" + b"\x00" * 6})


def test_response_exception_is_reported_not_swallowed(mira, monkeypatch):
    import io

    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    # An explicit stream rather than capsys/capfd: Console binds its stream at
    # construction, so what it writes to is decided before pytest's capture
    # fixtures are in play.
    stream = io.StringIO()
    peripheral = RoguePeripheral(
        profile=mira,
        console=Console(stream=stream, force_color=False),
        quiet=True,
    )
    asyncio.run(peripheral.build())

    def boom(*a, **k):
        raise RuntimeError("template exploded")

    peripheral.profile.protocol.responses_for = boom

    async def scenario():
        peripheral._loop = asyncio.get_running_loop()
        peripheral._on_write(FakeCharacteristic(NUS_TX), _a3_frame(mira))
        await asyncio.sleep(0.05)

    asyncio.run(scenario())

    assert peripheral.errors, "a failing response rule recorded no error"
    assert "template exploded" in peripheral.errors[0]
    assert "RuntimeError" in peripheral.errors[0]
    # Reported to the operator too, not just stashed on the object - and
    # reported even though the peripheral is quiet, since suppressing an error
    # because the operator asked for JSON is the exact failure being fixed.
    assert "template exploded" in stream.getvalue()


def test_response_errors_reach_the_session_summary(peripheral, mira):
    asyncio.run(peripheral.build())
    peripheral.profile.protocol.responses_for = lambda *a, **k: 1 / 0

    async def scenario():
        peripheral._loop = asyncio.get_running_loop()
        peripheral._on_write(FakeCharacteristic(NUS_TX), _a3_frame(mira))
        await asyncio.sleep(0.05)

    asyncio.run(scenario())
    assert any("ZeroDivisionError" in e for e in peripheral.summary()["errors"])


def test_pending_responses_are_drained_on_stop(peripheral, mira):
    """A rule that staggers frames must not be cut off by teardown.

    The Mira profile's A4 confirm is 1.2s behind its A3 ack; stopping without
    draining loses it and the session reads as though the client was ignored.
    """
    asyncio.run(peripheral.build())
    sent = []

    async def slow(frame, uuid=None):
        await asyncio.sleep(0.2)
        sent.append("late")

    peripheral._respond = slow

    async def scenario():
        peripheral._loop = asyncio.get_running_loop()
        peripheral._on_write(FakeCharacteristic(NUS_TX), _a3_frame(mira))
        assert peripheral._pending, "the response was not tracked"
        await peripheral.stop()

    asyncio.run(scenario())
    assert sent == ["late"], "stop() cut off an in-flight response"


# ---------------------------------------------------------------------------
# Notification delivery
# ---------------------------------------------------------------------------


def test_notify_is_marked_undelivered_when_nobody_subscribed(peripheral):
    """bless's update_value() returns True whether or not anyone is listening,
    so without the CCCD check a log of unheard notifications looks identical
    to one the client received.
    """
    asyncio.run(peripheral.build())
    asyncio.run(peripheral.notify(b"\x01\x02", uuid=NUS_RX, label="test"))

    entry = peripheral.log.tx[-1]
    assert entry.delivered is False
    assert entry.to_dict()["delivered"] is False


def test_notify_is_marked_delivered_once_a_central_subscribes(peripheral):
    asyncio.run(peripheral.build())
    peripheral._server.app.subscribed_characteristics.append(NUS_RX)
    asyncio.run(peripheral.notify(b"\x01\x02", uuid=NUS_RX, label="test"))

    assert peripheral.log.tx[-1].delivered is True


def test_delivery_is_unknown_when_the_server_exposes_no_app(peripheral):
    """Never claim a notification was dropped just because we cannot tell."""
    asyncio.run(peripheral.build())
    peripheral._server.app = None
    asyncio.run(peripheral.notify(b"\x01", uuid=NUS_RX, label="test"))

    assert peripheral.log.tx[-1].delivered is None


# ---------------------------------------------------------------------------
# Advertised name
# ---------------------------------------------------------------------------


def _profile_named(match_name, local_name=None, device_name="Device"):
    return Profile(
        slug="p",
        name=device_name,
        match=MatchSpec(name=match_name),
        advertising=AdvertisingSpec(local_name=local_name),
        services=[
            ServiceSpec(
                uuid="6e400001-b5a3-f393-e0a9-e50e24dcca9e",
                characteristics=[
                    CharacteristicSpec(uuid=NUS_RX, properties=["notify"])
                ],
            )
        ],
    )


def test_match_name_glob_never_becomes_the_advertised_name(console):
    """match.name is an fnmatch pattern for *finding* a device. Broadcasting
    it would put a literal "Mira-*" on the air.
    """
    profile = _profile_named("Mira-*", device_name="Mira Ultra4")
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    assert rogue.advertised_name == "Mira Ultra4"


def test_advertising_local_name_wins_over_the_device_name(console):
    profile = _profile_named("Mira-*", local_name="Mira-Analyzer", device_name="Mira Ultra4")
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    assert rogue.advertised_name == "Mira-Analyzer"


def test_a_name_with_no_usable_characters_is_refused(console):
    """bless builds its D-Bus object path by stripping the name to
    [A-Za-z0-9_]; a name that strips to nothing yields "/org/bluez//..." and
    an error that points nowhere near the profile.
    """
    from brat.core.peripheral import PeripheralError

    profile = _profile_named("*", device_name="***")
    with pytest.raises(PeripheralError, match="D-Bus object path"):
        RoguePeripheral(profile=profile, console=console, quiet=True)


def test_a_glob_looking_name_warns(console):
    profile = _profile_named("x", local_name="Mira-*", device_name="d")
    rogue = RoguePeripheral(profile=profile, console=console, quiet=True)
    assert any("looks like a glob" in w for w in rogue.warnings)


def test_adapter_is_passed_through_to_the_server(mira, console, monkeypatch):
    import brat.core.peripheral as mod

    monkeypatch.setattr(
        mod,
        "_require_bless",
        lambda: (FakeServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties),
    )
    rogue = RoguePeripheral(profile=mira, console=console, quiet=True, adapter="hci1")
    asyncio.run(rogue.build())
    assert rogue._server.adapter == "hci1"
