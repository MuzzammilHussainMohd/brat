"""The peripheral engine against the *real* bless server.

The rest of the peripheral suite substitutes a fake BlessServer, so nothing
bless actually does is exercised. Three consequences shipped green because of
that: `extended-properties` crashed registration, `--adapter` was never
covered, and the advertisement monkeypatch - the fix for bless only ever
advertising its first registered service - had literally never executed in a
test, because the fake server has no `app` attribute and the patch returns
early when it is missing.

Here bless runs unmodified and only D-Bus underneath it is faked, so these
tests fail if bless changes shape. No Bluetooth hardware required.
"""

import asyncio

import pytest

from brat.core.console import Console
from brat.core.peripheral import RoguePeripheral
from brat.core.profile import (
    AdvertisingSpec,
    CharacteristicSpec,
    Profile,
    ServiceSpec,
    load_profile,
)

pytest.importorskip("bless", reason="peripheral mode requires bless")

from fakes.dbus import FakeAdapter, install  # noqa: E402

NUS = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
FE59 = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CHAR = "8ec90003-f315-4f60-9fb8-838830daea50"


@pytest.fixture
def console():
    return Console(force_color=False)


def run(peripheral, *, stop=True):
    """Drive build() + start() inside one loop.

    BlessServerBlueZDBus.__init__ does loop.create_task(self.setup()), so the
    server cannot outlive the loop it was constructed in - everything has to
    happen in a single asyncio.run.
    """

    async def scenario():
        await peripheral.build()
        await peripheral.start()
        if stop:
            await peripheral.stop()

    asyncio.run(scenario())


@pytest.fixture
def mira(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    return load_profile("mira_ultra4")


# ---------------------------------------------------------------------------
# The advertisement
# ---------------------------------------------------------------------------


def test_the_profiles_uuid_goes_on_the_air_not_the_first_registered_service(
    mira, console, monkeypatch
):
    """bless hardcodes `advertisement._service_uuids.append(services[0].UUID)`.

    BRAT skips GAP and GATT, so the Mira profile's first *registered* service
    is Nordic DFU - which is what stock bless would advertise, and why a
    client filtering on the UART service saw nothing. This is the test that
    the monkeypatch fixing it has never had.
    """
    bus, adapter = install(monkeypatch)
    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)
    run(peripheral, stop=False)

    advertisement = peripheral._server.app.advertisements[-1]
    assert advertisement._service_uuids == [NUS]
    assert FE59 not in advertisement._service_uuids, "the DFU service must not be advertised"
    assert advertisement._local_name == "Mira-Analyzer"

    # And it really was handed to BlueZ.
    registered = adapter.called("call_register_advertisement")
    assert registered and registered[0][0] == advertisement.path


def test_the_advertisement_is_exported_on_the_bus(mira, console, monkeypatch):
    bus, _ = install(monkeypatch)
    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)
    run(peripheral, stop=False)

    assert bus.exported_paths(contains="advertisement")


def test_manufacturer_data_reaches_the_advertisement(console, monkeypatch):
    from dbus_next.signature import Variant

    install(monkeypatch)
    profile = Profile(
        slug="mfg",
        name="Mfg-Device",
        advertising=AdvertisingSpec(
            local_name="Mfg-Device",
            service_uuids=[NUS],
            manufacturer_data={"0x004c": "0215aabb"},
        ),
        services=[
            ServiceSpec(
                uuid=NUS,
                characteristics=[CharacteristicSpec(uuid=NUS_RX, properties=["notify"])],
            )
        ],
    )
    peripheral = RoguePeripheral(profile=profile, console=console, quiet=True)
    run(peripheral, stop=False)

    mfg = peripheral._server.app.advertisements[-1]._manufacturer_data
    assert isinstance(mfg[0x4C], Variant)
    assert mfg[0x4C].value == bytes.fromhex("0215aabb")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_the_whole_profile_tree_registers_through_real_bless(mira, console, monkeypatch):
    """Property flags, permissions and descriptors all survive bless's own
    conversion - which the fake server never performs.
    """
    install(monkeypatch)
    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)
    run(peripheral, stop=False)

    served = peripheral._server.app.services
    uuids = {s.UUID for s in served}
    assert NUS in uuids and FE59 in uuids
    assert "00001800-0000-1000-8000-00805f9b34fb" not in uuids, "BlueZ owns GAP"

    nus = peripheral._server.get_service(NUS)
    assert nus.get_characteristic(NUS_TX) is not None
    assert nus.get_characteristic(NUS_RX) is not None


def test_extended_properties_does_not_crash_real_registration(console, monkeypatch):
    """The exact crash: bless defines the flag but its D-Bus Flags enum has no
    matching member, so conversion raises StopIteration inside a coroutine and
    surfaces as "RuntimeError: coroutine raised StopIteration".
    """
    install(monkeypatch)
    profile = Profile(
        slug="ext",
        name="Ext-Device",
        advertising=AdvertisingSpec(local_name="Ext-Device", service_uuids=[NUS]),
        services=[
            ServiceSpec(
                uuid=NUS,
                characteristics=[
                    CharacteristicSpec(
                        uuid=NUS_RX,
                        properties=["read", "notify", "extended-properties"],
                    )
                ],
            )
        ],
    )
    peripheral = RoguePeripheral(profile=profile, console=console, quiet=True)
    run(peripheral, stop=False)  # must not raise

    assert peripheral._server.get_service(NUS).get_characteristic(NUS_RX) is not None
    assert any("extended-properties" in w for w in peripheral.warnings)


def test_the_adapter_argument_is_honoured(mira, console, monkeypatch):
    """Never covered before: the fake server's __init__ took no adapter kwarg,
    so every test went down the no-adapter path.
    """
    _, adapter = install(monkeypatch)
    peripheral = RoguePeripheral(
        profile=mira, console=console, quiet=True, adapter="hci1"
    )
    run(peripheral, stop=False)

    assert peripheral._server._adapter == "hci1"
    assert adapter.requested_name == "hci1"


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def test_notify_is_undelivered_until_a_central_subscribes(mira, console, monkeypatch):
    """Against real bless, whose update_value() returns True either way."""
    install(monkeypatch)
    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)

    async def scenario():
        await peripheral.build()
        await peripheral.start()

        await peripheral.notify(b"\x01\x02", uuid=NUS_RX, label="before")
        assert peripheral.log.tx[-1].delivered is False

        # What BlueZ does when the client writes the CCCD.
        peripheral._server.app.subscribed_characteristics.append(NUS_RX)

        await peripheral.notify(b"\x03\x04", uuid=NUS_RX, label="after")
        assert peripheral.log.tx[-1].delivered is True

        # The bytes really did reach the characteristic object bless serves.
        char = peripheral._server.get_service(NUS).get_characteristic(NUS_RX)
        assert bytes(char.value) == b"\x03\x04"
        await peripheral.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Failed registration and retry
# ---------------------------------------------------------------------------


def test_a_failed_advertisement_is_not_left_exported(mira, console, monkeypatch):
    """The patched start_advertising exports the advertisement before the
    registration that fails, so teardown has to undo both. Leaving it behind
    leaks the object and pushes the retry onto advertisement2, since bless
    derives the index from len(advertisements) + 1.
    """
    adapter = FakeAdapter()
    adapter.fail_once["call_register_advertisement"] = Exception(
        "org.bluez.Error.Failed: Failed to register advertisement"
    )
    bus, _ = install(monkeypatch, adapter)

    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)
    # Recovery is not available in a test environment, so start() will raise;
    # what matters is the state it leaves behind.
    monkeypatch.setattr(peripheral, "_recover_adapter", lambda: (True, "pretended"))

    async def scenario():
        await peripheral.build()
        await peripheral.start()

    asyncio.run(scenario())

    # The retry succeeded (only the first call was set to fail) and reused
    # advertisement1 rather than leaking the first and creating a second.
    paths = bus.exported_paths(contains="advertisement")
    assert len(paths) == 1, f"expected one advertisement on the bus, got {paths}"
    assert paths[0].endswith("advertisement1")


def test_a_failure_that_cannot_be_recovered_explains_itself(mira, console, monkeypatch):
    from brat.core.peripheral import PeripheralError

    adapter = FakeAdapter()
    adapter.fail_once["call_register_advertisement"] = Exception(
        "org.bluez.Error.Failed: Failed to register advertisement"
    )
    install(monkeypatch, adapter)

    peripheral = RoguePeripheral(profile=mira, console=console, quiet=True)
    monkeypatch.setattr(
        peripheral, "_recover_adapter", lambda: (False, "needs root")
    )

    async def scenario():
        await peripheral.build()
        with pytest.raises(PeripheralError) as exc:
            await peripheral.start()
        assert "did not run" in str(exc.value)
        assert "needs root" in str(exc.value)

    asyncio.run(scenario())
