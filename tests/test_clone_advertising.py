"""Which UUIDs a cloned profile is allowed to advertise.

The bug these pin came from trusting bleak's `service_uuids` as though it were
the advertisement's UUID list. It is not: BlueZ's `Device1.UUIDs` is a union of
what the device advertised and whatever BlueZ cached about it from earlier
connections. A real clone of a Nordic analyser came out advertising
8ec90001-f315-4f60-9fb8-838830daea50 - the Nordic DFU Control Point, which only
exists while the device is in bootloader mode. BlueZ had cached it from an
earlier session and reported it alongside the running device's real UUIDs, so
the clone advertised a service the profile's own GATT tree does not contain.
A client filtering its scan on the UART service never matched, which makes the
impersonated device look absent rather than wrong - a hard failure to attribute.
"""

from dataclasses import dataclass, field

from brat.commands.clone import _advertisable_uuids

NUS = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
FE59 = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CHAR = "8ec90003-f315-4f60-9fb8-838830daea50"
DFU_CTRL = "8ec90001-f315-4f60-9fb8-838830daea50"
GAP = "00001800-0000-1000-8000-00805f9b34fb"
GATT = "00001801-0000-1000-8000-00805f9b34fb"
BATTERY = "0000180f-0000-1000-8000-00805f9b34fb"


@dataclass
class FakeChar:
    uuid: str


@dataclass
class FakeService:
    uuid: str
    characteristics: list = field(default_factory=list)


@dataclass
class FakeScan:
    service_uuids: list


def example_tree():
    """The GATT tree of the real unit, as `brat clone` enumerated it."""
    return [
        FakeService(GATT),
        FakeService(FE59, [FakeChar(DFU_CHAR)]),
        FakeService(NUS, [FakeChar(NUS_RX)]),
        FakeService(GAP),
    ]


def test_the_real_clone_advertises_the_uart_service():
    """The exact failure, with the exact inputs.

    BlueZ reported only 8ec90001 - the DFU Control Point, which exists only
    while the device is in bootloader mode and so appears nowhere in the tree
    enumerated from the running application. It is therefore rejected as a
    stale cached UUID, and the fallback picks the vendor service the device
    really does serve.
    """
    kept, rejected = _advertisable_uuids(FakeScan([DFU_CTRL]), example_tree())

    assert kept == [NUS], "should fall back to the vendor service in the tree"
    assert [u for u, _ in rejected] == [DFU_CTRL]
    assert "not present in the device's GATT tree" in rejected[0][1]


def test_a_characteristic_uuid_is_never_advertised():
    """A UUID that is in the tree but as a characteristic cannot be
    advertised as a service, and saying so beats calling it stale.
    """
    kept, rejected = _advertisable_uuids(FakeScan([DFU_CHAR]), example_tree())

    assert kept == [NUS]
    assert [u for u, _ in rejected] == [DFU_CHAR]
    assert "characteristic" in rejected[0][1]


def test_a_served_service_is_kept():
    kept, rejected = _advertisable_uuids(FakeScan([NUS]), example_tree())
    assert kept == [NUS]
    assert rejected == []


def test_a_uuid_absent_from_the_tree_is_rejected_as_stale():
    stale = "0000abcd-0000-1000-8000-00805f9b34fb"
    kept, rejected = _advertisable_uuids(FakeScan([stale, NUS]), example_tree())

    assert kept == [NUS]
    assert rejected == [(stale, rejected[0][1])]
    assert "cached" in rejected[0][1]


def test_bluez_owned_services_are_never_advertised():
    """A profile cannot serve GAP or GATT, so it must not claim to advertise
    them - BlueZ registers those itself and rejects the attempt.
    """
    kept, rejected = _advertisable_uuids(FakeScan([GAP, GATT, NUS]), example_tree())

    assert kept == [NUS]
    assert {u for u, _ in rejected} == {GAP, GATT}
    assert all("BlueZ" in why for _, why in rejected)


def test_fallback_prefers_a_vendor_service_over_a_sig_one():
    """With nothing usable advertised, the vendor 128-bit service is what a
    client is plausibly filtering on; Battery identifies nothing.
    """
    tree = [FakeService(BATTERY), FakeService(NUS)]
    kept, _ = _advertisable_uuids(FakeScan([]), tree)
    assert kept == [NUS]


def test_fallback_uses_a_sig_service_when_that_is_all_there_is():
    kept, _ = _advertisable_uuids(FakeScan([]), [FakeService(BATTERY)])
    assert kept == [BATTERY]


def test_no_scan_result_still_yields_something_advertisable():
    kept, rejected = _advertisable_uuids(None, example_tree())
    assert kept == [NUS]
    assert rejected == []


def test_duplicates_are_collapsed():
    kept, _ = _advertisable_uuids(FakeScan([NUS, NUS.upper()]), example_tree())
    assert kept == [NUS]
