"""Adapter readiness checks.

The bug these pin: `doctor` decided an adapter had no address by reading
BlueZ's `Adapter1.Address`. But when a controller boots without an address -
which the nRF52840's Zephyr hci_usb firmware does - BlueZ *invents* a static
random one and reports that. So the check could never fire on the very dongle
it was written for, and `doctor` reported `impersonate` as ready on hardware
that had already logged "Failed to add advertisement: No Resources" twice.

The values below are the real ones read off that machine.
"""

import pytest

from brat.commands.doctor import _is_zephyr_hci, _peripheral_verdict

# As reported for the nRF52840 dongle running Zephyr hci_usb.
ZEPHYR = {
    "name": "hci0",
    "address": "F6:EC:34:1D:3C:F0",          # BlueZ invented this
    "controller_address": "00:00:00:00:00:00",  # what the chip actually has
    "address_type": "random",
    "manufacturer": 1521,                     # Zephyr Project
    "modalias": "",
    "powered": True,
    "can_advertise": True,
    "can_serve_gatt": True,
    "supported_features": [],
    "min_tx_power": 0,
    "max_tx_power": 0,
}

HEALTHY = {
    "name": "hci1",
    "address": "AA:BB:CC:DD:EE:FF",
    "controller_address": "AA:BB:CC:DD:EE:FF",
    "address_type": "public",
    "manufacturer": 2,
    "modalias": "usb:v8087p0026",
    "powered": True,
    "can_advertise": True,
    "can_serve_gatt": True,
    "supported_features": ["CanSetTxPower"],
    "min_tx_power": -34,
    "max_tx_power": 7,
}


def test_a_zephyr_dongle_is_recognised_by_its_manufacturer():
    assert _is_zephyr_hci(ZEPHYR) is True


def test_a_normal_adapter_is_not_flagged():
    assert _is_zephyr_hci(HEALTHY) is False


def test_a_nordic_dongle_is_recognised_by_its_usb_id():
    """Some kernels report no Manufacturer, but the modalias still gives it away."""
    adapter = dict(HEALTHY, manufacturer=None, modalias="usb:v2FE3p000B")
    assert _is_zephyr_hci(adapter) is True


def test_an_anonymous_controller_is_recognised_by_its_signature():
    """No identity at all, but no advertising features, no TX power range and
    no address of its own is the same hardware.
    """
    adapter = dict(ZEPHYR, manufacturer=None, modalias="")
    assert _is_zephyr_hci(adapter) is True


def test_a_healthy_adapter_missing_only_tx_power_is_not_flagged():
    """The signature needs all three symptoms; one is not enough, or every
    modest controller gets condemned.
    """
    adapter = dict(HEALTHY, min_tx_power=0, max_tx_power=0)
    assert _is_zephyr_hci(adapter) is False


@pytest.mark.parametrize(
    "adapter,expected",
    [
        (HEALTHY, "yes"),
        (ZEPHYR, "no (no addr)"),
        (dict(HEALTHY, powered=False), "no (off)"),
        (dict(HEALTHY, can_advertise=False), "no (no iface)"),
        (dict(HEALTHY, manufacturer=1521), "no (zephyr)"),
    ],
)
def test_the_peripheral_verdict_says_why_not(adapter, expected):
    """A rejection reason belongs in the adapters table, not only in the
    checks list - the table is where the operator looks first.
    """
    assert _peripheral_verdict(adapter) == expected


def test_a_synthesized_bluez_address_does_not_mask_a_zero_controller_address():
    """The whole bug in one assertion: BlueZ's address looks perfectly valid
    while the controller has none, so only the controller's own answer counts.
    """
    assert ZEPHYR["address"] != "00:00:00:00:00:00"
    assert ZEPHYR["controller_address"] == "00:00:00:00:00:00"
    assert _peripheral_verdict(ZEPHYR).startswith("no")
