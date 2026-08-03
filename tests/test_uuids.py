

# ---------------------------------------------------------------------------
# Health *measurement characteristics*, not just their parent services.
#
# `posture` asks whether each characteristic is sensitive. Registering only the
# service UUIDs left glucose/heart-rate/BP readings classified as ordinary
# reads, ranked alongside Device Name - on precisely the device class this
# category exists to protect.
# ---------------------------------------------------------------------------


def test_health_measurement_characteristics_are_sensitive():
    from brat.core.uuids import risk_for

    for short in ("2a18", "2a1c", "2a35", "2a37", "2a5f", "2a9d"):
        uuid = f"0000{short}-0000-1000-8000-00805f9b34fb"
        entry = risk_for(uuid)
        assert entry is not None, f"{short} has no risk entry"
        assert entry.category == "sensitive-data", f"{short} miscategorised"


def test_measurement_characteristic_outranks_its_service():
    """The reading is worth more than the fact the device exists."""
    from brat.core.findings import Severity
    from brat.core.uuids import risk_for

    service = risk_for("00001808-0000-1000-8000-00805f9b34fb")   # Glucose
    char = risk_for("00002a18-0000-1000-8000-00805f9b34fb")      # Glucose Measurement

    assert service is not None and char is not None
    assert char.severity > service.severity
