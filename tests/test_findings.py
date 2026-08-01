"""Findings model, report envelope, and UUID knowledge base."""

import json

import pytest

from brat.core.ble import AddressType, GattResult, classify_address, classify_error
from brat.core.findings import Confidence, Finding, FindingSet, Severity
from brat.core.report import Report, render_json
from brat.core.uuids import describe, label, normalize, risk_for, short_form


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.HIGH >= Severity.HIGH


def test_severity_parse():
    assert Severity.parse("critical") is Severity.CRITICAL
    assert Severity.parse("  HIGH ") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("catastrophic")


# ---------------------------------------------------------------------------
# FindingSet
# ---------------------------------------------------------------------------


def _finding(check, severity):
    return Finding(check=check, title=check, severity=severity)


def test_sorted_puts_worst_first():
    fs = FindingSet(
        [
            _finding("a", Severity.LOW),
            _finding("b", Severity.CRITICAL),
            _finding("c", Severity.MEDIUM),
        ]
    )
    assert [f.check for f in fs.sorted()] == ["b", "c", "a"]


def test_sort_is_stable_within_severity():
    fs = FindingSet([_finding(name, Severity.HIGH) for name in "xyz"])
    assert [f.check for f in fs.sorted()] == ["x", "y", "z"]


def test_counts_and_worst():
    fs = FindingSet([_finding("a", Severity.HIGH), _finding("b", Severity.INFO)])
    assert fs.counts()["HIGH"] == 1
    assert fs.counts()["CRITICAL"] == 0
    assert fs.worst is Severity.HIGH
    assert FindingSet().worst is None


def test_exit_code_threshold():
    fs = FindingSet([_finding("a", Severity.MEDIUM)])
    assert fs.exit_code(Severity.HIGH) == 0
    assert fs.exit_code(Severity.MEDIUM) == 1
    assert FindingSet().exit_code(Severity.INFO) == 0


def test_finding_serializes_enums_as_strings():
    d = _finding("x", Severity.CRITICAL).to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["confidence"] == "confirmed"
    assert json.dumps(d)


def test_confidence_defaults_to_confirmed():
    assert _finding("x", Severity.LOW).confidence is Confidence.CONFIRMED


def test_raw_bytes_in_evidence_are_normalized_to_hex():
    """Regression: to_dict() is documented as canonical - text is a view over
    it - so raw bytes in evidence must render the same fact both ways, not a
    Python repr string via json.dump's default=str fallback.
    """
    f = Finding(
        check="x", title="x", severity=Severity.HIGH,
        evidence={"value": b"\xaa\xbb\xcc"},
    )
    d = f.to_dict()
    assert d["evidence"]["value"] == "aabbcc"
    assert json.dumps(d)  # must not need default=str to succeed


def test_bytes_nested_in_list_and_dict_evidence_are_normalized():
    f = Finding(
        check="x", title="x", severity=Severity.HIGH,
        evidence={
            "matches": [{"uuid": "abcd", "raw": b"\x01\x02"}],
            "nested": {"deep": b"\xff"},
        },
    )
    d = f.to_dict()
    assert d["evidence"]["matches"][0]["raw"] == "0102"
    assert d["evidence"]["nested"]["deep"] == "ff"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_dict_is_json_serializable():
    report = Report(command="posture", target="AA:BB:CC:DD:EE:FF")
    report.findings.add(_finding("link.no-encryption", Severity.HIGH))
    report.note("write probing was skipped")

    doc = report.to_dict()
    assert doc["tool"] == "brat"
    assert doc["command"] == "posture"
    assert doc["summary"]["worst"] == "HIGH"
    assert doc["summary"]["by_severity"]["HIGH"] == 1
    assert doc["notes"] == ["write probing was skipped"]
    assert json.loads(json.dumps(doc, default=str))


def test_render_json_writes_valid_document(capsys):
    report = Report(command="scan")
    report.findings.add(_finding("privacy.static-address", Severity.LOW))
    render_json(report)
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["findings"][0]["check"] == "privacy.static-address"


# ---------------------------------------------------------------------------
# UUIDs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "given,expected",
    [
        ("180f", "0000180f-0000-1000-8000-00805f9b34fb"),
        ("0x180F", "0000180f-0000-1000-8000-00805f9b34fb"),
        ("0000180F-0000-1000-8000-00805F9B34FB", "0000180f-0000-1000-8000-00805f9b34fb"),
        ("6E400001-B5A3-F393-E0A9-E50E24DCCA9E", "6e400001-b5a3-f393-e0a9-e50e24dcca9e"),
    ],
)
def test_normalize(given, expected):
    assert normalize(given) == expected


def test_short_form_only_for_sig_uuids():
    assert short_form("180f") == "180f"
    assert short_form("6e400001-b5a3-f393-e0a9-e50e24dcca9e") is None


def test_describe_known_uuids():
    assert describe("180f", "service") == "Battery"
    assert describe("2a19", "characteristic") == "Battery Level"
    assert describe("2902", "descriptor") == "Client Characteristic Configuration"
    assert describe("6e400001-b5a3-f393-e0a9-e50e24dcca9e") == "Nordic UART Service (NUS)"


def test_label_falls_back_to_uuid():
    assert label("180f", "service") == "Battery"
    assert label("abcd") == "0xABCD"


def test_dfu_characteristics_are_high_risk():
    risk = risk_for("8ec90003-f315-4f60-9fb8-838830daea50")
    assert risk is not None
    assert risk.category == "firmware-update"
    assert risk.severity >= Severity.HIGH


def test_legacy_dfu_is_critical():
    """Legacy DFU has no signature enforcement, unlike Secure DFU."""
    risk = risk_for("00001530-1212-efde-1523-785feabcd123")
    assert risk.severity is Severity.CRITICAL


def test_nus_flagged_as_proprietary_protocol():
    assert risk_for("6e400001-b5a3-f393-e0a9-e50e24dcca9e").category == "proprietary-protocol"


def test_health_services_flagged_sensitive():
    for uuid in ("1808", "180d", "181f", "1822"):
        assert risk_for(uuid).category == "sensitive-data"


def test_unknown_uuid_has_no_risk():
    assert risk_for("12345678-0000-0000-0000-000000000000") is None


# ---------------------------------------------------------------------------
# BLE helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Insufficient Authentication", GattResult.AUTHENTICATION_REQUIRED),
        ("insufficient encryption", GattResult.ENCRYPTION_REQUIRED),
        ("Not authorized", GattResult.AUTHORIZATION_REQUIRED),
        ("Read not permitted", GattResult.NOT_PERMITTED),
        ("Request not supported", GattResult.NOT_SUPPORTED),
        ("Device disconnected", GattResult.DISCONNECTED),
        ("something else entirely", GattResult.UNKNOWN_ERROR),
    ],
)
def test_classify_error(message, expected):
    assert classify_error(Exception(message))[0] is expected


def test_att_error_code_is_recognised():
    assert classify_error(Exception("ATT error: 0x05"))[0] is (
        GattResult.AUTHENTICATION_REQUIRED
    )


def test_security_refusal_excludes_plain_not_permitted():
    """A non-readable characteristic proves nothing about authentication."""
    assert GattResult.AUTHENTICATION_REQUIRED.is_security_refusal
    assert GattResult.ENCRYPTION_REQUIRED.is_security_refusal
    assert not GattResult.NOT_PERMITTED.is_security_refusal
    assert not GattResult.SUCCESS.is_security_refusal


@pytest.mark.parametrize(
    "address,dbus_type,expected",
    [
        ("D4:8A:39:11:22:33", "public", AddressType.PUBLIC),
        ("D4:8A:39:11:22:33", "random", AddressType.RANDOM_STATIC),
        ("55:59:7D:04:AD:D1", "random", AddressType.RESOLVABLE_PRIVATE),
        ("15:59:7D:04:AD:D1", "random", AddressType.NON_RESOLVABLE_PRIVATE),
        ("D4:8A:39:11:22:33", None, AddressType.UNKNOWN),
    ],
)
def test_classify_address(address, dbus_type, expected):
    assert classify_address(address, dbus_type) is expected


def test_only_stable_addresses_are_trackable():
    assert AddressType.PUBLIC.is_trackable
    assert AddressType.RANDOM_STATIC.is_trackable
    assert not AddressType.RESOLVABLE_PRIVATE.is_trackable
    assert not AddressType.NON_RESOLVABLE_PRIVATE.is_trackable
