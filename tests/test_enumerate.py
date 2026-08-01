"""`brat enum` finding generation.

`_add_findings` takes a plain GATT-tree dict, so it is testable without a live
BLE connection - the same reason `core/secrets.py` and `core/findings.py` are
unit tested directly rather than through a real device.
"""

from brat.commands.enumerate import _add_findings
from brat.core.report import Report


def _info(characteristics: list[dict]) -> dict:
    return {
        "services": [
            {
                "uuid": "12345678-0000-0000-0000-000000000000",
                "characteristics": characteristics,
            }
        ]
    }


def test_credential_shaped_value_is_flagged_critical():
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dGhpc2lzbm90YXJlYWxzaWc"
    ).encode("ascii")
    report = Report(command="enum")
    _add_findings(
        report,
        _info(
            [
                {
                    "uuid": "abcd0001-0000-0000-0000-000000000000",
                    "properties": ["read"],
                    "read_result": "success",
                    "value": fake_jwt.hex(),
                }
            ]
        ),
    )
    checks = [f.check for f in report.findings]
    assert "gatt.credential-in-value" in checks
    hit = next(f for f in report.findings if f.check == "gatt.credential-in-value")
    assert hit.severity.name == "CRITICAL"


def test_ordinary_value_is_not_flagged():
    report = Report(command="enum")
    _add_findings(
        report,
        _info(
            [
                {
                    "uuid": "abcd0002-0000-0000-0000-000000000000",
                    "properties": ["read"],
                    "read_result": "success",
                    "value": b"Example-Band".hex(),
                }
            ]
        ),
    )
    checks = [f.check for f in report.findings]
    assert "gatt.credential-in-value" not in checks
    assert "gatt.possible-credential-in-value" not in checks


def test_unread_value_is_not_scanned():
    """A characteristic that was never successfully read has nothing to scan."""
    report = Report(command="enum")
    _add_findings(
        report,
        _info(
            [
                {
                    "uuid": "abcd0003-0000-0000-0000-000000000000",
                    "properties": ["read"],
                    "read_result": "authentication-required",
                    "value": None,
                }
            ]
        ),
    )
    checks = [f.check for f in report.findings]
    assert "gatt.credential-in-value" not in checks
    assert "gatt.possible-credential-in-value" not in checks
