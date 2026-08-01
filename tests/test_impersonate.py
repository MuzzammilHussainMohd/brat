"""`brat impersonate` finding generation.

`_add_findings` only touches `.connected`, `.log.rx`, `.log.tx`, and
`.advertised_name`, so a small duck-typed stub exercises it without needing a
real bless-backed `RoguePeripheral` - same reasoning as the `FakeServer` stub
in test_peripheral.py.
"""

from dataclasses import dataclass, field

from brat.commands.impersonate import _add_findings
from brat.core.peripheral import LogEntry
from brat.core.report import Report


@dataclass
class _FakeLog:
    entries: list

    @property
    def rx(self):
        return [e for e in self.entries if e.direction == "rx"]

    @property
    def tx(self):
        return [e for e in self.entries if e.direction == "tx"]


@dataclass
class _FakePeripheral:
    connected: bool
    log: _FakeLog
    advertised_name: str = "Fake-Device"
    errors: list = field(default_factory=list)


@dataclass
class _FakeProfile:
    slug: str = "fake_device"
    protocol_config: dict | None = field(default_factory=lambda: {"name": "fake-protocol"})


def test_no_connection_produces_only_a_note():
    report = Report(command="impersonate")
    peripheral = _FakePeripheral(connected=False, log=_FakeLog([]))
    _add_findings(report, peripheral, _FakeProfile())
    assert len(report.findings) == 0
    assert any("No central connected" in n for n in report.notes)


def test_connected_but_no_writes_gets_medium_not_critical():
    """A central that only reads must not be reported as having 'sent data'."""
    report = Report(command="impersonate")
    log = _FakeLog([LogEntry("00:00:01", "tx", "uuid", b"\x01", origin="read-reply")])
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "peripheral.impersonation-connected-only" in checks
    assert "peripheral.impersonation-accepted" not in checks
    hit = next(f for f in report.findings if f.check == "peripheral.impersonation-connected-only")
    assert hit.severity.name == "MEDIUM"
    assert "sent nothing" in hit.title


def test_connected_with_writes_gets_critical():
    report = Report(command="impersonate")
    log = _FakeLog([LogEntry("00:00:01", "rx", "uuid", b"\x01\x02")])
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "peripheral.impersonation-accepted" in checks
    hit = next(f for f in report.findings if f.check == "peripheral.impersonation-accepted")
    assert hit.severity.name == "CRITICAL"
    assert "and sent data" in hit.title


def test_read_reply_does_not_count_as_protocol_response():
    """A plain GATT read reply must not inflate the attacker-response finding."""
    report = Report(command="impersonate")
    log = _FakeLog(
        [
            LogEntry("00:00:01", "rx", "uuid", b"\x01\x02"),
            LogEntry("00:00:02", "tx", "uuid", b"\x03\x04", origin="read-reply"),
        ]
    )
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "protocol.attacker-responses-accepted" not in checks


def test_protocol_response_does_count():
    report = Report(command="impersonate")
    log = _FakeLog(
        [
            LogEntry("00:00:01", "rx", "uuid", b"\x01\x02"),
            LogEntry("00:00:02", "tx", "uuid", b"\x03\x04", origin="protocol-response"),
        ]
    )
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "protocol.attacker-responses-accepted" in checks


def test_frame_ok_gates_the_protocol_command_finding():
    """A frame that failed to decode/checksum must not count as a sent command."""
    report = Report(command="impersonate")
    log = _FakeLog(
        [
            LogEntry("00:00:01", "rx", "uuid", b"\x01\x02", decoded="(protocol error: x)", frame_ok=False),
        ]
    )
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "protocol.no-peripheral-authentication" not in checks


def test_frame_ok_true_produces_the_protocol_command_finding():
    report = Report(command="impersonate")
    log = _FakeLog(
        [
            LogEntry("00:00:01", "rx", "uuid", b"\x01\x02", decoded="CMD=0xA3", frame_ok=True),
        ]
    )
    peripheral = _FakePeripheral(connected=True, log=log)
    _add_findings(report, peripheral, _FakeProfile())

    checks = [f.check for f in report.findings]
    assert "protocol.no-peripheral-authentication" in checks
