"""`brat posture` check-function unit tests.

Each check function takes a plain `PostureContext` and returns findings, so
these are testable without a live BLE connection - the same approach as
test_enumerate.py's `_add_findings` tests.
"""

from brat.commands.posture import (
    PostureContext,
    check_dfu,
    check_link,
    check_privacy,
    check_write_exposure,
)
from brat.core.ble import AddressType, GattResult, ScanResult

_DFU_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"  # Nordic Buttonless DFU


def _service(chars: list[dict]) -> dict:
    return {"uuid": "12345678-0000-0000-0000-000000000000", "characteristics": chars}


def _char(
    uuid: str,
    properties: list[str],
    read_result: str | None = None,
    value: str | None = None,
) -> dict:
    return {"uuid": uuid, "properties": properties, "read_result": read_result, "value": value}


# ---------------------------------------------------------------------------
# link.no-encryption / profile.encryption-expected consistency
# ---------------------------------------------------------------------------


def test_zero_length_successful_read_still_counts_as_unencrypted():
    """A read of zero bytes still proves the ATT operation ran unauthenticated.

    Regression: `link.no-encryption` used to also require a truthy `value`,
    so a device whose only readable characteristics return empty values
    produced no `link.no-encryption` finding while `profile.encryption-
    expected` (checking read_result alone) fired anyway - two findings
    disagreeing about the same underlying fact.
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service([_char("2a19", ["read"], read_result="success")]),
        ],
    )
    # value is deliberately absent/empty in the fixture - only read_result matters now.
    findings = check_link(ctx)
    checks = [f.check for f in findings]
    assert "link.no-encryption" in checks


def test_no_successful_reads_means_no_encryption_finding():
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service([_char("2a19", ["read"], read_result="authentication-required")]),
        ],
    )
    findings = check_link(ctx)
    checks = [f.check for f in findings]
    assert "link.no-encryption" not in checks


# ---------------------------------------------------------------------------
# check_dfu severity - contradicting evidence must downgrade the verdict
# ---------------------------------------------------------------------------


def test_dfu_writable_with_no_other_evidence_is_critical_inferred():
    """The ordinary case: nothing else observed, properties alone -> CRITICAL/INFERRED."""
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[_service([_char(_DFU_UUID, ["write", "indicate"])])],
    )
    findings = check_dfu(ctx)
    hit = next(f for f in findings if f.check == "gatt.dfu-exposed")
    assert hit.severity.name == "CRITICAL"
    assert hit.confidence.value == "inferred"


def test_dfu_writable_with_contradicting_evidence_is_downgraded_to_high():
    """Regression: a device that enforces auth elsewhere must not read identically
    to a device confirmed to accept the DFU write - both used to be CRITICAL.
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service(
                [
                    _char(_DFU_UUID, ["write", "indicate"]),
                    # Another characteristic on this device DID demand auth -
                    # direct evidence the device enforces security somewhere.
                    _char("2a25", ["read"], read_result="authentication-required"),
                ]
            )
        ],
    )
    findings = check_dfu(ctx)
    hit = next(f for f in findings if f.check == "gatt.dfu-exposed")
    assert hit.severity.name == "HIGH"
    assert hit.confidence.value == "inferred"
    assert hit.evidence["other_characteristics_enforced_auth"] is True


def test_dfu_write_actually_confirmed_is_critical_confirmed_regardless():
    """If the write WAS probed and succeeded, that overrides everything - it is
    no longer an inference at all, confirmed or contradicting evidence aside.
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service(
                [
                    _char(_DFU_UUID, ["write", "indicate"]),
                    _char("2a25", ["read"], read_result="authentication-required"),
                ]
            )
        ],
        write_probes={_DFU_UUID: GattResult.SUCCESS.value},
    )
    findings = check_dfu(ctx)
    hit = next(f for f in findings if f.check == "gatt.dfu-exposed")
    assert hit.severity.name == "CRITICAL"
    assert hit.confidence.value == "confirmed"
    assert hit.evidence["write_confirmed"] is True


# ---------------------------------------------------------------------------
# check_privacy - identity characteristic evidence rendering
# ---------------------------------------------------------------------------


def test_binary_system_id_is_rendered_as_hex_not_mangled_utf8():
    """2a23 (System ID) is 8 raw binary bytes - decoding as UTF-8 with
    errors='replace' produces unusable replacement-character mush. Hex is
    what makes it readable and round-trippable.
    """
    binary_value = bytes([0x01, 0x02, 0xFF, 0xFE, 0x00, 0x11, 0x22, 0x33]).hex()
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[_service([_char("2a23", ["read"], read_result="success", value=binary_value)])],
    )
    findings = check_privacy(ctx)
    hit = next(f for f in findings if f.check == "privacy.identity-disclosure")
    entry = hit.evidence["identifiers"][0]
    assert entry["uuid"] == "00002a23-0000-1000-8000-00805f9b34fb" or "2a23" in entry["uuid"]
    assert entry["value"] == binary_value
    assert "�" not in entry["value"]  # no replacement characters


def test_serial_number_string_is_still_decoded_as_text():
    """2a25 (Serial Number String) is genuinely text per the GATT spec."""
    text_value = b"SN-00123456".hex()
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[_service([_char("2a25", ["read"], read_result="success", value=text_value)])],
    )
    findings = check_privacy(ctx)
    hit = next(f for f in findings if f.check == "privacy.identity-disclosure")
    entry = hit.evidence["identifiers"][0]
    assert entry["value"] == "SN-00123456"


def test_two_identity_characteristics_both_appear_in_evidence():
    """Regression: evidence used to be a dict keyed by uuid, so two entries
    sharing a uuid would silently collapse into one."""
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service(
                [
                    _char("2a23", ["read"], read_result="success", value="0102030405060708"),
                    _char("2a25", ["read"], read_result="success", value=b"ABC".hex()),
                ]
            )
        ],
    )
    findings = check_privacy(ctx)
    hit = next(f for f in findings if f.check == "privacy.identity-disclosure")
    assert len(hit.evidence["identifiers"]) == 2


# ---------------------------------------------------------------------------
# check_write_exposure - signed-write-only characteristics
# ---------------------------------------------------------------------------


def test_signed_write_only_characteristic_is_not_silently_invisible():
    """Regression: posture.py's _WRITE_PROPS used to omit
    authenticated-signed-writes entirely, so a characteristic whose only
    write-capable property was signed writes produced ZERO write findings -
    a silent gap, not a deliberate "not applicable".
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[_service([_char("abcd0001", ["authenticated-signed-writes"])])],
    )
    findings = check_write_exposure(ctx)
    checks = [f.check for f in findings]
    assert "gatt.signed-write-only" in checks


def test_signed_write_only_is_info_not_high_or_critical():
    """A signed write is authenticated via CSRK from bonding - it must not be
    bucketed into the "exposed to an unpaired peer" HIGH finding, which would
    overclaim severity for a channel an unbonded peer cannot actually use.
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[_service([_char("abcd0001", ["authenticated-signed-writes"])])],
    )
    findings = check_write_exposure(ctx)
    hit = next(f for f in findings if f.check == "gatt.signed-write-only")
    assert hit.severity.name == "INFO"
    # And it must not ALSO appear in the plain-write HIGH/CRITICAL buckets.
    assert "gatt.write-exposed" not in [f.check for f in findings]
    assert "gatt.write-unauthenticated" not in [f.check for f in findings]


def test_plain_write_alongside_signed_write_still_gets_the_high_finding():
    """A characteristic offering BOTH plain write and signed writes is still
    exposed via the plain write path and must still get the HIGH finding for
    that - the signed-write carve-out must not swallow real exposure.
    """
    ctx = PostureContext(
        address="AA:BB:CC:DD:EE:FF",
        connected_unpaired=True,
        services=[
            _service([_char("abcd0001", ["write", "authenticated-signed-writes"])])
        ],
    )
    findings = check_write_exposure(ctx)
    checks = [f.check for f in findings]
    assert "gatt.write-exposed" in checks


# ---------------------------------------------------------------------------
# check_privacy - address type UNKNOWN must not look like "checked and clean"
# ---------------------------------------------------------------------------


def test_unknown_address_type_gets_a_coverage_note_not_silence():
    """Regression: a device seen advertising but whose AddressType BlueZ
    couldn't report produced NO finding either way (not trackable, not
    flagged) - indistinguishable from "checked, and the address rotates".
    """
    scan_result = ScanResult(address="AA:BB:CC:DD:EE:FF", address_type=AddressType.UNKNOWN)
    ctx = PostureContext(address="AA:BB:CC:DD:EE:FF", scan_result=scan_result)

    check_privacy(ctx)  # populates ctx.skipped as a side effect
    assert any("could not be determined" in note for note in ctx.skipped)


def test_resolvable_private_address_gets_no_note_and_no_finding():
    """The ordinary, well-configured case must stay silent - no false alarm."""
    scan_result = ScanResult(
        address="AA:BB:CC:DD:EE:FF", address_type=AddressType.RESOLVABLE_PRIVATE
    )
    ctx = PostureContext(address="AA:BB:CC:DD:EE:FF", scan_result=scan_result)

    findings = check_privacy(ctx)
    assert not any("could not be determined" in note for note in ctx.skipped)
    assert "privacy.static-address" not in [f.check for f in findings]
