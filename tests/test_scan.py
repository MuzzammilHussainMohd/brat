"""`brat scan` profile fingerprinting - tie-breaking.

`fingerprint`/`fingerprint_all` take a plain ScanResult and a list of Profile
objects, so they're testable without a live BLE connection.
"""

from brat.commands.scan import fingerprint, fingerprint_all
from brat.core.ble import ScanResult
from brat.core.profile import MatchSpec, Profile


def _profile(slug: str, service_uuids: list[str]) -> Profile:
    return Profile(slug=slug, name=slug, match=MatchSpec(service_uuids=service_uuids))


def test_single_match_is_returned():
    profiles = [_profile("only_one", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"])]
    result = ScanResult(
        address="AA:BB:CC:DD:EE:FF",
        service_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
    )
    match = fingerprint(result, profiles)
    assert match is not None
    assert match[0].slug == "only_one"


def test_tied_top_scores_refuse_to_auto_pick():
    """Regression: two profiles scoring identically used to be resolved by
    whichever happened to sort first in `load_all_profiles()` - directory
    glob order, not anything meaningful about the device. This is exactly
    the shape of two units of the same product family (e.g. a patched and an
    unpatched device) cloned as separate profiles advertising the same
    vendor service.
    """
    profiles = [
        _profile("device_variant_a", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]),
        _profile("device_variant_b", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]),
    ]
    result = ScanResult(
        address="AA:BB:CC:DD:EE:FF",
        service_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
    )
    assert fingerprint(result, profiles) is None


def test_fingerprint_all_still_reports_every_tied_candidate():
    """The caller needs to see and report the tie, not have it hidden."""
    profiles = [
        _profile("device_variant_a", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]),
        _profile("device_variant_b", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]),
    ]
    result = ScanResult(
        address="AA:BB:CC:DD:EE:FF",
        service_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
    )
    ranked = fingerprint_all(result, profiles)
    assert len(ranked) == 2
    assert ranked[0][1] == ranked[1][1]
    assert {p.slug for p, _s in ranked} == {"device_variant_a", "device_variant_b"}


def test_clear_winner_is_not_affected_by_a_lower_scoring_tie():
    """A tie for SECOND place must not block the clear first-place winner."""
    profiles = [
        _profile(
            "clear_winner",
            ["6e400001-b5a3-f393-e0a9-e50e24dcca9e", "6e400002-b5a3-f393-e0a9-e50e24dcca9e"],
        ),
        _profile("tied_second_a", ["180f"]),
        _profile("tied_second_b", ["180a"]),
    ]
    result = ScanResult(
        address="AA:BB:CC:DD:EE:FF",
        service_uuids=[
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
            "6e400002-b5a3-f393-e0a9-e50e24dcca9e",
            "180f",
            "180a",
        ],
    )
    match = fingerprint(result, profiles)
    assert match is not None
    assert match[0].slug == "clear_winner"
