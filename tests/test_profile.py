"""Profile loading, validation, matching, and round-tripping.

Includes a test that every profile shipped in the repo actually loads and
validates - a broken shipped profile is the fastest way to lose a user.
"""

from pathlib import Path

import pytest
import yaml

from brat.core.profile import (
    MatchSpec,
    Profile,
    ProfileError,
    available_profiles,
    load_profile,
)

REPO_PROFILES = Path(__file__).resolve().parent.parent / "brat" / "profiles"

MINIMAL = {
    "brat_profile_version": 1,
    "device": {"slug": "test_dev", "name": "Test Device"},
    "match": {"name": "Test-*", "service_uuids": ["180f"]},
    "advertising": {"local_name": "Test-Device"},
    "gatt": {
        "services": [
            {
                "uuid": "180f",
                "name": "Battery",
                "characteristics": [
                    {
                        "uuid": "2a19",
                        "name": "Battery Level",
                        "properties": ["read", "notify"],
                        "value": "58",
                    }
                ],
            }
        ]
    },
}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_from_dict_normalizes_uuids():
    profile = Profile.from_dict(MINIMAL)
    assert profile.slug == "test_dev"
    assert profile.services[0].uuid == "0000180f-0000-1000-8000-00805f9b34fb"
    assert profile.services[0].characteristics[0].uuid == (
        "00002a19-0000-1000-8000-00805f9b34fb"
    )
    assert profile.match.service_uuids == ["0000180f-0000-1000-8000-00805f9b34fb"]


def test_characteristic_property_helpers():
    char = Profile.from_dict(MINIMAL).services[0].characteristics[0]
    assert char.readable
    assert char.subscribable
    assert not char.writable
    assert char.value_bytes == b"\x58"


def test_slug_is_required():
    with pytest.raises(ProfileError, match="device.slug"):
        Profile.from_dict({"device": {"name": "no slug"}})


def test_future_version_rejected():
    with pytest.raises(ProfileError, match="newer than this BRAT"):
        Profile.from_dict({**MINIMAL, "brat_profile_version": 99})


def test_missing_file_gives_clear_error(tmp_path):
    with pytest.raises(ProfileError, match="not found"):
        Profile.load(tmp_path / "nope.yaml")


def test_invalid_yaml_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("device: {slug: x\n  broken")
    with pytest.raises(ProfileError, match="invalid YAML"):
        Profile.load(bad)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_save_load_roundtrip(tmp_path):
    original = Profile.from_dict(MINIMAL)
    path = original.save(tmp_path / "test_dev.yaml", header="# generated\n")

    assert path.read_text().startswith("# generated\n")

    reloaded = Profile.load(path)
    assert reloaded.slug == original.slug
    assert reloaded.to_dict() == original.to_dict()


def test_saved_profile_is_plain_yaml(tmp_path):
    path = Profile.from_dict(MINIMAL).save(tmp_path / "p.yaml")
    data = yaml.safe_load(path.read_text())
    assert data["device"]["slug"] == "test_dev"
    assert data["brat_profile_version"] == 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_valid_profile_has_no_problems():
    assert Profile.from_dict(MINIMAL).validate() == []


def test_empty_profile_reports_problems():
    problems = Profile.from_dict({"device": {"slug": "empty"}}).validate()
    assert any("no GATT services" in p for p in problems)
    assert any("match block is empty" in p for p in problems)


def test_duplicate_characteristic_detected():
    spec = {
        **MINIMAL,
        "gatt": {
            "services": [
                {
                    "uuid": "180f",
                    "characteristics": [
                        {"uuid": "2a19", "properties": ["read"]},
                        {"uuid": "2a19", "properties": ["read"]},
                    ],
                }
            ]
        },
    }
    assert any("duplicate" in p for p in Profile.from_dict(spec).validate())


def test_broken_protocol_block_surfaces_in_validation():
    spec = {**MINIMAL, "protocol": {"name": "broken"}}
    problems = Profile.from_dict(spec).validate()
    assert any("frame.fields is required" in p for p in problems)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def test_service_uuid_outweighs_name():
    """A vendor service-UUID hit must score above a name-only hit - names are
    spoofable. Uses a vendor 128-bit UUID, not a SIG base one (e.g. Battery) -
    a SIG UUID is common across huge numbers of unrelated devices and is
    deliberately weighted lower; see test_sig_uuid_scores_lower_than_vendor_uuid.
    """
    by_name = MatchSpec(name="Widget-*")
    by_uuid = MatchSpec(service_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"])

    name_score = by_name.score("Widget-1", "AA:BB:CC:DD:EE:FF", [])
    uuid_score = by_uuid.score(
        "Widget-1", "AA:BB:CC:DD:EE:FF", ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]
    )
    assert uuid_score > name_score > 0


def test_sig_uuid_scores_lower_than_vendor_uuid():
    """Regression: a SIG base UUID (Battery, Device Information, ...) used to
    score identically to a vendor 128-bit UUID. Two profiles that differ only
    in common SIG services then tied on any device advertising those services -
    exactly the situation of two units of the same product family (a patched
    vs. an unpatched device, say) cloned as separate profiles.
    """
    sig_only = MatchSpec(service_uuids=["180f"])  # Battery
    vendor_only = MatchSpec(service_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"])

    sig_score = sig_only.score(None, None, ["180f"])
    vendor_score = vendor_only.score(
        None, None, ["6e400001-b5a3-f393-e0a9-e50e24dcca9e"]
    )
    assert vendor_score > sig_score > 0


def test_all_declared_criteria_must_match():
    spec = MatchSpec(name="Widget-*", service_uuids=["180f"])
    assert spec.score("Widget-1", "AA:BB:CC:DD:EE:FF", ["180f"]) > 0
    # Right name, wrong service.
    assert spec.score("Widget-1", "AA:BB:CC:DD:EE:FF", ["180d"]) == 0
    # Right service, wrong name.
    assert spec.score("Other", "AA:BB:CC:DD:EE:FF", ["180f"]) == 0


def test_glob_and_regex_matching():
    assert MatchSpec(name="Mira-*").score("Mira-Analyzer", None, []) > 0
    assert MatchSpec(name="Mira-*").score("Nira-Analyzer", None, []) == 0
    assert MatchSpec(name_regex=r"^Mira").score("Mira-Analyzer", None, []) > 0


def test_address_match_is_case_insensitive():
    spec = MatchSpec(address="aa:bb:cc:dd:ee:ff")
    assert spec.score(None, "AA:BB:CC:DD:EE:FF", []) > 0
    assert spec.score(None, "11:22:33:44:55:66", []) == 0


def test_empty_match_never_matches():
    assert MatchSpec().is_empty
    assert MatchSpec().score("anything", "AA:BB:CC:DD:EE:FF", ["180f"]) == 0


# ---------------------------------------------------------------------------
# Shipped profiles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", sorted(REPO_PROFILES.glob("*.yaml")), ids=lambda p: p.stem
)
def test_shipped_profile_loads_and_validates(path):
    profile = Profile.load(path)
    assert profile.validate() == []


def test_shipped_profiles_are_discoverable(monkeypatch, tmp_path):
    """Shipped profiles must be found from any directory, not just the repo.

    They live inside the package, so an installed wheel resolves them too.
    """
    monkeypatch.chdir(tmp_path)
    found = {p.stem for p in available_profiles()}
    assert "example_nus_device" in found
    assert "example_wearable" in found


def test_profile_resolves_by_slug(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    profile = load_profile("example_nus_device")
    assert profile.slug == "example_nus_device"
    assert profile.protocol is not None


def test_example_profile_contains_no_captured_identifiers():
    """The shipped profile must stay free of real session data."""
    text = (REPO_PROFILES / "example_nus_device.yaml").read_text()
    # Account identifiers observed in research captures were 6-digit numeric
    # strings followed by "--". Nothing of that shape may appear here.
    import re

    assert not re.search(r"\d{6}--", text)
    assert "658409" not in text
    assert "659318" not in text
