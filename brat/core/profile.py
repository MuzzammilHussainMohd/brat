"""Device profiles.

A profile is the whole of what BRAT knows about one device: how to recognise
it, what its advertising looks like, its full GATT tree, what security posture
it ought to have, and optionally how its application-layer protocol is framed.

Profiles are data, never code. Every command in the toolkit is generic; the
profile is what points it at a specific device. `brat clone` writes these, so
in the normal workflow nobody hand-authors one.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .protocol import ProtocolEngine, ProtocolError, parse_hex
from .uuids import is_sig
from .uuids import normalize as norm_uuid

PROFILE_VERSION = 1


class ProfileError(ValueError):
    """Malformed or unloadable profile."""


# ---------------------------------------------------------------------------
# GATT tree
# ---------------------------------------------------------------------------


@dataclass
class DescriptorSpec:
    uuid: str
    name: str = ""
    value: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "DescriptorSpec":
        return cls(
            uuid=norm_uuid(d["uuid"]),
            name=str(d.get("name", "")),
            value=d.get("value"),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"uuid": self.uuid}
        if self.name:
            out["name"] = self.name
        if self.value is not None:
            out["value"] = self.value
        return out


@dataclass
class CharacteristicSpec:
    uuid: str
    name: str = ""
    properties: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    value: str | None = None          # hex; captured or served
    descriptors: list[DescriptorSpec] = field(default_factory=list)
    handle: int | None = None
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CharacteristicSpec":
        if "uuid" not in d:
            raise ProfileError(f"characteristic missing uuid: {d!r}")
        return cls(
            uuid=norm_uuid(d["uuid"]),
            name=str(d.get("name", "")),
            properties=[str(p).lower() for p in d.get("properties", [])],
            permissions=[str(p).lower() for p in d.get("permissions", [])],
            value=d.get("value"),
            descriptors=[DescriptorSpec.from_dict(x) for x in d.get("descriptors", [])],
            handle=d.get("handle"),
            notes=str(d.get("notes", "")),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"uuid": self.uuid}
        if self.name:
            out["name"] = self.name
        out["properties"] = self.properties
        if self.permissions:
            out["permissions"] = self.permissions
        if self.handle is not None:
            out["handle"] = self.handle
        if self.value is not None:
            out["value"] = self.value
        if self.descriptors:
            out["descriptors"] = [d.to_dict() for d in self.descriptors]
        if self.notes:
            out["notes"] = self.notes
        return out

    @property
    def value_bytes(self) -> bytes:
        return parse_hex(self.value) if self.value else b""

    def has(self, prop: str) -> bool:
        return prop.lower() in self.properties

    @property
    def writable(self) -> bool:
        return any(p in self.properties for p in ("write", "write-without-response"))

    @property
    def readable(self) -> bool:
        return "read" in self.properties

    @property
    def subscribable(self) -> bool:
        return any(p in self.properties for p in ("notify", "indicate"))


@dataclass
class ServiceSpec:
    uuid: str
    name: str = ""
    primary: bool = True
    characteristics: list[CharacteristicSpec] = field(default_factory=list)
    handle: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "ServiceSpec":
        if "uuid" not in d:
            raise ProfileError(f"service missing uuid: {d!r}")
        return cls(
            uuid=norm_uuid(d["uuid"]),
            name=str(d.get("name", "")),
            primary=bool(d.get("primary", True)),
            characteristics=[
                CharacteristicSpec.from_dict(c) for c in d.get("characteristics", [])
            ],
            handle=d.get("handle"),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"uuid": self.uuid}
        if self.name:
            out["name"] = self.name
        out["primary"] = self.primary
        if self.handle is not None:
            out["handle"] = self.handle
        out["characteristics"] = [c.to_dict() for c in self.characteristics]
        return out


# ---------------------------------------------------------------------------
# Matching and advertising
# ---------------------------------------------------------------------------


@dataclass
class MatchSpec:
    """How to recognise this device during a scan."""

    name: str | None = None            # glob, e.g. "Device-*"
    name_regex: str | None = None
    address: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_id: int | None = None

    def __post_init__(self) -> None:
        # Normalize here rather than only in from_dict, so a MatchSpec built in
        # code compares equal to one loaded from YAML. Without this, a spec
        # holding "180f" silently never matches an advertised full-form UUID.
        self.service_uuids = [norm_uuid(u) for u in self.service_uuids]

    @classmethod
    def from_dict(cls, d: dict) -> "MatchSpec":
        return cls(
            name=d.get("name"),
            name_regex=d.get("name_regex"),
            address=d.get("address"),
            service_uuids=[norm_uuid(u) for u in d.get("service_uuids", [])],
            manufacturer_id=d.get("manufacturer_id"),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        for key in ("name", "name_regex", "address", "manufacturer_id"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.service_uuids:
            out["service_uuids"] = self.service_uuids
        return out

    def score(
        self,
        name: str | None,
        address: str | None,
        service_uuids: list[str] | None,
        manufacturer_ids: list[int] | None = None,
    ) -> int:
        """How strongly this device matches. 0 = no match; higher is better.

        Weighted so a service-UUID hit outranks a name hit - names are trivially
        spoofed and frequently truncated in advertising packets.
        """
        points = 0
        advertised = {norm_uuid(u) for u in (service_uuids or [])}

        if self.address:
            if not address or address.lower() != self.address.lower():
                return 0
            points += 5

        if self.service_uuids:
            hits = advertised & set(self.service_uuids)
            if not hits:
                return 0
            # SIG base UUIDs (Battery, Device Information, Generic Access...)
            # are common across huge numbers of unrelated devices and carry
            # almost no power to tell one device apart from another - two
            # different products, or two units of the same product family
            # cloned as separate profiles, routinely share every one of
            # these. A vendor-specific 128-bit UUID (a custom service like
            # Nordic UART) is a much stronger identifying signal. Scoring
            # them the same made two profiles that differ only in their SIG
            # UUIDs tie on devices that are not actually the same thing.
            for uuid in hits:
                points += 1 if is_sig(uuid) else 4

        if self.name:
            if not name or not fnmatch.fnmatch(name, self.name):
                return 0
            points += 2

        if self.name_regex:
            if not name or not re.search(self.name_regex, name):
                return 0
            points += 2

        if self.manufacturer_id is not None:
            if not manufacturer_ids or self.manufacturer_id not in manufacturer_ids:
                return 0
            points += 3

        return points

    @property
    def is_empty(self) -> bool:
        return not any(
            [self.name, self.name_regex, self.address, self.service_uuids, self.manufacturer_id]
        )


@dataclass
class AdvertisingSpec:
    """What to broadcast when impersonating this device."""

    local_name: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, str] = field(default_factory=dict)
    appearance: int | None = None
    tx_power: int | None = None

    def __post_init__(self) -> None:
        self.service_uuids = [norm_uuid(u) for u in self.service_uuids]

    @classmethod
    def from_dict(cls, d: dict) -> "AdvertisingSpec":
        return cls(
            local_name=d.get("local_name"),
            service_uuids=[norm_uuid(u) for u in d.get("service_uuids", [])],
            manufacturer_data={
                int(k): str(v) for k, v in (d.get("manufacturer_data") or {}).items()
            },
            appearance=d.get("appearance"),
            tx_power=d.get("tx_power"),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        if self.local_name is not None:
            out["local_name"] = self.local_name
        if self.service_uuids:
            out["service_uuids"] = self.service_uuids
        if self.manufacturer_data:
            out["manufacturer_data"] = self.manufacturer_data
        if self.appearance is not None:
            out["appearance"] = self.appearance
        if self.tx_power is not None:
            out["tx_power"] = self.tx_power
        return out


@dataclass
class SecuritySpec:
    """Expected posture. Drives which posture findings apply to this device."""

    expect_encryption: bool = True
    expect_pairing: bool = True
    expect_bonding: bool = False
    sensitive_characteristics: list[str] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.sensitive_characteristics = [
            norm_uuid(u) for u in self.sensitive_characteristics
        ]

    @classmethod
    def from_dict(cls, d: dict) -> "SecuritySpec":
        return cls(
            expect_encryption=bool(d.get("expect_encryption", True)),
            expect_pairing=bool(d.get("expect_pairing", True)),
            expect_bonding=bool(d.get("expect_bonding", False)),
            sensitive_characteristics=[
                norm_uuid(u) for u in d.get("sensitive_characteristics", [])
            ],
            observed=d.get("observed") or {},
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "expect_encryption": self.expect_encryption,
            "expect_pairing": self.expect_pairing,
            "expect_bonding": self.expect_bonding,
        }
        if self.sensitive_characteristics:
            out["sensitive_characteristics"] = self.sensitive_characteristics
        if self.observed:
            out["observed"] = self.observed
        return out

    def is_sensitive(self, uuid: str) -> bool:
        return norm_uuid(uuid) in self.sensitive_characteristics


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


@dataclass
class Profile:
    slug: str
    name: str = ""
    vendor: str = ""
    model: str = ""
    notes: str = ""
    source: str = ""                   # how this profile was produced
    match: MatchSpec = field(default_factory=MatchSpec)
    advertising: AdvertisingSpec = field(default_factory=AdvertisingSpec)
    services: list[ServiceSpec] = field(default_factory=list)
    security: SecuritySpec = field(default_factory=SecuritySpec)
    protocol_config: dict | None = None
    path: Path | None = None

    # -- protocol -----------------------------------------------------------

    _engine: ProtocolEngine | None = field(default=None, repr=False, compare=False)

    @property
    def protocol(self) -> ProtocolEngine | None:
        """Lazily built protocol engine, or None if the profile defines none."""
        if self.protocol_config is None:
            return None
        if self._engine is None:
            try:
                self._engine = ProtocolEngine(self.protocol_config)
            except ProtocolError as exc:
                raise ProfileError(f"{self.slug}: invalid protocol block: {exc}") from None
        return self._engine

    # -- serialization ------------------------------------------------------

    @classmethod
    def from_dict(cls, d: dict, path: Path | None = None) -> "Profile":
        version = d.get("brat_profile_version", PROFILE_VERSION)
        if int(version) > PROFILE_VERSION:
            raise ProfileError(
                f"profile version {version} is newer than this BRAT understands "
                f"({PROFILE_VERSION}); upgrade brat"
            )

        device = d.get("device") or {}
        slug = device.get("slug") or (path.stem if path else None)
        if not slug:
            raise ProfileError("profile needs device.slug")

        return cls(
            slug=str(slug),
            name=str(device.get("name", slug)),
            vendor=str(device.get("vendor", "")),
            model=str(device.get("model", "")),
            notes=str(device.get("notes", "")),
            source=str(device.get("source", "")),
            match=MatchSpec.from_dict(d.get("match") or {}),
            advertising=AdvertisingSpec.from_dict(d.get("advertising") or {}),
            services=[ServiceSpec.from_dict(s) for s in (d.get("gatt") or {}).get("services", [])],
            security=SecuritySpec.from_dict(d.get("security") or {}),
            protocol_config=d.get("protocol"),
            path=path,
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"brat_profile_version": PROFILE_VERSION}
        device: dict[str, Any] = {"slug": self.slug, "name": self.name}
        for key in ("vendor", "model", "source", "notes"):
            value = getattr(self, key)
            if value:
                device[key] = value
        out["device"] = device

        match = self.match.to_dict()
        if match:
            out["match"] = match
        advertising = self.advertising.to_dict()
        if advertising:
            out["advertising"] = advertising
        out["security"] = self.security.to_dict()
        out["gatt"] = {"services": [s.to_dict() for s in self.services]}
        if self.protocol_config:
            out["protocol"] = self.protocol_config
        return out

    @classmethod
    def load(cls, path: str | Path) -> "Profile":
        p = Path(path)
        if not p.exists():
            raise ProfileError(f"profile not found: {p}")
        try:
            data = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ProfileError(f"{p}: invalid YAML: {exc}") from None
        if not isinstance(data, dict):
            raise ProfileError(f"{p}: profile must be a YAML mapping")
        return cls.from_dict(data, path=p)

    def save(self, path: str | Path, header: str | None = None) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        body = yaml.safe_dump(
            self.to_dict(), sort_keys=False, default_flow_style=False, width=100
        )
        p.write_text((header or "") + body)
        self.path = p
        return p

    # -- queries ------------------------------------------------------------

    def characteristic(self, uuid: str) -> CharacteristicSpec | None:
        target = norm_uuid(uuid)
        for service in self.services:
            for char in service.characteristics:
                if char.uuid == target:
                    return char
        return None

    def all_characteristics(self) -> list[tuple[ServiceSpec, CharacteristicSpec]]:
        return [(s, c) for s in self.services for c in s.characteristics]

    def validate(self) -> list[str]:
        """Return a list of problems. Empty list means the profile is usable."""
        problems: list[str] = []
        if not self.services:
            problems.append("no GATT services defined - impersonate will have nothing to serve")
        if self.match.is_empty:
            problems.append("match block is empty - `brat scan` cannot fingerprint this device")
        if not self.advertising.local_name and not self.advertising.service_uuids:
            problems.append("advertising block has neither local_name nor service_uuids")

        seen: set[str] = set()
        for service in self.services:
            for char in service.characteristics:
                if char.uuid in seen:
                    problems.append(f"duplicate characteristic uuid {char.uuid}")
                seen.add(char.uuid)
                if not char.properties:
                    problems.append(f"{char.uuid} has no properties")

        if self.protocol_config is not None:
            try:
                _ = self.protocol
            except ProfileError as exc:
                problems.append(str(exc))
        return problems


# ---------------------------------------------------------------------------
# Profile discovery
# ---------------------------------------------------------------------------


def profile_search_paths() -> list[Path]:
    """Where BRAT looks for profiles, in priority order."""
    paths: list[Path] = []

    env = os.environ.get("BRAT_PROFILE_PATH")
    if env:
        paths.extend(Path(p) for p in env.split(os.pathsep) if p)

    paths.append(Path.cwd() / "profiles")

    config_home = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    paths.append(Path(config_home) / "brat" / "profiles")

    # Profiles shipped inside the installed package. Lowest priority, so a
    # local copy of the same filename always wins.
    paths.append(Path(__file__).resolve().parent.parent / "profiles")

    seen: set[Path] = set()
    out: list[Path] = []
    for p in paths:
        rp = p.expanduser()
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out


def resolve_profile(reference: str) -> Path:
    """Resolve a profile given a path, a filename, or a bare slug."""
    direct = Path(reference).expanduser()
    if direct.exists():
        return direct

    candidates = [reference]
    if not reference.endswith((".yaml", ".yml")):
        candidates += [f"{reference}.yaml", f"{reference}.yml"]

    for directory in profile_search_paths():
        for candidate in candidates:
            found = directory / candidate
            if found.exists():
                return found

    searched = "\n  ".join(str(p) for p in profile_search_paths())
    raise ProfileError(f"profile {reference!r} not found. Searched:\n  {searched}")


def load_profile(reference: str) -> Profile:
    return Profile.load(resolve_profile(reference))


def available_profiles() -> list[Path]:
    """Every profile YAML BRAT can see, deduplicated by filename."""
    out: list[Path] = []
    seen: set[str] = set()
    for directory in profile_search_paths():
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            if path.name not in seen:
                seen.add(path.name)
                out.append(path)
    return out


def load_all_profiles() -> list[Profile]:
    """Load every discoverable profile, skipping ones that fail to parse."""
    profiles: list[Profile] = []
    for path in available_profiles():
        try:
            profiles.append(Profile.load(path))
        except ProfileError:
            continue
    return profiles
