"""`brat scan` - passive discovery with profile fingerprinting.

Advertising packets are broadcast in the clear by design, so listening to them
intercepts nothing private. What this adds over any other scanner is the
fingerprint step: every result is scored against every known profile, so the
output says "this is a Mira Ultra4, and there is a profile for it" rather than
leaving you to recognise a MAC.

It also classifies the address type, which is the cheapest privacy finding in
BLE and one almost no scanner surfaces.
"""

from __future__ import annotations

from ..core import ble
from ..core.console import Console
from ..core.findings import Confidence, Finding, Severity
from ..core.profile import Profile, load_all_profiles
from ..core.report import Report
from ..core.uuids import label as uuid_label
from ..core.uuids import risk_for


def fingerprint_all(
    result: ble.ScanResult, profiles: list[Profile]
) -> list[tuple[Profile, int]]:
    """Every profile that matches at all, sorted by score, best first."""
    scored = []
    for profile in profiles:
        score = profile.match.score(
            name=result.name,
            address=result.address,
            service_uuids=result.service_uuids,
            manufacturer_ids=list(result.manufacturer_data.keys()),
        )
        if score > 0:
            scored.append((profile, score))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored


def fingerprint(result: ble.ScanResult, profiles: list[Profile]) -> tuple[Profile, int] | None:
    """Best-scoring profile for this scan result, or None.

    Refuses to pick when the top two candidates tie - two profiles differing
    only in properties the score doesn't weigh (two cloned units of the same
    product family, say) would otherwise be resolved by directory glob order,
    silently applying whichever one happened to sort first. Use
    `fingerprint_all` when you want to see and report the tie instead of
    having it hidden.
    """
    ranked = fingerprint_all(result, profiles)
    if not ranked:
        return None
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return None
    return ranked[0]


async def execute(args, console: Console) -> Report:
    report = Report(command="scan")

    profiles = [] if args.no_profiles else load_all_profiles()

    if args.output == "text":
        console.info(
            f"Scanning for {args.timeout:g}s"
            + (f" on {args.adapter}" if args.adapter else "")
            + (f", matching {len(profiles)} profile(s)" if profiles else "")
            + " ..."
        )

    results = await ble.scan(timeout=args.timeout, adapter=args.adapter)

    if args.name:
        needle = args.name.lower()
        results = [r for r in results if r.name and needle in r.name.lower()]
    if args.address:
        wanted = args.address.lower()
        results = [r for r in results if r.address.lower() == wanted]
    if args.min_rssi is not None:
        results = [r for r in results if (r.rssi or -999) >= args.min_rssi]

    entries = []
    ambiguous_addresses = []
    for result in results:
        entry = result.to_dict()
        ranked = fingerprint_all(result, profiles)
        tied = len(ranked) > 1 and ranked[0][1] == ranked[1][1]

        if ranked and not tied:
            profile, score = ranked[0]
            entry["profile"] = {
                "slug": profile.slug,
                "name": profile.name,
                "score": score,
                "path": str(profile.path) if profile.path else None,
                "has_protocol": profile.protocol_config is not None,
            }
        elif tied:
            # Two (or more) profiles matched with the same score - showing
            # one of them as "the" match would be arbitrary (whichever
            # happened to load first) and wrong exactly when it matters most:
            # two units of the same product family cloned as separate
            # profiles. Report the ambiguity instead of picking silently.
            tied_scores = [ranked[0][1]]
            candidates = [ranked[0][0]]
            for profile, score in ranked[1:]:
                if score == ranked[0][1]:
                    candidates.append(profile)
                else:
                    break
            entry["profile"] = None
            entry["ambiguous_profiles"] = [
                {"slug": p.slug, "name": p.name, "score": tied_scores[0]} for p in candidates
            ]
            ambiguous_addresses.append(result.address)
        else:
            entry["profile"] = None

        # Services worth remarking on, straight from the advertising packet.
        flagged = []
        for uuid in result.service_uuids:
            risk = risk_for(uuid)
            if risk:
                flagged.append(
                    {
                        "uuid": uuid,
                        "label": risk.label,
                        "severity": risk.severity.name,
                        "category": risk.category,
                    }
                )
        entry["flagged_services"] = flagged
        entries.append(entry)

    report.data = {
        "scan_seconds": args.timeout,
        "adapter": args.adapter,
        "device_count": len(entries),
        "devices": entries,
        "profiles_loaded": [p.slug for p in profiles],
    }

    _add_findings(report, entries)

    if args.address or args.name:
        report.note(
            "Results were filtered; devices not matching the filter were not assessed."
        )
    if len(entries) == 0 and not (args.address or args.name):
        report.note(
            "No devices found. If this follows a `brat impersonate` or `brat inject` "
            "session, BlueZ D-Bus state may be corrupted — run: "
            "`sudo systemctl restart bluetooth && sleep 3` then retry."
        )
    if ambiguous_addresses:
        report.note(
            f"{len(ambiguous_addresses)} device(s) matched more than one profile with "
            "an equal score, so no profile was auto-picked for them (see "
            "'ambiguous_profiles' on the device entry). Pass --profile explicitly for "
            "these, e.g. to `brat posture`."
        )
    report.note(
        "Passive advertising capture only. No connection was made, so nothing here "
        "reflects GATT-level security - run `brat posture` for that."
    )

    return report


def _add_findings(report: Report, entries: list[dict]) -> None:
    """Advertising-only findings. Deliberately conservative.

    A scan cannot tell you whether a device enforces authentication. It can
    tell you the device is trackable and what it is broadcasting about itself.
    """
    for entry in entries:
        address = entry["address"]

        if entry["trackable_address"]:
            report.findings.add(
                Finding(
                    check="privacy.static-address",
                    title=f"Static, trackable BLE address ({entry['address_type']})",
                    severity=Severity.LOW,
                    target=address,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "This device advertises an address that does not rotate. Anyone "
                        "within radio range can log its presence over time and correlate "
                        "sightings into a movement history for whoever carries it. "
                        "Resolvable private addresses exist to prevent exactly this and "
                        "rotate roughly every 15 minutes."
                    ),
                    evidence={
                        "address": address,
                        "address_type": entry["address_type"],
                        "advertised_name": entry["name"],
                    },
                    remediation=(
                        "Use resolvable private addresses (LE Privacy) with an IRK "
                        "shared only with bonded peers."
                    ),
                    references=[
                        "Bluetooth Core Spec, Vol 3, Part C, 10.7 (Privacy Feature)"
                    ],
                )
            )

        for flagged in entry["flagged_services"]:
            risk = risk_for(flagged["uuid"])
            if risk is None:
                continue
            report.findings.add(
                Finding(
                    check=f"advertising.service.{risk.category}",
                    title=f"Advertises {risk.label}",
                    severity=Severity.INFO if risk.severity < Severity.HIGH else Severity.MEDIUM,
                    target=address,
                    confidence=Confidence.INFERRED,
                    description=(
                        f"{risk.rationale} This was seen in the advertising packet, so it "
                        "is visible without connecting. Connect with `brat posture` to "
                        "determine whether it is actually reachable unauthenticated."
                    ),
                    evidence={"uuid": flagged["uuid"], "advertised_name": entry["name"]},
                    remediation=risk.remediation,
                )
            )


def render(report: Report, console: Console) -> None:
    data = report.data
    devices = data["devices"]

    console.header(f"DEVICES ({len(devices)})")
    if not devices:
        console.write()
        console.warn("Nothing found. If you expected a device here, check `brat doctor`.")
        return

    rows = []
    for d in devices:
        profile = d.get("profile")
        tag = ""
        if profile:
            tag = f"{profile['slug']}"
            if profile["has_protocol"]:
                tag += " +proto"
        elif d.get("ambiguous_profiles"):
            tag = f"ambiguous ({len(d['ambiguous_profiles'])})"
        rows.append(
            [
                d["address"],
                (d["name"] or "-")[:28],
                str(d["rssi"]) if d["rssi"] is not None else "-",
                d["address_type"],
                str(len(d["service_uuids"])),
                tag or "-",
            ]
        )

    console.write()
    console.table(
        ["ADDRESS", "NAME", "RSSI", "ADDR TYPE", "SVCS", "PROFILE"], rows
    )

    interesting = [
        d
        for d in devices
        if d.get("profile") or d.get("ambiguous_profiles") or d["flagged_services"]
    ]
    if interesting:
        console.header("NOTABLE")
        for d in interesting:
            console.write()
            name = d["name"] or "(unnamed)"
            console.write(f"  {console.bold(name)}  {console.dim(d['address'])}")
            if d.get("profile"):
                p = d["profile"]
                console.kv("matches profile", f"{p['name']} ({p['slug']}, score {p['score']})", 4)
                if p["has_protocol"]:
                    console.kv(
                        "protocol", "profile defines an application-layer protocol", 4
                    )
            elif d.get("ambiguous_profiles"):
                names = ", ".join(f"{p['slug']} (score {p['score']})" for p in d["ambiguous_profiles"])
                console.kv(
                    "ambiguous match",
                    f"tied between {len(d['ambiguous_profiles'])} profiles: {names} - "
                    "pass --profile explicitly",
                    4,
                )
            for f in d["flagged_services"]:
                console.kv(f"{f['severity'].lower()}", f"{f['label']}  {console.dim(f['uuid'])}", 4)
            for uuid in d["service_uuids"]:
                if not any(f["uuid"] == uuid for f in d["flagged_services"]):
                    console.kv("service", f"{uuid_label(uuid, 'service')}  {console.dim(uuid)}", 4)
