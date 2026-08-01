"""`brat profiles` - list, inspect, and validate device profiles.

Useful on its own, and the quickest way to check that a profile you just wrote
by hand is well formed before taking it to hardware.
"""

from __future__ import annotations

from ..core.console import Console
from ..core.profile import (
    Profile,
    ProfileError,
    available_profiles,
    load_profile,
    profile_search_paths,
)
from ..core.report import Report
from ..core.uuids import label as uuid_label
from ..core.uuids import risk_for


async def execute(args, console: Console) -> Report:
    report = Report(command="profiles")

    if args.profile_action == "show":
        return _show(args, report)
    if args.profile_action == "validate":
        return _validate(args, report)
    return _list(report)


def _list(report: Report) -> Report:
    entries = []
    for path in available_profiles():
        try:
            profile = Profile.load(path)
        except ProfileError as exc:
            entries.append(
                {
                    "path": str(path),
                    "slug": path.stem,
                    "error": str(exc),
                    "valid": False,
                }
            )
            continue
        entries.append(
            {
                "path": str(path),
                "slug": profile.slug,
                "name": profile.name,
                "vendor": profile.vendor,
                "services": len(profile.services),
                "characteristics": sum(len(s.characteristics) for s in profile.services),
                "has_protocol": profile.protocol_config is not None,
                "emulation_rules": (
                    len(profile.protocol.rules) if profile.protocol_config else 0
                ),
                "valid": not profile.validate(),
            }
        )

    report.data = {
        "search_paths": [str(p) for p in profile_search_paths()],
        "count": len(entries),
        "profiles": entries,
    }
    return report


def _show(args, report: Report) -> Report:
    profile = load_profile(args.name)
    report.target = profile.slug
    report.data = {
        "slug": profile.slug,
        "name": profile.name,
        "vendor": profile.vendor,
        "model": profile.model,
        "source": profile.source,
        "notes": profile.notes,
        "path": str(profile.path),
        "match": profile.match.to_dict(),
        "advertising": profile.advertising.to_dict(),
        "security": profile.security.to_dict(),
        "services": [s.to_dict() for s in profile.services],
        "protocol": (
            {
                "name": profile.protocol.name,
                "commands": {
                    f"0x{k:02X}": v for k, v in profile.protocol.commands.items()
                },
                "rules": [
                    {
                        "name": r.name,
                        "on_cmd": f"0x{r.on_cmd:02X}" if r.on_cmd is not None else None,
                        "on_any": r.on_any,
                        "responses": len(r.responses),
                    }
                    for r in profile.protocol.rules
                ],
                "variables": sorted(profile.protocol.variables),
            }
            if profile.protocol_config
            else None
        ),
        "validation_problems": profile.validate(),
    }
    return report


def _validate(args, report: Report) -> Report:
    targets = [args.name] if args.name else [str(p) for p in available_profiles()]
    results = []
    for target in targets:
        try:
            profile = load_profile(target)
            problems = profile.validate()
            results.append(
                {"profile": profile.slug, "path": str(profile.path), "problems": problems, "ok": not problems}
            )
        except ProfileError as exc:
            results.append({"profile": target, "problems": [str(exc)], "ok": False})

    report.data = {"results": results, "all_ok": all(r["ok"] for r in results)}
    return report


def render(report: Report, console: Console) -> None:
    data = report.data

    if "results" in data:
        console.header("VALIDATION")
        for r in data["results"]:
            if r["ok"]:
                console.write(f"  {console.green('ok  ')} {r['profile']}")
            else:
                console.write(f"  {console.red('FAIL')} {r['profile']}")
                for p in r["problems"]:
                    console.bullet(p, indent=8)
        return

    if "profiles" in data:
        console.header(f"PROFILES ({data['count']})")
        if not data["profiles"]:
            console.write()
            console.warn("No profiles found. Searched:")
            for p in data["search_paths"]:
                console.bullet(p, indent=4)
            console.write()
            console.info("Create one from a device you own:  brat clone --address <MAC>")
            return

        console.write()
        console.table(
            ["SLUG", "NAME", "SVCS", "CHARS", "PROTOCOL", "OK"],
            [
                [
                    p["slug"],
                    (p.get("name") or "-")[:28],
                    str(p.get("services", "-")),
                    str(p.get("characteristics", "-")),
                    f"{p['emulation_rules']} rules" if p.get("has_protocol") else "-",
                    "yes" if p.get("valid") else "no",
                ]
                for p in data["profiles"]
            ],
        )
        console.write()
        console.write(console.dim("Search paths:"))
        for p in data["search_paths"]:
            console.bullet(console.dim(p), indent=4)
        return

    # show
    console.header(f"{data['name']}  ({data['slug']})")
    for key in ("vendor", "model", "path", "source"):
        if data.get(key):
            console.kv(key, data[key])
    if data.get("notes"):
        console.write()
        console.write(f"  {data['notes']}")

    console.header("MATCHING")
    for k, v in (data["match"] or {}).items():
        console.kv(k, v)

    console.header("ADVERTISING")
    for k, v in (data["advertising"] or {}).items():
        console.kv(k, v)

    console.header("SECURITY EXPECTATIONS")
    for k, v in data["security"].items():
        if k == "sensitive_characteristics":
            console.kv(k, f"{len(v)} characteristic(s)")
            for uuid in v:
                console.bullet(
                    f"{uuid_label(uuid, 'characteristic')} {console.dim(uuid)}", indent=6
                )
        else:
            console.kv(k, v)

    console.header("GATT TREE")
    for service in data["services"]:
        console.write()
        console.write(f"  {console.bold(service.get('name') or service['uuid'])}")
        console.write(f"  {console.dim(service['uuid'])}")
        for char in service["characteristics"]:
            risk = risk_for(char["uuid"])
            marker = console.yellow(f"  <-- {risk.label}") if risk else ""
            console.write(
                f"    {char.get('name') or char['uuid']}{marker}"
            )
            console.write(
                f"        {console.dim(char['uuid'])}  "
                f"{console.cyan(','.join(char.get('properties', [])))}"
            )

    if data.get("protocol"):
        proto = data["protocol"]
        console.header("PROTOCOL")
        console.kv("name", proto["name"])
        console.kv("commands", len(proto["commands"]))
        for code, label in proto["commands"].items():
            console.bullet(f"{code}  {label}", indent=6)
        if proto["variables"]:
            console.kv("variables", ", ".join(proto["variables"]))
        console.kv("emulation rules", len(proto["rules"]))
        for rule in proto["rules"]:
            trigger = rule["on_cmd"] or ("any frame" if rule["on_any"] else "-")
            console.bullet(
                f"{rule['name']}: on {trigger} -> {rule['responses']} response(s)", indent=6
            )

    if data.get("validation_problems"):
        console.header("PROBLEMS")
        for p in data["validation_problems"]:
            console.bullet(p, indent=4)
