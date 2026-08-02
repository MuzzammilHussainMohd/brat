# Demo target firmware — handoff brief

Written 2026-08-02 at the end of the session that got `brat impersonate` working
on air for the first time. This is the starting context for the *next* piece of
work, which is a separate effort: building a BLE peripheral we own, to attack in
the demo instead of the Mira analyzer.

Read this first, then see "Open decisions" for what still needs deciding.

---

## Why this exists

BRAT is a general-purpose BLE recon and attack toolkit. Its flagship story is the
round trip `brat clone` (device → YAML profile) → `brat impersonate` (profile →
live rogue peripheral). Every command is generic; a YAML profile is what makes it
device-specific.

Until now the demo target was a Mira Ultra4 fertility tracker — an FDA-cleared
Class II medical device. **That is being dropped as the demo target.** Three
reasons:

1. Nobody in the audience owns one, so nothing shown can be reproduced or
   verified by them that evening.
2. Every artifact in the repo currently says "Mira", which undercuts the actual
   claim being made — that BRAT is a general tool and not a pile of
   device-specific scripts.
3. Disclosure constraints cap what can be shown.

The Mira work is **not** discarded. It stays as the research contribution (the
paper, the findings). The own-target becomes the demonstrable, reproducible
artifact. They complement each other; the talk should keep at least one slide of
Mira evidence as the "and here is the same class of bug in a real shipping
medical device" proof that it is not a toy.

---

## Hardware — verified this session, do not re-derive

Four radios are present. Roles are constrained by what each one can actually do:

| Role | Device | Constraint |
|---|---|---|
| Target peripheral | **nRF52840-DK** (SEGGER J-Link `1366:1061`) | to be flashed |
| Attacker: impersonate/inject | **TP-Link UB500**, Realtek, `2357:0604` → `hci1`, `E0:D3:62:64:7C:A5` | **the only radio here that can advertise** |
| Sniffer | nRF52840 dongle A (`2fe3:000b`) | needs nRF Sniffer firmware; see `tools/sniffer_mode.sh` |
| Recon central: scan/enum/posture/clone | nRF52840 dongle B (`2fe3:000b`) | central mode works fine — it scanned 91 devices |

The two dongles currently run Zephyr `hci_usb` and take `hci0` / `hci2`.

**Facts established by measurement, worth not rediscovering:**

- The dongles **cannot advertise**. They boot with BD address
  `00:00:00:00:00:00`, and BlueZ invents a random static address to paper over
  it, so `bluetoothctl show` looks healthy and is not evidence. `brat doctor`
  detects and refuses them for peripheral mode.
- That zero-address problem is a property of the **Zephyr `hci_usb` sample
  build**, not of the nRF52840 chip. An nRF52840 running a peripheral
  *application* uses its FICR address and advertises normally. So a dongle
  could serve as a target too — the DK is still preferred for its debugger,
  buttons, LEDs and RTT console.
- `brat impersonate --adapter hci1` is **verified working on air**: a physically
  separate radio received 64 ADV_IND + 55 SCAN_RSP at -27 dBm, name complete and
  untruncated, connectable and scannable, held 28s, torn down cleanly. No
  `Memory Capacity Exceeded`.
- **Two adapters in one machine cannot see each other via the BlueZ API.** They
  share one `bluetoothd`, which never raises a `Device1` object for an address
  belonging to one of its own controllers. `brat scan` on `hci2` will not list
  `hci1`'s advertisement even while `btmon --index 2` shows it arriving. This
  cost real time to diagnose; `brat doctor` now warns about it
  (`local-adapter-selftest`). **The DK is unaffected** — it is a separate board,
  not managed by the host's `bluetoothd`, so `brat scan` will see it normally.
- Always pass `--adapter hci1` for peripheral commands. bless resolves its
  adapter by literal substring match on `"hci0"` and fails outright otherwise.

---

## Decisions already made

- **Target board: nRF52840-DK.** Real BD address, onboard J-Link so the target's
  internal state can be shown changing while the attack lands, plus buttons and
  LEDs for visible effect.
- **Client: the nRF Connect mobile app.** Chosen for simplicity — no companion
  app to write.

### What the client choice costs, and what it means for the firmware

nRF Connect connects to anything, so there is **no trust decision to subvert**.
`impersonate` therefore cannot demonstrate "the victim app was fooled". Its story
becomes "here is the cloned device, byte-identical, and nothing on the wire
distinguishes it from the real one."

That is still a real demo, but it shifts the weight: **the target firmware has to
carry the drama.** A visible state change on the board is what sells it, not the
client. Design accordingly.

(If that turns out too weak once built, the fallback discussed was a small
companion app with realistic trust logic — matching by name + service UUID, the
same way the Mira app does — so the trust decision can be shown in source. Not
chosen, but keep it in mind.)

---

## What the firmware should deliberately contain

Design so each BRAT command has something to bite:

- **A NUS-based framed protocol** — header constant, length byte, command byte,
  CRC-16. Makes `brat protocol infer` demonstrable. The Mira frame format is a
  good shape to borrow without the target *being* Mira; see the Protocol Quick
  Reference in the parent `CLAUDE.md`.
- **An unauthenticated command that changes state** — `brat posture` finds it,
  `brat inject` exploits it.
- **A bind/auth handshake carrying a value captured from an earlier frame** —
  exercises the profile schema's `capture:` clause and `{sess.NAME}` tokens.
- **A buttonless DFU characteristic** — the DoS trigger, safely, on hardware we
  own.
- **A characteristic whose value visibly drives an LED** — so the audience *sees*
  the injection land.

**The money shot** is the self-contained round trip: `clone` the DK →
`impersonate` it → nRF Connect connects to the fake → `inject` → the LED changes
on a board that is no longer even in the conversation.

---

## Open decisions

1. **Zephyr vs nRF Connect SDK** for the target firmware. Not yet decided; this
   is the first thing to settle.
2. Whether the framed protocol should mirror the Mira layout closely (reuses
   existing analysis, risks looking Mira-specific) or be deliberately different
   (proves generality, more work).
3. Whether to keep a secondary off-the-shelf device as a "it generalizes" demo.

---

## Success criteria

The demo works when, with the real DK powered off:

1. `brat clone --address <DK> --adapter hci2` produces a profile that validates.
2. `brat impersonate --profile <clone> --adapter hci1 --confirm` advertises, and
   nRF Connect on a phone finds and connects to it.
3. The session log shows frames received and answered, every tx `delivered: true`.
4. `brat protocol infer --session-log <log>` independently rediscovers the
   framing and CRC of the firmware that produced it.
5. `brat inject` changes the LED state on the real DK.

---

## Useful paths

- `README.md` — full command reference and profile schema
- `brat/profiles/example_wearable.yaml` — a simple committable profile to model on
- `brat/profiles/mira_ultra4.yaml` — reference profile with a full `protocol:`
  block (5 rules), including `capture:` / `{sess.NAME}` / `once:` usage
- `tools/sniffer_mode.sh`, `tools/flash_hci.sh` — dongle firmware switching
- `tools/diag_connect.sh` — three-layer HCI / D-Bus / BRAT correlation when a
  session stalls
- Parent `CLAUDE.md` — Mira protocol reference, ethics/scope rules
