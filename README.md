# BRAT — BLE Recon and Attack Toolkit

**Clone a BLE device into a portable profile, then become it — or drive it.**

Most BLE security tooling plays the central: it connects to a device and asks
it questions. BRAT does that too, but the reason it exists is the other half —
standing your machine up *as* the device and recording what talks to it, or
connecting to the real device and driving it with crafted protocol commands.

```
brat clone --address AA:BB:CC:DD:EE:FF          # device  -> profiles/mydevice.yaml
brat impersonate --profile mydevice --confirm   # profile -> a live rogue peripheral
brat drive --profile mydevice -a AA:BB:.. --confirm   # send commands to the real device
```

That round trip is the whole idea. Everything else in the toolkit supports it.

---

## Why this exists

The peripheral side of BLE testing is where the tooling ran out. The MITM and
device-cloning frameworks that security researchers cite — GATTacker, BtleJuice
— were written around 2016 against Node.js BLE stacks that are no longer
maintained, and several want two machines to run a single attack. A 2025 survey
that evaluated BLE tooling against real devices found most of it no longer
usable. Meanwhile the central-side tools have gotten good.

So BRAT is deliberately not another scanner. It is a maintained, Python,
profile-driven implementation of the part nobody kept up:

|                          | Central-side tools | BRAT |
|--------------------------|:------------------:|:----:|
| Scan / enumerate GATT    | yes                | yes  |
| Posture and auth checks  | yes                | yes  |
| **Clone a device to a reusable profile** | no | **yes** |
| **Advertise and serve as that device**   | no | **yes** |
| **Decode a vendor protocol from a config file** | no | **yes** |
| **Inject fabricated data into a client** | no | **yes** |
| **Drive the real device with crafted commands** | no | **yes** |

If you want deep central-side assessment, use a central-side tool —
Praetorian's [Caeruleus](https://github.com/praetorian-inc/caeruleus) is
excellent and explicitly scopes itself to the central role. Use BRAT when you
need to be the peripheral. They compose well.

---

## Quick Start

### Requirements

- **Linux** with BlueZ (tested on Ubuntu 20.04+, Debian, Kali)
- **Python 3.9+**
- **Bluetooth adapter** — any USB dongle works for scanning/posture; peripheral mode needs one that supports LE advertising (Intel, Realtek, CSR — most do)

### Install

```bash
# Clone and install
git clone https://github.com/MuzzammilHussainMohd/brat.git
cd brat
pip install -e '.[peripheral]'

# Verify your environment
brat doctor
```

That's it. If `brat doctor` shows green, you're ready.

**Minimal install** (recon only, no peripheral mode):
```bash
pip install -e .
```

### First scan

```bash
sudo brat scan
```

You'll see every BLE device advertising nearby, with address type classification
and profile fingerprinting if a match exists.

---

## The workflow

### 1. Find it

```bash
$ brat scan
```

```
DEVICES (4)

  ADDRESS            NAME            RSSI  ADDR TYPE      SVCS  PROFILE
  D4:8A:39:11:22:33  MyDevice        -48   random-static  1     example_nus_device +proto
  C8:1B:2E:00:11:22  Fitness-Band    -71   resolvable...  2     -
```

Every result is scored against every known profile, so the output names the
device instead of leaving you to recognise a MAC. It also classifies the
address type — a device advertising a non-rotating address can be followed
around by anyone with a receiver, which is a real finding that most scanners
never surface.

### 2. Check whether it does its job

```bash
$ brat posture --address D4:8A:39:11:22:33
```

One script, no device-specific logic. It connects cold and reports what an
unauthenticated peer was allowed to do:

```
VERDICT: connected and read data with no pairing, no authentication, no encryption.

FINDINGS (6)

 CRITICAL  Firmware update interface writable by an unauthenticated peer
           gatt.dfu-exposed
 HIGH      Data is transferred over an unencrypted link
           link.no-encryption
 ...
```

Findings are marked **confirmed** (BRAT performed the action and it worked) or
**inferred** (a property says it would work, but BRAT did not exercise it —
usually because doing so would write to the device). Tools that blur those two
produce findings that evaporate under scrutiny. `--probe-writes` converts the
inferred write findings into confirmed ones, and skips firmware-update
characteristics while doing it.

Run it against a device you believe is well configured and you should get the
opposite verdict. That is the point — it is the same script.

### 3. Clone it

```bash
$ brat clone --address D4:8A:39:11:22:33
```

Walks the advertising data and the full GATT tree and writes a complete profile.
No hand-authoring:

```yaml
device:
  slug: my_device
  name: MyDevice
match:
  name: MyDevice
  service_uuids: [6e400001-b5a3-f393-e0a9-e50e24dcca9e]
gatt:
  services:
    - uuid: 6e400001-b5a3-f393-e0a9-e50e24dcca9e
      name: Nordic UART Service (NUS)
      characteristics:
        - uuid: 6e400002-b5a3-f393-e0a9-e50e24dcca9e
          properties: [write, write-without-response]
```

A clone copies values verbatim, so it can pick up serial numbers and other
per-unit identifiers. BRAT tells you when it has, and `--no-values` gives you a
structure-only clone.

### 4. Become it

```bash
$ brat impersonate --profile my_device --confirm
```

Your machine now advertises that name and serves that GATT tree. Point the real
client at it and read what it sends:

```
[+] Advertising as 'MyDevice'. Waiting for a central to connect.

[+] Central connected (inferred from first GATT operation at 14:22:07.118)

  [14:22:07.412] WRITE -> NUS RX (central writes here)  (25B)
         0000  A5 00 00 D0 E0 A3 00 0E 49 44 45 4E 54 30 30 31  |........IDENT001|
         0010  69 C1 B4 B0 01 4A 1F 3C 5A                        |.....J.<Z|
         CMD=0xA3 (AUTH)  direction=0  length=14  payload=14B
  [14:22:07.562] NOTIFY <- A3-ack  (20B)
```

This is also the practical way to learn an undocumented protocol: let the real
client talk to your clone and read the frames.

---

## The protocol engine

Most custom BLE devices don't use GATT semantically. They open a transparent
serial pipe — Nordic UART or a vendor equivalent — and push fixed-layout frames
through it. GATT enumeration sees the pipe; it cannot see the frames.

So a profile can declare the framing as data, and BRAT will decode and generate
frames for a protocol it has never seen:

```yaml
protocol:
  frame:
    fields:
      - {name: start,   type: const,  value: "A5"}
      - {name: cmd,     type: u8}
      - {name: length,  type: u16be,  length_of: payload}
      - {name: payload, type: bytes,  length_from: length}
      - {name: crc,     type: crc}
      - {name: end,     type: const,  value: "5A"}
  crc:
    algorithm: crc16-ibm
    byte_order: big
```

Checksums are configured, not coded: `crc16-modbus`, `crc16-ccitt-false`,
`crc16-xmodem`, `crc16-kermit`, `crc8`, `crc8-maxim`, `crc32`, `sum8`, `xor8`,
plus per-field overrides for anything unusual. Every preset is verified against
its published check value in the test suite.

Responses are templates over the request:

```yaml
  emulation:
    variables:
      bind_token: "DEADBEEFCAFE0001"
    rules:
      - on_cmd: 0xA3
        respond:
          - {cmd: 0xA3, direction: 0x01, payload: "{req.payload[0:8]}01", delay: 0.15}
          - {cmd: 0xA4, direction: 0x02, delay: 1.2,
             payload: "{req.payload[0:8]}{var.bind_token}{ts:u32be}"}
```

| Token | Substitutes |
|---|---|
| `{req.payload[a:b]}` | a slice of the request payload |
| `{req.raw[a:b]}` | a slice of the raw request frame |
| `{var.NAME}` | a profile variable |
| `{blob.NAME}` | a file loaded with `--payload NAME=FILE` |
| `{sess.NAME}` | a value captured from an earlier frame |
| `{ts}` / `{ts:u32le}` | current unix time |
| `{rand:N}` / `{zero:N}` | N random / zero bytes |

All of `req.payload`, `req.raw`, `var.`, `blob.` and `sess.` take an `[a:b]`
slice. A slice that runs past the end of its source is an error, not a short
field — silently truncating produces a malformed frame that looks like the
device replied with nonsense.

Real handshakes need more than the frame in front of them. A device that
receives an account identifier during authentication has to quote it back in a
data frame several commands later, so a rule can save one:

```yaml
  - name: auth
    on_cmd: 0xA3
    capture:
      uid: "{req.payload[0:8]}"     # readable later as {sess.uid}

  - name: data-sync-push
    on_cmd: 0x90
    once: true                       # clients that time out restart the
    respond:                         # handshake; unsolicited pushes must
      - {cmd: 0x92, delay: 0.2,      # not go out twice
         payload: "{sess.uid}{blob.sync[8:]}"}
```

Captures are cleared when the central disconnects, so the next client is never
answered with the previous one's identifiers. Delays accumulate across every
response a frame matches, which is how a device that pushes something
unprompted after a handshake step gets expressed — as a second rule on the
same command, not as a special "unsolicited" construct.

Length fields and checksums are computed for you. Writing a working device
emulator is a config exercise, not a programming one.

---

## Injecting data

```bash
brat inject --profile mydevice --confirm \
  --on-cmd 0x93 --inject '02{ts:u32be}{rand:64}'
```

When the client sends command `0x93`, it gets a correctly-framed, correctly-
checksummed frame of your content instead of the device's. The profile's normal
handshake rules still run, so the client reaches the state where the injected
frame makes sense.

**A limit worth stating plainly:** this proves a client *accepted and parsed*
fabricated data. It cannot prove what the client then did with it — displayed,
stored, uploaded. That requires observing the client, which is a separate
exercise. BRAT's findings are worded to that boundary and say so.

---

## Driving the real device

The mirror image of `impersonate`/`inject`: connect to the *real* device as an
unauthenticated central and send it correctly framed protocol commands.

```bash
brat drive --profile mydevice -a AA:BB:CC:DD:EE:FF --confirm \
  --send 30 --send 20:00 --send 30
```

`posture` can tell you the command characteristic is writable by anyone; `drive`
tells you what the device does when someone writes to it. The sequence above
sends a read-back command, a state-changing command, and the same read again —
if the two replies differ, the device's own response proves the change came from
an unauthenticated attacker.

```
STATE CHANGE PROVEN
  probe:      0x30 (STATUS)
  before:     0028 01 00 01000001
  after:      0028 00 00 01000001
    byte 2:   01 -> 00
  caused by:  0x20 (ALARM_SET)

CRITICAL  An unauthenticated command changed device state
```

The state-change inference requires no knowledge of what the command means. A
device that refuses to talk without pairing produces an INFO finding instead,
and a device that tears down the link (common when pairing fails) is reported
as a disconnect — both are the "secure" outcome.

---

## Commands

| Command | Transmits | Does |
|---|:---:|---|
| `brat doctor` | no | Adapter, BlueZ, and peripheral-mode readiness |
| `brat scan` | no | Passive discovery, profile fingerprinting, address typing |
| `brat enum` | no | Full GATT tree with risk annotations |
| `brat posture` | no | Security posture check with severity-ranked findings |
| `brat clone` | no | Device → reusable YAML profile |
| `brat impersonate` | **yes** | Serve a profile as a rogue peripheral |
| `brat inject` | **yes** | Serve a profile and feed the client fabricated data |
| `brat drive` | **yes** | Connect to a device and issue protocol commands |
| `brat profiles` | no | List, show, and validate profiles |
| `brat protocol` | no | Infer a frame layout from a capture, or decode against a profile |

Every command supports `-o text|json|jsonl`. JSON is canonical and complete;
the terminal view is a rendering of it, never the other way round. `--fail-at`
sets the severity that makes the process exit non-zero, for CI use.

---

## Writing your own profile

You usually don't — `brat clone` writes it. When you do, start from
[`brat/profiles/example_wearable.yaml`](brat/profiles/example_wearable.yaml) (a
minimal template) or [`brat/profiles/example_medical_device.yaml`](brat/profiles/example_medical_device.yaml) (a complete profile with a `protocol:` block), and check it with:

```bash
brat profiles validate myprofile
```

### Working out an unknown protocol

A GATT walk sees the pipe, not the frames, so a fresh clone can only listen.
The loop that closes that:

```bash
brat impersonate --profile mydevice --confirm --session-log session.json
brat protocol infer --session-log session.json          # hex   -> draft block
# paste the block into the profile, rename the fields
brat protocol decode --profile mydevice -s session.json # block -> proof
```

`infer` looks for the framing constants, an offset whose value tracks the frame
length, the byte that varies most (the command, usually), and brute-forces
every checksum preset, byte order and covered range. Then it builds an engine
from its own output, decodes the same capture back, and refuses to claim
success below 100% — an inference nobody checked is a guess wearing a suit. It
says so plainly when there are too few frames, when every frame is the same
length so a length field cannot be told from a constant, and when no checksum
fits, rather than inventing an answer.

`decode` is the other direction: it shows what your block made of each frame,
field by field, and what the profile would have replied with.

Once you know a device family's framing, carry it onto the next unit:

```bash
brat clone --address <MAC> --protocol-from mydevice
```

`examples/decode_frame.py` still works and is a short tour of the library API.

Profiles are searched in `$BRAT_PROFILE_PATH`, `./profiles/`,
`~/.config/brat/profiles/`, then the ones shipped here.

[`brat/profiles/example_medical_device.yaml`](brat/profiles/example_medical_device.yaml) is the worked example
with a complete `protocol:` block, if you want to see what a finished one looks
like.

---

## Safety and scope

`impersonate`, `inject`, and `drive` transmit. They require `--confirm`, and
there is no environment variable that bypasses it — passing the flag *is* the
bypass, and it has to be typed. Without it you get a dry run describing exactly
what would have happened.

- Point BRAT only at hardware you own or have written authorisation to test.
- A rogue peripheral will accept connections from **any** central in range,
  including devices belonging to people who did not consent. Consider where you
  run it.
- Impersonating a device on a radio you do not control may be unlawful where
  you are, regardless of intent.
- Session logs and cloned profiles contain raw bytes from real clients. Treat
  everything BRAT writes to disk as sensitive, and review it before sharing.

Passive advertising capture (`brat scan`) is a different matter — advertising
packets are broadcast in the clear by design and listening to them intercepts
nothing private.

### Included profiles

The example profiles in `brat/profiles/` demonstrate different use cases:

- `example_wearable.yaml` — minimal template, no protocol block
- `example_nus_device.yaml` — Nordic UART Service device with full protocol
- `example_medical_device.yaml` — complete profile with emulation rules and variables

These are synthetic examples meant to illustrate what a finished profile looks
like. They contain no data from any real device or session.

---

## Troubleshooting

### `brat doctor` fails

```bash
# Make sure BlueZ is running
sudo systemctl start bluetooth

# Check adapter is recognized
hciconfig -a

# If adapter shows DOWN:
sudo hciconfig hci0 up
```

### Permission denied

Most commands need root for raw HCI access:
```bash
sudo brat scan
sudo brat posture --address AA:BB:CC:DD:EE:FF
```

### Adapter shows as hci1 instead of hci0

Pass `--adapter hci1` to any command:
```bash
sudo brat scan --adapter hci1
```

---

## Development

```bash
pip install -e '.[all]'
pytest -q
```

300+ tests, no hardware required. Most of the peripheral suite runs against a
stubbed bless server, but `tests/test_peripheral_realbless.py` drives the *real*
one with only D-Bus faked underneath — which is what catches the things a stub
cannot, since a fake server never performs bless's own flag conversion or builds
its advertisement. CRC presets are verified against published check values, the
frame codec is verified by round-tripping a 237-byte frame recorded off real
hardware, and layout inference is verified by round trip: frames built with a
known codec, run through `infer` with the codec discarded, must produce the same
field types and constants back.

Contributions welcome, especially:

- **Profiles** for devices you own — the more the toolkit ships, the more useful
  `brat scan` gets for everyone.
- **Checksum algorithms** and frame field types the codec doesn't cover yet.
- **Posture checks.** They are small independent functions in
  `brat/commands/posture.py`; adding one is a local change.

---

## Authors

- Muzzammil Hussain Mohd
- Narmina Karimova
- Gigi Lau
- Luces

## License

Apache 2.0.
