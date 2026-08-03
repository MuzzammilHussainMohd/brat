# Build specification — BLE demonstration targets + companion app

Self-contained brief for building three artifacts. Everything needed to start is
here; no prior conversation is assumed. Work happens in `~/demo-target/`.

**Deliverables**

1. `glucose-v1` — nRF52840-DK firmware, deliberately insecure BLE peripheral
2. `glucose-v2` — same source, secure build configuration
3. `viewer` — minimal Android app that displays the peripheral's readings

These are security-research demonstration targets built on hardware we own.
The insecure build is intentional and its weaknesses are the point; do not
"fix" them in v1.

---

## 1. Environment — already installed, do not redo

The machine is **Kali Linux on aarch64 (ARM64)**, inside a VMware VM. This
matters more than usual — see the traps below.

| Component | Location / version |
|---|---|
| nRF Connect SDK | `~/ncs`, tag **v3.4.0** |
| Zephyr | v4.4.0 (in the NCS tree) |
| Zephyr SDK | `~/zephyr-sdk-1.0.1` |
| ARM compiler | `~/zephyr-sdk-1.0.1/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc` (14.3.0) |
| Python venv for west | `~/ncs/.venv` |
| Flash/debug | `nrfutil` (`/usr/local/bin`), `JLinkExe`, `adb` |

**Build invocation** (both firmware variants):

```bash
cd ~/ncs && source .venv/bin/activate && export ZEPHYR_BASE=~/ncs/zephyr
cd ~/demo-target
west build -b nrf52840dk/nrf52840 -d /tmp/build_v1
west flash -d /tmp/build_v1 --no-rebuild
```

### Traps specific to this machine — read before debugging anything

- **`nrfutil toolchain-manager` does not exist on aarch64.** Every Nordic
  tutorial tells you to run it. `nrfutil search` lists only `ble-sniffer`,
  `core`, `device`, `mcu-manager`, `sdk-manager`, `trace`. The upstream Zephyr
  SDK is used instead and is already installed.
- **Zephyr SDK 1.0 moved the compiler** to `<sdk>/gnu/arm-zephyr-eabi/bin/`,
  not `<sdk>/arm-zephyr-eabi/bin/` as older docs say.
- **Do not set `CONFIG_LOG_MODE_IMMEDIATE=y`.** It formats log output on the
  calling thread's stack; the Bluetooth callbacks overflow within ~50 ms of
  boot and the board enters a reset loop. The symptom is a device that appears
  in scans but never completes a connection — it looks exactly like a radio or
  host problem and will waste hours. Use deferred logging (the default) with
  `CONFIG_LOG_BUFFER_SIZE=4096` and 4096-byte stacks.
- **Advertising must be restarted on disconnect.** Zephyr stops advertising
  once connected; without an explicit restart the device is discoverable only
  once per boot. Use a workqueue item from the disconnect callback, not a
  direct call.
- **USB passthrough into the VM is unreliable.** Devices drop and re-enumerate.
  If BlueZ wedges (`rfkill` lists an adapter but `hciconfig` says "No such
  device", or `btmgmt` hangs), run `sudo systemctl restart bluetooth`.
- Console logging uses deferred mode, so lines are prefixed `I:` / `W:` / `E:`,
  **not** `<inf> module:`. Grep accordingly.

---

## 2. Hardware and roles

| Role | Device | Notes |
|---|---|---|
| Insecure target | nRF52840-DK #1 | flash `glucose-v1` |
| Secure target | nRF52840-DK #2 | flash `glucose-v2` |
| Scanning central | nRF52840 dongle | leave on its current Zephyr `hci_usb` firmware — **do not reflash** |
| Impersonator | TP-Link UB500 (Realtek, `2357:0604`) | the only adapter here that can advertise |
| Viewer | Android phone | over `adb` |

The DK is board target `nrf52840dk/nrf52840`, PCA10056. It advertises from its
FICR address (a real static-random address) and runs standalone on USB, CR2032,
or Li-Po — a host is needed only for flashing.

Serial console is `/dev/ttyACM0` at 115200.

**Nothing is plugged in as of writing.** Confirm with `nrfutil device list` and
`hciconfig` before assuming a fault.

Note: two Bluetooth adapters in the same host cannot see each other through
BlueZ — they share one `bluetoothd`, which never raises a device object for an
address belonging to one of its own controllers. Scanning from the dongle will
not show the UB500's advertisement even when it is provably on air. Verify with
`btmon --index N` below BlueZ, or from a separate machine.

---

## 3. Existing code — starting point

`~/demo-target/` currently contains a **working, verified** peripheral called
`SmartLock-7A21`. It builds clean (13.5% flash, 15.8% RAM) and has been tested
on air. Reuse it; do not start from scratch.

```
~/demo-target/
├── CMakeLists.txt
├── prj.conf
└── src/
    ├── main.c        GATT services, command dispatch, connection handling
    ├── frame.c       frame codec
    └── frame.h       wire format documentation
```

What already works and should be preserved:

- Framed protocol over Nordic UART Service, CRC verified both directions
- Malformed frames (bad CRC) rejected without reply
- A buttonless-DFU-style characteristic that reboots on unauthenticated write
- Advertising restart after disconnect
- Zero-length writes accepted as permission probes without side effects

---

## 4. Firmware task — retheme to a glucose monitor

Rename the device and change command semantics. **The wire format, CRC, and
GATT plumbing stay exactly as they are.**

New identity: **`GlucoSense-7A21`** — a fictional continuous glucose monitor.
Keep it obviously fictional; do not use or imitate any real manufacturer's
name, branding, or product identity.

### Command mapping

| Existing | Becomes | Behaviour |
|---|---|---|
| `0x01` PING | `0x01` PING | unchanged |
| `0x10` AUTH | `0x10` AUTH | unchanged — accepts any identifier, verifies nothing |
| `0x20` LOCK_SET | `0x20` ALARM_SET | payload byte 0 = silence alarm, 1 = raise alarm |
| `0x30` STATUS | `0x30` STATUS | returns current glucose reading + alarm state + firmware version |
| `0x40` TELEMETRY | `0x40` TELEMETRY | battery, sensor age |

### LED mapping (nRF52840-DK)

| LED | Meaning |
|---|---|
| LED1 | alarm active (lit = urgent low) |
| LED2 | client connected |
| LED3 | heartbeat |

### Glucose model

Keep it trivial — a value in mg/dL held in RAM, drifting slowly downward on a
timer so the device reaches an alarm state on its own. Alarm threshold 70
mg/dL. Default start value ~120. `ALARM_SET` with payload `0x00` silences the
alarm and clears LED1 **without changing the underlying value** — the divergence
between the real reading and the reported state is the point.

### Additional GATT service

Add the **SIG standard Glucose service `0x1808`** with the Glucose Measurement
characteristic `0x2A18`, readable **without authentication in v1**. This is in
addition to the existing vendor NUS channel; real devices commonly expose both.

### Wire format (unchanged from the existing code)

```
7E 00 <dir> 10 20 <cmd> <len:u16be> <payload...> <crc16:be> EF
```

- `dir`: `0x00` request, `0x01` ack, `0x02` push
- CRC-16/MODBUS (poly `0x8005` reflected = `0xA001`, init `0xFFFF`, no final
  XOR), big-endian, covering `start` through `payload` — not the end marker
- Fixed overhead 11 bytes; max payload 64

Known-good frames for testing:

| Frame | Bytes |
|---|---|
| PING request | `7E 00 00 10 20 01 00 00 60 5D EF` |
| PING ack | `7E 00 01 10 20 01 00 01 01 69 71 EF` |
| AUTH request (`DEMOUSER`) | `7E 00 00 10 20 10 00 08 44 45 4D 4F 55 53 45 52 FB 8A EF` |
| `0x20` set, payload `01` | `7E 00 00 10 20 20 00 01 01 95 6B EF` |
| STATUS request | `7E 00 00 10 20 30 00 00 AF 0C EF` |

---

## 5. The two build variants

**One source tree, two configuration files.** This is a hard requirement — the
two builds must differ only in `prj.conf` / `prj_secure.conf`, never in `src/`.
The value of the artifact is that the two configs can be diffed side by side.

```bash
west build -b nrf52840dk/nrf52840 -d /tmp/build_v1
west build -b nrf52840dk/nrf52840 -d /tmp/build_v2 -- -DCONF_FILE=prj_secure.conf
```

### v1 — insecure (`prj.conf`)

Current behaviour. No `CONFIG_BT_SMP`. All characteristics use
`BT_GATT_PERM_READ` / `BT_GATT_PERM_WRITE`. Nothing requires pairing,
encryption, or bonding. The application-layer `AUTH` command sets a flag that
no other command ever checks.

This configuration is essentially what Nordic's own `peripheral_uart` and
`peripheral_lbs` samples ship with — no security was removed to produce it.
Preserve that property; it is what makes the artifact honest.

### v2 — secure (`prj_secure.conf`)

Must genuinely refuse an unauthenticated peer at the ATT layer, not merely
behave differently in application code.

- `CONFIG_BT_SMP=y`, bonding enabled
- **Require MITM protection** (passkey), not Just Works. Just Works pairing
  produces an encrypted-but-unauthenticated link and any decent posture check
  will still flag it — a "secure" build that draws a HIGH severity finding
  defeats the purpose. Use a fixed passkey via `bt_passkey_set()` and print it
  to the console.
- All data characteristics use `BT_GATT_PERM_READ_ENCRYPT` /
  `BT_GATT_PERM_WRITE_ENCRYPT`
- The DFU-style reboot characteristic requires an encrypted link
- `ALARM_SET` additionally checks the application-layer auth flag

Expected outcome: a cold read from an unpaired peer returns Insufficient
Authentication / Insufficient Encryption; a bonded peer works normally. Once a
client has bonded, an impersonator advertising the same name cannot complete
encryption and the client's connection fails — that contrast is the entire
purpose of building both variants.

---

## 6. Android viewer app

A prop for a live demonstration, not a product. **One screen. Must work with no
internet and no cable.**

### Constraints

- **No network access at runtime**, ever. Nothing may be fetched, hosted, or
  loaded from a URL.
- Installed once over `adb`; thereafter fully standalone.
- Do **not** use a Web Bluetooth page — it requires a secure-context origin,
  which cannot be satisfied offline without tethering the phone to a laptop.
  That was evaluated and rejected.

### Behaviour

1. Scan for a peripheral advertising the NUS service
   `6e400001-b5a3-f393-e0a9-e50e24dcca9e` and/or the name `GlucoSense-7A21`
2. Connect, subscribe to NUS TX `6e400003-...`
3. Poll `STATUS` (`0x30`) every ~2 s by writing to NUS RX `6e400002-...`
4. Parse the reply and display:
   - glucose value, very large, readable across a room
   - state banner: green **"In range"** / red **"URGENT LOW"**
   - connection status
5. Surface connection and encryption failures visibly — when pointed at the
   secure build without a bond, the failure must be obvious on screen rather
   than a silent blank. This is a demonstrated case, not an error path.

Optional if time allows: a small rolling line graph of recent values. Lowest
priority.

### Build notes for aarch64

The normal Android Gradle toolchain is not viable here — Google ships
`aapt2`/`d8` as x86_64 binaries only. Debian **does** package native arm64
equivalents:

| Package | Arch |
|---|---|
| `android-sdk-build-tools` (29.0.3) | arm64 |
| `aapt` | arm64 |
| `dx` | arm64 |
| `apksigner` | all (Java) |

Java 21 is installed. Expect to assemble the APK manually: `javac` →
`dx` → `aapt` → `apksigner`. Target an older `compileSdk` consistent with the
Debian SDK. Verify `adb devices` sees the phone and that USB debugging is
enabled before starting.

If this path proves unworkable within a couple of hours, say so rather than
sinking a day into it — a generic BLE scanner app is an acceptable, if
unattractive, fallback.

---

## 7. Verification

Firmware, per variant:

```bash
west build ... && west flash ...
sudo timeout 12 cat /dev/ttyACM0     # expect boot banner, no MPU FAULT / stack overflow
```

Then, from the scanning dongle:

- v1: device is discoverable; a cold connection succeeds; characteristics read
  without pairing; a valid frame written to NUS RX produces a correct ack;
  `ALARM_SET 0x00` clears LED1
- v2: device is discoverable; a cold read is refused with a security error;
  after bonding with a passkey, the same operations succeed

App:

- Displays a live value from v1 and updates as the value drifts
- Shows the alarm state changing when `ALARM_SET` is sent by another client
- Against v2 with no bond, fails visibly rather than silently

Sanity checks worth running because each has already caused a
misdiagnosis here: confirm the board is not in a reset loop (console), confirm
the adapter is up (`hciconfig`), and confirm which `hciN` index each radio has
rather than trusting a remembered number — the numbering changes when devices
are replugged.
