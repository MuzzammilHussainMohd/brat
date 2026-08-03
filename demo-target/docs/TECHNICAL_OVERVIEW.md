# GlucoSense BLE Security Demo - Technical Overview

## Project Overview

A simulated continuous glucose monitor (CGM) built on **nRF52840-DK** with two firmware variants to demonstrate BLE security vulnerabilities in medical devices.

| Component | v1 (GlucoSense-OPEN) | v2 (GlucoSense-SECURE) |
|-----------|---------------------|------------------------|
| Pairing | **None** | Passkey: `123456` |
| Encryption | **None** | AES-CCM link encryption |
| MITM Protection | **None** | Passkey MITM protection |
| Bonding | **Disabled** | Required |

---

## Wire Protocol (over Nordic UART Service)

```
7E 00 <dir> 10 20 <cmd> <len:u16be> <payload...> <crc16:be> EF
│  │   │    │  │    │       │           │            │      │
│  │   │    │  │    │       │           │            │      End marker
│  │   │    │  │    │       │           │            CRC-16/MODBUS (big-endian)
│  │   │    │  │    │       │           Payload (variable length)
│  │   │    │  │    │       Payload length (16-bit big-endian)
│  │   │    │  │    Command byte
│  │   │    │  Source address (0x20, constant)
│  │   │    Destination address (0x10, constant)
│  │   Direction: 0x00=request, 0x01=ack, 0x02=push
│  Reserved (0x00)
Start marker (0x7E)
```

### Commands

| Cmd | Hex | Function |
|-----|-----|----------|
| PING | `0x01` | Connectivity test |
| AUTH | `0x10` | Authentication (accepts ANY identifier) |
| ALARM_SET | `0x20` | **Silence/activate alarm** |
| STATUS | `0x30` | Get glucose, alarm state, auth state |
| TELEMETRY | `0x40` | Battery, sensor age, uptime |

### STATUS Response Format

```
Offset  Size  Field
------  ----  -----
0-1     2     glucose_mg_dl (uint16_t big-endian)
2       1     alarm_state (0x00 = silent, 0x01 = active)
3       1     auth_state (0x00 = no, 0x01 = yes)
4-7     4     firmware_version
```

### TELEMETRY Response Format

```
Offset  Size  Field
------  ----  -----
0       1     battery_percent
1-2     2     sensor_age_hours (uint16_t big-endian)
3-6     4     uptime_seconds (uint32_t big-endian)
```

---

## BLE Services Exposed

| Service | UUID | Purpose |
|---------|------|---------|
| Nordic UART (NUS) | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` | Command/response transport |
| SIG Glucose | `0x1808` | Standard glucose reading |
| DFU Service | `0xFE59` | Buttonless DFU (decoy) |

### NUS Characteristics

| Characteristic | UUID | Properties | Purpose |
|----------------|------|------------|---------|
| TX | `6e400003-...` | NOTIFY | Device → App responses |
| RX | `6e400002-...` | WRITE, WRITE_NO_RSP | App → Device commands |

### DFU Characteristic

| Characteristic | UUID | Properties | Purpose |
|----------------|------|------------|---------|
| Buttonless DFU | `8ec90003-f315-4f60-9fb8-838830daea50` | WRITE, INDICATE | Triggers reboot |

---

## Vulnerabilities in v1 (GlucoSense-OPEN)

### 1. No Link-Layer Security

```c
// prj.conf - v1 is MISSING these:
// CONFIG_BT_SMP=y          ← No Security Manager Protocol
// CONFIG_BT_BONDABLE=y     ← No bonding
// CONFIG_BT_BONDING_REQUIRED=y
```

**Impact:** Any device in radio range can connect and communicate. No encryption, no authentication at BLE layer.

### 2. Unauthenticated ALARM_SET Command

```c
case CMD_ALARM_SET: {
    // THE VULNERABILITY - v1 never checks state.authenticated
    if (f->length < 1) return;
    bool want_alarm = (f->payload[0] != 0x00);
    
#ifdef CONFIG_BT_SMP
    // v2 ONLY: Requires authentication to silence alarm
    if (!want_alarm && !state.authenticated) {
        LOG_WRN("ALARM_SET(silence) rejected: not authenticated");
        return;
    }
#endif
    // v1: Falls through - NO CHECK!
    set_alarm(false);  // Silences alarm without any credential
}
```

**Attack Frame:**
```
7E 00 00 10 20 20 00 01 00 3F 87 EF
```

**Impact:** 
- Alarm LED turns off
- Glucose value remains critically low (e.g., 45 mg/dL)
- **State divergence:** Device shows "everything fine" while patient is in danger

### 3. Fake Authentication (CMD_AUTH)

```c
case CMD_AUTH: {
    // Accepts ANY identifier - nothing to verify against
    memcpy(state.uid, f->payload, 8);
    state.authenticated = true;  // Always succeeds!
    LOG_INF("AUTH accepted... (nothing was verified)");
}
```

**Attack:** Send any 8-byte identifier → always "authenticated"

**Impact:** Authentication is theater - provides no actual security.

### 4. Unauthenticated DFU Reboot (DoS)

```c
static ssize_t dfu_write(...) {
    if (data[0] == 0x01) {
        LOG_WRN("No credential was required. Rebooting in 1s.");
        k_work_schedule(&reboot_work, K_MSEC(1000));
    }
}
```

**Attack:** Write `0x01` to DFU characteristic

**Impact:** Device reboots immediately → denial of service, patient loses CGM data.

### 5. GATT Permissions Wide Open

```c
// v1 permissions:
#define GLUCOSENSE_PERM_READ  BT_GATT_PERM_READ   // No encryption required
#define GLUCOSENSE_PERM_WRITE BT_GATT_PERM_WRITE  // Anyone can write
```

---

## Security in v2 (GlucoSense-SECURE)

### 1. SMP Pairing Required

```c
// prj_secure.conf:
CONFIG_BT_SMP=y
CONFIG_BT_BONDABLE=y
CONFIG_BT_BONDING_REQUIRED=y
CONFIG_BT_SMP_ENFORCE_MITM=y
CONFIG_BT_FIXED_PASSKEY=y       // Passkey: 123456
```

### 2. Encrypted Characteristics

```c
// v2 permissions:
#define GLUCOSENSE_PERM_READ  BT_GATT_PERM_READ_ENCRYPT
#define GLUCOSENSE_PERM_WRITE BT_GATT_PERM_WRITE_ENCRYPT
```

**Effect:** Connection without pairing → `ATT_ERROR_INSUFFICIENT_ENCRYPTION` (0x0F)

### 3. ALARM_SET Requires Authentication

```c
#ifdef CONFIG_BT_SMP
    if (!want_alarm && !state.authenticated) {
        LOG_WRN("ALARM_SET(silence) rejected: not authenticated");
        uint8_t nak[2] = {f->payload[0], 0x00};
        send_frame(DIR_ACK, CMD_ALARM_SET, nak, sizeof(nak));
        return;  // ← Blocks the attack
    }
#endif
```

### 4. Bond Storage

```c
CONFIG_BT_SETTINGS=y
CONFIG_FLASH=y
CONFIG_NVS=y
CONFIG_SETTINGS=y
```

**Effect:** Bonding keys persist across reboots.

---

## Glucose Simulation

```c
#define GLUCOSE_INITIAL_VALUE   120   // Starts at 120 mg/dL
#define GLUCOSE_ALARM_THRESHOLD 70    // Alarm triggers below 70
#define GLUCOSE_DRIFT_INTERVAL_MS 7000 // Drops 1 mg/dL every 7 seconds

static void glucose_drift_handler(...) {
    if (state.glucose_mg_dl > 40) {
        state.glucose_mg_dl--;
    }
    update_alarm_state();  // Sets alarm_active if < 70
}
```

**Behavior:**
- Starts at 120 mg/dL
- Drops by 1 every 7 seconds
- Minimum value: 40 mg/dL
- Alarm triggers when glucose < 70 mg/dL
- Alarm must be manually silenced (does not auto-clear when glucose rises)

---

## Android App Architecture

| Component | Function |
|-----------|----------|
| BLE Scanner | Filters by NUS service UUID |
| Device List | Shows all GlucoSense devices with connection state |
| GATT Client | Connects, subscribes to NUS TX notifications |
| Protocol Handler | Sends STATUS requests every 2 seconds, parses responses |
| UI | Shows glucose value, alarm state, connection status |

### App Flow

1. Start scanning for devices with NUS service UUID
2. Display discovered GlucoSense devices in list
3. User taps device → connect via GATT
4. Subscribe to NUS TX characteristic (notifications)
5. Poll STATUS command every 2 seconds
6. Parse response and update UI

---

## Demo Attack Scenario

1. **v1 Running:** Device shows glucose drifting down (120 → 70 → alarm triggers)
2. **Attacker connects:** No pairing prompt
3. **Attacker sends:** `ALARM_SET(0x00)` → Alarm LED turns off
4. **Result:** Glucose continues dropping (65, 60, 55...) but alarm is silenced
5. **Patient impact:** No warning of hypoglycemia

**v2 Defense:** Same attack fails with "ENCRYPTION REQUIRED" error until passkey entered.

---

## File Locations

| File | Purpose |
|------|---------|
| `src/main.c` | Firmware logic, GATT services, vulnerability |
| `src/frame.c` | Wire protocol implementation |
| `src/frame.h` | Wire protocol definition |
| `prj.conf` | v1 config (insecure) |
| `prj_secure.conf` | v2 config (secure) |
| `android/` | Companion app source |

## Build Locations

| Firmware | Build Directory |
|----------|-----------------|
| GlucoSense-OPEN (v1) | `/tmp/build_v1/` |
| GlucoSense-SECURE (v2) | `/tmp/build_v2/` |

## Flashing

```bash
# Flash v1 (insecure)
west flash -d /tmp/build_v1

# Flash v2 (secure)
west flash -d /tmp/build_v2
```
