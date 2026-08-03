/*
 * GlucoSense-7A21 - a deliberately vulnerable BLE peripheral.
 *
 * Built as a demonstration target for the BRAT toolkit. Every weakness below
 * is intentional and is a real property of this firmware, not a simulation:
 *
 *   - No pairing, bonding, or link encryption is required for anything (v1).
 *   - The framed protocol on NUS authenticates nothing. CMD_AUTH accepts any
 *     identifier and always succeeds; no later command checks whether it ran.
 *   - CMD_ALARM_SET silences a critical low-glucose alarm with no credential.
 *   - A Nordic-style buttonless DFU characteristic reboots the device on an
 *     unauthenticated write.
 *
 * The vulnerability: ALARM_SET with payload 0x00 clears the alarm LED without
 * changing the underlying glucose value. The device continues to read a
 * dangerously low glucose level, but the alarm is silenced - exactly the
 * kind of safety-critical state divergence that matters in medical devices.
 *
 * The DFU characteristic is a decoy: it reboots the application rather than
 * entering a real bootloader, because the point is to demonstrate the
 * unauthenticated-reboot denial of service safely, on hardware we own,
 * without a signed-image update path to get wrong. To a scanner it is
 * indistinguishable from the real thing - same service, same characteristic
 * UUID, same properties.
 */

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/settings/settings.h>

#include <dk_buttons_and_leds.h>

#include "frame.h"

LOG_MODULE_REGISTER(glucosense, LOG_LEVEL_INF);

#define LED_ALARM_ACTIVE DK_LED1   /* lit = urgent low glucose */
#define LED_CONNECTED    DK_LED2
#define LED_HEARTBEAT    DK_LED3

#define RUN_LED_BLINK_INTERVAL 1000

/* Glucose drift interval: decrease by 1 mg/dL every 1.5 seconds (fast for demo) */
#define GLUCOSE_DRIFT_INTERVAL_MS 1500

/* Alarm threshold: below this value triggers urgent low alarm */
#define GLUCOSE_ALARM_THRESHOLD 70

/* Initial glucose value */
#define GLUCOSE_INITIAL_VALUE 120

/* Firmware version reported by CMD_STATUS. A product constant. */
static const uint8_t fw_version[4] = {0x01, 0x00, 0x00, 0x01};

/* Simulated sensor age in hours (static for demo) */
#define SENSOR_AGE_HOURS 48

/* ------------------------------------------------------------------------
 * GATT permission macros - differ between secure and insecure builds
 * ------------------------------------------------------------------------ */

#ifdef CONFIG_BT_SMP
#define GLUCOSENSE_PERM_READ  BT_GATT_PERM_READ_ENCRYPT
#define GLUCOSENSE_PERM_WRITE BT_GATT_PERM_WRITE_ENCRYPT
#else
#define GLUCOSENSE_PERM_READ  BT_GATT_PERM_READ
#define GLUCOSENSE_PERM_WRITE BT_GATT_PERM_WRITE
#endif

/* ------------------------------------------------------------------------
 * Device state
 * ------------------------------------------------------------------------ */

static struct bt_conn *current_conn;

/*
 * Session state. `authenticated` is set by CMD_AUTH and then never consulted
 * by any command handler in v1 - that is the vulnerability, deliberately
 * written so the flaw is visible in the source rather than hidden in an
 * omission. In v2 (CONFIG_BT_SMP), ALARM_SET checks this flag.
 */
static struct {
	bool    authenticated;
	uint8_t uid[8];
	uint16_t glucose_mg_dl;  /* Current glucose value in mg/dL */
	bool    alarm_active;    /* True when glucose < threshold */
	bool    alarm_silenced;  /* Latch: true if alarm was explicitly silenced this episode */
} state;

/* ------------------------------------------------------------------------
 * Glucose simulation - drift timer
 * ------------------------------------------------------------------------ */

static void glucose_drift_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(glucose_drift_work, glucose_drift_handler);

static void update_alarm_state(void)
{
	bool below_threshold = (state.glucose_mg_dl < GLUCOSE_ALARM_THRESHOLD);

	if (!below_threshold) {
		/* Glucose back in range - clear the silenced latch so a future
		 * drop can trigger the alarm again. Do NOT clear alarm_active
		 * here; alarm must be explicitly silenced via ALARM_SET. This is
		 * intentional behavior for medical alarms.
		 */
		state.alarm_silenced = false;
		return;
	}

	/* Below threshold: raise alarm only if not already active AND not
	 * explicitly silenced this episode. This prevents a silenced alarm
	 * from immediately re-raising on the next drift tick.
	 */
	if (!state.alarm_active && !state.alarm_silenced) {
		state.alarm_active = true;
		dk_set_led_on(LED_ALARM_ACTIVE);
		LOG_WRN("*** ALARM: URGENT LOW GLUCOSE (%u mg/dL) ***",
			state.glucose_mg_dl);
	}
}

static void glucose_drift_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	/* Drift glucose downward, minimum value 40 mg/dL */
	if (state.glucose_mg_dl > 40) {
		state.glucose_mg_dl--;
		LOG_INF("Glucose: %u mg/dL", state.glucose_mg_dl);
	}

	update_alarm_state();

	/* Reschedule */
	k_work_schedule(&glucose_drift_work, K_MSEC(GLUCOSE_DRIFT_INTERVAL_MS));
}

/* ------------------------------------------------------------------------
 * Demo button controls (physical access only - not part of threat model)
 *
 * These are test/demo controls for live presentations. Physical access to
 * the development kit is required, which is out of scope for the BLE
 * vulnerability demonstration.
 * ------------------------------------------------------------------------ */

static void button_handler(uint32_t button_state, uint32_t has_changed)
{
	if (has_changed & DK_BTN1_MSK) {
		if (button_state & DK_BTN1_MSK) {
			/* Button 1 pressed: force hypoglycemia for demo */
			LOG_WRN("=== DEMO: Button 1 - forcing hypoglycemia ===");
			state.glucose_mg_dl = 45;
			state.alarm_silenced = false;
			update_alarm_state();
			LOG_WRN("Glucose set to %u mg/dL, alarm should trigger",
				state.glucose_mg_dl);
		}
	}

	if (has_changed & DK_BTN2_MSK) {
		if (button_state & DK_BTN2_MSK) {
			/* Button 2 pressed: reset to normal */
			LOG_INF("=== DEMO: Button 2 - resetting to normal ===");
			state.glucose_mg_dl = GLUCOSE_INITIAL_VALUE;
			state.alarm_active = false;
			state.alarm_silenced = false;
			dk_set_led_off(LED_ALARM_ACTIVE);
			LOG_INF("Glucose reset to %u mg/dL, alarm cleared",
				state.glucose_mg_dl);
		}
	}
}

/* ------------------------------------------------------------------------
 * Nordic UART Service - the transport for the framed protocol
 * ------------------------------------------------------------------------ */

#define BT_UUID_NUS_SERVICE_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_RX_VAL \
	BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_TX_VAL \
	BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

static const struct bt_uuid_128 nus_service_uuid =
	BT_UUID_INIT_128(BT_UUID_NUS_SERVICE_VAL);
static const struct bt_uuid_128 nus_rx_uuid =
	BT_UUID_INIT_128(BT_UUID_NUS_RX_VAL);
static const struct bt_uuid_128 nus_tx_uuid =
	BT_UUID_INIT_128(BT_UUID_NUS_TX_VAL);

static bool nus_notify_enabled;

static void nus_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	nus_notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	LOG_INF("NUS notifications %s",
		nus_notify_enabled ? "ENABLED" : "disabled");
}

static ssize_t nus_rx_write(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr, const void *buf,
			    uint16_t len, uint16_t offset, uint8_t flags);

/*
 * In v1 (no CONFIG_BT_SMP): BT_GATT_PERM_WRITE, any peer can drive this.
 * In v2: BT_GATT_PERM_WRITE_ENCRYPT, requires an encrypted link.
 */
BT_GATT_SERVICE_DEFINE(nus_svc,
	BT_GATT_PRIMARY_SERVICE(&nus_service_uuid),
	BT_GATT_CHARACTERISTIC(&nus_tx_uuid.uuid,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_NONE,
			       NULL, NULL, NULL),
	BT_GATT_CCC(nus_ccc_changed,
		    GLUCOSENSE_PERM_READ | GLUCOSENSE_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(&nus_rx_uuid.uuid,
			       BT_GATT_CHRC_WRITE |
				       BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       GLUCOSENSE_PERM_WRITE,
			       NULL, nus_rx_write, NULL),
);

/* The TX characteristic value sits at attribute index 1 in the table above. */
static int nus_send(const uint8_t *data, uint16_t len)
{
	if (!current_conn || !nus_notify_enabled) {
		return -ENOTCONN;
	}

	return bt_gatt_notify(current_conn, &nus_svc.attrs[1], data, len);
}

/* ------------------------------------------------------------------------
 * SIG Glucose Service (0x1808) - standard BLE glucose service
 * ------------------------------------------------------------------------ */

/* Glucose Measurement characteristic value (simplified for demo) */
static ssize_t glucose_read(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr, void *buf,
			    uint16_t len, uint16_t offset)
{
	/*
	 * Simplified Glucose Measurement format:
	 * - Flags (1 byte): 0x00 = base format
	 * - Sequence Number (2 bytes): always 0x0001 for demo
	 * - Base Time (7 bytes): zeroed for demo
	 * - Glucose Concentration (2 bytes SFLOAT): mg/dL value
	 *
	 * For simplicity, we just return the raw mg/dL as a uint16_t BE.
	 * A real implementation would use the full SFLOAT format.
	 */
	uint8_t measurement[4];

	measurement[0] = (uint8_t)(state.glucose_mg_dl >> 8);   /* High byte */
	measurement[1] = (uint8_t)(state.glucose_mg_dl & 0xFF); /* Low byte */
	measurement[2] = state.alarm_active ? 0x01 : 0x00;
	measurement[3] = state.authenticated ? 0x01 : 0x00;

	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 measurement, sizeof(measurement));
}

static bool glucose_notify_enabled;

static void glucose_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	glucose_notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	LOG_INF("Glucose notifications %s",
		glucose_notify_enabled ? "ENABLED" : "disabled");
}

BT_GATT_SERVICE_DEFINE(glucose_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_16(0x1808)),
	BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_16(0x2A18),
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
			       GLUCOSENSE_PERM_READ,
			       glucose_read, NULL, NULL),
	BT_GATT_CCC(glucose_ccc_changed,
		    GLUCOSENSE_PERM_READ | GLUCOSENSE_PERM_WRITE),
);

/* ------------------------------------------------------------------------
 * Buttonless DFU decoy
 * ------------------------------------------------------------------------ */

#define BT_UUID_DFU_BUTTONLESS_VAL \
	BT_UUID_128_ENCODE(0x8ec90003, 0xf315, 0x4f60, 0x9fb8, 0x838830daea50)

static const struct bt_uuid_128 dfu_buttonless_uuid =
	BT_UUID_INIT_128(BT_UUID_DFU_BUTTONLESS_VAL);

static void dfu_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	LOG_INF("DFU indications %s",
		(value == BT_GATT_CCC_INDICATE) ? "enabled" : "disabled");
}

static void reboot_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(reboot_work, reboot_work_handler);

static void reboot_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	LOG_WRN("Rebooting now (DFU trigger)");
	sys_reboot(SYS_REBOOT_COLD);
}

static ssize_t dfu_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset,
			 uint8_t flags)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	const uint8_t *data = buf;

	if (len < 1) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	LOG_WRN("=== DFU TRIGGER: opcode 0x%02X from unauthenticated peer ===",
		data[0]);

	/* 0x01 is "enter bootloader" in Nordic's buttonless DFU. */
	if (data[0] == 0x01) {
		LOG_WRN("No credential was required. Rebooting in 1s.");
		/* Deferred so the ATT write response is sent before the
		 * reboot - otherwise the client sees a dropped connection
		 * rather than a successful write, which muddles the finding.
		 */
		k_work_schedule(&reboot_work, K_MSEC(1000));
	}

	return len;
}

BT_GATT_SERVICE_DEFINE(dfu_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_16(0xFE59)),
	BT_GATT_CHARACTERISTIC(&dfu_buttonless_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_INDICATE,
			       GLUCOSENSE_PERM_WRITE,
			       NULL, dfu_write, NULL),
	BT_GATT_CCC(dfu_ccc_changed,
		    GLUCOSENSE_PERM_READ | GLUCOSENSE_PERM_WRITE),
);

/* ------------------------------------------------------------------------
 * Protocol command handling
 * ------------------------------------------------------------------------ */

static void send_frame(uint8_t direction, uint8_t cmd, const uint8_t *payload,
		       uint16_t payload_len)
{
	uint8_t out[FRAME_MAX_LEN];
	size_t n = frame_build(out, sizeof(out), direction, cmd, payload,
			       payload_len);

	if (n == 0) {
		LOG_ERR("frame_build failed for cmd 0x%02X", cmd);
		return;
	}

	int err = nus_send(out, n);

	if (err == -ENOTCONN) {
		/* Not a failure: the peer simply never subscribed to the TX
		 * characteristic. A client that writes commands without
		 * enabling notifications is driving the device blind, which
		 * is a perfectly good attack and should not look like a bug.
		 */
		LOG_INF("cmd 0x%02X handled; no reply sent (peer has not "
			"subscribed to notifications)", cmd);
	} else if (err) {
		LOG_ERR("notify failed for cmd 0x%02X (err %d)", cmd, err);
	} else {
		LOG_INF("TX  cmd=0x%02X dir=0x%02X len=%u", cmd, direction,
			payload_len);
	}
}

static void set_alarm(bool active)
{
	state.alarm_active = active;
	dk_set_led(LED_ALARM_ACTIVE, active ? 1 : 0);
	LOG_WRN("*** ALARM STATE -> %s ***", active ? "ACTIVE" : "SILENCED");
}

static void handle_frame(const struct frame *f)
{
	LOG_INF("RX  cmd=0x%02X dir=0x%02X len=%u", f->cmd, f->direction,
		f->length);

	switch (f->cmd) {
	case CMD_PING: {
		uint8_t pong[1] = {0x01};

		send_frame(DIR_ACK, CMD_PING, pong, sizeof(pong));
		break;
	}

	case CMD_AUTH: {
		/*
		 * Accepts any identifier. There is nothing to verify it
		 * against - no shared secret, no challenge, no signature - so
		 * this always succeeds. The identifier is echoed back, which
		 * is what lets an impersonating peripheral replay a value it
		 * captured from an earlier session.
		 */
		if (f->length < 8) {
			LOG_WRN("AUTH with short payload (%u bytes)", f->length);
			return;
		}

		memcpy(state.uid, f->payload, 8);
		state.authenticated = true;

		LOG_INF("AUTH accepted for uid %02X%02X%02X%02X%02X%02X%02X%02X"
			" (nothing was verified)",
			state.uid[0], state.uid[1], state.uid[2], state.uid[3],
			state.uid[4], state.uid[5], state.uid[6], state.uid[7]);

		uint8_t ack[9];

		memcpy(ack, state.uid, 8);
		ack[8] = 0x01; /* accepted */
		send_frame(DIR_ACK, CMD_AUTH, ack, sizeof(ack));
		break;
	}

	case CMD_ALARM_SET: {
		/*
		 * THE VULNERABILITY. In v1, state.authenticated is never
		 * checked. Any peer in radio range can silence a critical
		 * alarm. The underlying glucose value does NOT change - only
		 * the alarm state. This divergence between the real reading
		 * and the reported state is the point.
		 */
		if (f->length < 1) {
			return;
		}

		bool want_alarm = (f->payload[0] != 0x00);

#ifdef CONFIG_BT_SMP
		/* In secure build, require authentication to silence alarm */
		if (!want_alarm && !state.authenticated) {
			LOG_WRN("ALARM_SET(silence) rejected: not authenticated");
			uint8_t nak[2] = {f->payload[0], 0x00}; /* rejected */
			send_frame(DIR_ACK, CMD_ALARM_SET, nak, sizeof(nak));
			return;
		}
#endif

		if (!state.authenticated) {
			LOG_WRN("ALARM_SET accepted from a peer that never "
				"authenticated");
		}

		if (!want_alarm) {
			/* Silence alarm - clears LED1 but does NOT change
			 * glucose value. The glucose may still be critically
			 * low, but the alarm is silenced. Set the latch so
			 * the alarm does not immediately re-raise on the next
			 * drift tick while glucose remains below threshold.
			 */
			set_alarm(false);
			state.alarm_silenced = true;
			LOG_WRN("Alarm silenced while glucose is %u mg/dL",
				state.glucose_mg_dl);
		} else {
			/* Raise alarm manually - clear the silenced latch */
			state.alarm_silenced = false;
			set_alarm(true);
		}

		uint8_t ack[2] = {f->payload[0], 0x01}; /* accepted */

		send_frame(DIR_ACK, CMD_ALARM_SET, ack, sizeof(ack));
		break;
	}

	case CMD_STATUS: {
		/*
		 * Status response format:
		 *   [0-1] glucose_mg_dl (uint16_t big-endian)
		 *   [2]   alarm_state (0x00 = silent, 0x01 = active)
		 *   [3]   auth_state (0x00 = no, 0x01 = yes)
		 *   [4-7] firmware_version (4 bytes)
		 */
		uint8_t resp[8];

		resp[0] = (uint8_t)(state.glucose_mg_dl >> 8);   /* High byte */
		resp[1] = (uint8_t)(state.glucose_mg_dl & 0xFF); /* Low byte */
		resp[2] = state.alarm_active ? 0x01 : 0x00;
		resp[3] = state.authenticated ? 0x01 : 0x00;
		memcpy(&resp[4], fw_version, sizeof(fw_version));
		send_frame(DIR_ACK, CMD_STATUS, resp, sizeof(resp));
		break;
	}

	case CMD_TELEMETRY: {
		/*
		 * Telemetry response format:
		 *   [0]   battery_percent
		 *   [1-2] sensor_age_hours (uint16_t big-endian)
		 *   [3-6] uptime_seconds (uint32_t big-endian)
		 */
		uint32_t uptime = (uint32_t)(k_uptime_get() / 1000);
		uint8_t resp[7];

		resp[0] = 0x54; /* 84% battery */
		resp[1] = (uint8_t)(SENSOR_AGE_HOURS >> 8);   /* High byte */
		resp[2] = (uint8_t)(SENSOR_AGE_HOURS & 0xFF); /* Low byte */
		resp[3] = (uint8_t)(uptime >> 24);
		resp[4] = (uint8_t)(uptime >> 16);
		resp[5] = (uint8_t)(uptime >> 8);
		resp[6] = (uint8_t)(uptime);
		send_frame(DIR_ACK, CMD_TELEMETRY, resp, sizeof(resp));
		break;
	}

	default:
		LOG_WRN("unknown command 0x%02X", f->cmd);
		break;
	}
}

static ssize_t nus_rx_write(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr, const void *buf,
			    uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	struct frame f;

	if (len == 0) {
		/* A zero-length write is how a scanner probes for write
		 * permission without side effects. Accept it so the probe
		 * gets an honest answer, and do nothing else.
		 */
		LOG_INF("zero-length write on NUS RX (permission probe)");
		return len;
	}

	if (!frame_parse(buf, len, &f)) {
		LOG_WRN("dropped %u bytes: not a valid frame", len);
		return len;
	}

	handle_frame(&f);

	return len;
}

/* ------------------------------------------------------------------------
 * Connection handling and advertising
 * ------------------------------------------------------------------------ */

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME,
		sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

/*
 * The 128-bit NUS UUID goes in the scan response rather than the
 * advertisement: a complete local name plus a 128-bit UUID is 31 bytes of
 * AD data, and the advertising packet has exactly 31 to spend. Putting both
 * in would silently truncate the name.
 */
static const struct bt_data sd[] = {
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_SERVICE_VAL),
};

/*
 * Zephyr stops advertising as soon as a connection is established, so it has
 * to be restarted by hand on disconnect. Without this the device is
 * discoverable exactly once per boot: the first client to connect and leave
 * takes it off the air permanently, which looks indistinguishable from a
 * crashed or out-of-range board.
 *
 * Deferred to the system workqueue rather than called straight from the
 * disconnected callback, because the connection object is not fully torn
 * down until that callback returns and restarting from inside it can race
 * the stack's own cleanup.
 */
static void adv_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(adv_work, adv_work_handler);

static void adv_start(void)
{
	int err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd,
				  ARRAY_SIZE(sd));

	if (err == -EALREADY) {
		return;
	}
	if (err) {
		LOG_ERR("advertising failed to start (err %d)", err);
		return;
	}

	LOG_INF("Advertising as '%s'", CONFIG_BT_DEVICE_NAME);
}

static void adv_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	adv_start();
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	if (err) {
		LOG_ERR("connection failed (err %u)", err);
		return;
	}

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Connected: %s (no pairing was required)", addr);

	current_conn = bt_conn_ref(conn);
	dk_set_led_on(LED_CONNECTED);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Disconnected: %s (reason %u)", addr, reason);

	if (current_conn) {
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}

	nus_notify_enabled = false;

	/*
	 * Session state is cleared on disconnect, but the alarm and glucose
	 * state deliberately are not - a silenced alarm persists after the
	 * attacker walks away, which is the point.
	 */
	state.authenticated = false;
	memset(state.uid, 0, sizeof(state.uid));

	dk_set_led_off(LED_CONNECTED);

	k_work_schedule(&adv_work, K_MSEC(100));
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
};

/* ------------------------------------------------------------------------
 * Secure build (CONFIG_BT_SMP) - passkey authentication
 * ------------------------------------------------------------------------ */

#ifdef CONFIG_BT_SMP

/* Fixed passkey for demo - printed to console at boot */
#define FIXED_PASSKEY 123456

static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Passkey for %s: %06u", addr, passkey);
}

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Pairing cancelled: %s", addr);
}

static void auth_pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Pairing complete: %s (bonded=%d)", addr, bonded);
}

static void auth_pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_WRN("Pairing failed: %s (reason %d)", addr, reason);
}

static struct bt_conn_auth_cb auth_cb = {
	.passkey_display = auth_passkey_display,
	.cancel = auth_cancel,
};

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = auth_pairing_complete,
	.pairing_failed = auth_pairing_failed,
};

static void setup_security(void)
{
	int err;

	err = bt_passkey_set(FIXED_PASSKEY);
	if (err) {
		LOG_ERR("bt_passkey_set failed (err %d)", err);
	} else {
		LOG_INF("Fixed passkey set: %06u", FIXED_PASSKEY);
	}

	err = bt_conn_auth_cb_register(&auth_cb);
	if (err) {
		LOG_ERR("bt_conn_auth_cb_register failed (err %d)", err);
	}

	err = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (err) {
		LOG_ERR("bt_conn_auth_info_cb_register failed (err %d)", err);
	}
}

#endif /* CONFIG_BT_SMP */

/* ------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------ */

int main(void)
{
	int err;

	LOG_INF("GlucoSense-7A21 starting");

	err = dk_leds_init();
	if (err) {
		LOG_ERR("dk_leds_init failed (err %d)", err);
		return -1;
	}

	err = dk_buttons_init(button_handler);
	if (err) {
		LOG_ERR("dk_buttons_init failed (err %d)", err);
		return -1;
	}

	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("bt_enable failed (err %d)", err);
		return -1;
	}

#ifdef CONFIG_BT_SETTINGS
	settings_load();
#endif

	LOG_INF("Bluetooth initialised");

#ifdef CONFIG_BT_SMP
	setup_security();
	LOG_INF("Secure mode: pairing required (passkey: %06u)", FIXED_PASSKEY);
#else
	LOG_INF("Insecure mode: no pairing required");
#endif

	/* Initialize glucose state */
	state.glucose_mg_dl = GLUCOSE_INITIAL_VALUE;
	state.alarm_active = false;
	state.alarm_silenced = false;
	state.authenticated = false;

	LOG_INF("Initial glucose: %u mg/dL (alarm threshold: %u mg/dL)",
		state.glucose_mg_dl, GLUCOSE_ALARM_THRESHOLD);
	LOG_INF("Demo controls: Button1=force hypo, Button2=reset normal");

	/* Start glucose drift timer */
	k_work_schedule(&glucose_drift_work, K_MSEC(GLUCOSE_DRIFT_INTERVAL_MS));

	adv_start();

	char addr_s[BT_ADDR_LE_STR_LEN];
	bt_addr_le_t addr = {0};
	size_t count = 1;

	bt_id_get(&addr, &count);
	bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
	LOG_INF("Advertising as '%s' at %s", CONFIG_BT_DEVICE_NAME, addr_s);

	for (;;) {
		dk_set_led(LED_HEARTBEAT, 1);
		k_sleep(K_MSEC(RUN_LED_BLINK_INTERVAL / 2));
		dk_set_led(LED_HEARTBEAT, 0);
		k_sleep(K_MSEC(RUN_LED_BLINK_INTERVAL / 2));
	}

	return 0;
}
