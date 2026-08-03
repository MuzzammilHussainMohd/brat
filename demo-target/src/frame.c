/*
 * Frame codec for GlucoSense-7A21. See frame.h for the wire layout.
 */

#include <string.h>

#include "frame.h"

uint16_t frame_crc16(const uint8_t *data, size_t len)
{
	uint16_t crc = 0xFFFF;

	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int bit = 0; bit < 8; bit++) {
			if (crc & 1U) {
				crc = (crc >> 1) ^ 0xA001;
			} else {
				crc >>= 1;
			}
		}
	}

	return crc;
}

bool frame_parse(const uint8_t *buf, size_t len, struct frame *out)
{
	if (len < FRAME_OVERHEAD) {
		return false;
	}

	if (buf[0] != FRAME_START || buf[1] != FRAME_RESERVED ||
	    buf[3] != FRAME_DST || buf[4] != FRAME_SRC) {
		return false;
	}

	uint16_t payload_len = ((uint16_t)buf[6] << 8) | buf[7];

	if (payload_len > FRAME_MAX_PAYLOAD) {
		return false;
	}

	/* The frame must be exactly this long - no trailing bytes. A write
	 * carrying more than one frame is rejected rather than partially
	 * accepted, so a malformed batch cannot smuggle a second command.
	 */
	if (len != (size_t)FRAME_OVERHEAD + payload_len) {
		return false;
	}

	if (buf[len - 1] != FRAME_END) {
		return false;
	}

	size_t crc_offset = 8 + payload_len;
	uint16_t got = ((uint16_t)buf[crc_offset] << 8) | buf[crc_offset + 1];
	uint16_t want = frame_crc16(buf, crc_offset);

	if (got != want) {
		return false;
	}

	out->direction = buf[2];
	out->cmd = buf[5];
	out->length = payload_len;
	if (payload_len) {
		memcpy(out->payload, &buf[8], payload_len);
	}

	return true;
}

size_t frame_build(uint8_t *buf, size_t buf_len, uint8_t direction, uint8_t cmd,
		   const uint8_t *payload, uint16_t payload_len)
{
	if (payload_len > FRAME_MAX_PAYLOAD) {
		return 0;
	}

	size_t total = (size_t)FRAME_OVERHEAD + payload_len;

	if (buf_len < total) {
		return 0;
	}

	buf[0] = FRAME_START;
	buf[1] = FRAME_RESERVED;
	buf[2] = direction;
	buf[3] = FRAME_DST;
	buf[4] = FRAME_SRC;
	buf[5] = cmd;
	buf[6] = (uint8_t)(payload_len >> 8);
	buf[7] = (uint8_t)(payload_len & 0xFF);

	if (payload_len && payload != NULL) {
		memcpy(&buf[8], payload, payload_len);
	}

	size_t crc_offset = 8 + payload_len;
	uint16_t crc = frame_crc16(buf, crc_offset);

	buf[crc_offset] = (uint8_t)(crc >> 8);
	buf[crc_offset + 1] = (uint8_t)(crc & 0xFF);
	buf[crc_offset + 2] = FRAME_END;

	return total;
}
