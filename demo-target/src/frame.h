/*
 * GlucoSense-7A21 wire protocol.
 *
 * Fixed-layout framing carried over the Nordic UART Service:
 *
 *   7E 00 <dir> 10 20 <cmd> <len:u16be> <payload...> <crc16:be> EF
 *   |  |   |    |  |    |      |            |            |      |
 *   |  |   |    |  |    |      |            |            |      end marker
 *   |  |   |    |  |    |      |            |            CRC-16/MODBUS, big-endian
 *   |  |   |    |  |    |      |            payload, `len` bytes
 *   |  |   |    |  |    |      payload length, 16-bit big-endian
 *   |  |   |    |  |    command byte
 *   |  |   |    |  source address (constant)
 *   |  |   |    destination address (constant)
 *   |  |   direction: 0 = from client, 1 = ack, 2 = push
 *   |  reserved
 *   start marker
 *
 * The CRC covers every byte from `start` through the end of `payload` -
 * that is, everything before the CRC field itself. It does NOT cover the
 * end marker.
 *
 * The length field is a full 16 bits even though no command here uses a
 * payload longer than 64 bytes, so its high byte reads as a constant 0x00
 * in every capture. That is deliberate: it is exactly the kind of detail a
 * frame-inference pass has to get right, and misreading it as padding
 * produces a decoder that works until the first long response.
 */

#ifndef FRAME_H_
#define FRAME_H_

#include <zephyr/kernel.h>
#include <stdbool.h>
#include <stdint.h>

#define FRAME_START     0x7E
#define FRAME_RESERVED  0x00
#define FRAME_DST       0x10
#define FRAME_SRC       0x20
#define FRAME_END       0xEF

/* Byte count of everything that is not payload. */
#define FRAME_OVERHEAD  11
#define FRAME_MAX_PAYLOAD 64
#define FRAME_MAX_LEN   (FRAME_OVERHEAD + FRAME_MAX_PAYLOAD)

/* Direction field values. */
#define DIR_REQUEST     0x00
#define DIR_ACK         0x01
#define DIR_PUSH        0x02

/* Commands. */
#define CMD_PING        0x01
#define CMD_AUTH        0x10
#define CMD_ALARM_SET   0x20
#define CMD_STATUS      0x30
#define CMD_TELEMETRY   0x40

struct frame {
	uint8_t  direction;
	uint8_t  cmd;
	uint16_t length;
	uint8_t  payload[FRAME_MAX_PAYLOAD];
};

/* CRC-16/MODBUS: poly 0x8005 reflected (0xA001), init 0xFFFF, no final XOR. */
uint16_t frame_crc16(const uint8_t *data, size_t len);

/*
 * Parse one frame from `buf`. Returns true only if the markers, length and
 * CRC all check out. `out` is untouched on failure.
 */
bool frame_parse(const uint8_t *buf, size_t len, struct frame *out);

/*
 * Serialise a frame. Returns the number of bytes written to `buf`, or 0 if
 * `payload_len` exceeds FRAME_MAX_PAYLOAD or the buffer is too small.
 */
size_t frame_build(uint8_t *buf, size_t buf_len, uint8_t direction, uint8_t cmd,
		   const uint8_t *payload, uint16_t payload_len);

#endif /* FRAME_H_ */
