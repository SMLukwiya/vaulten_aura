#include "frame.h"
/**
 * Conn preface: Valid vs Invalid
 * Conn preface: Empty: Timeout
 *
 * Invalid settings:
 *  - invalid len, invalid stream id, invalid value, invalid ack
 *
 * Wrong headerse
 *  - missing mandatory pseudo header
 *  - invalid pseudo header (after regular header)
 *  - uppercase in header name
 *  - conn specific header,e.g, transfer encoding
 *
 * Invalid continuation
 *  - Interleaved frame
 *  - wrong stream
 *  - endless continuation
 *
 * Invalid frame sequence
 *  - Data on idle stream
 *  - Data on closed stream
 *  - Frame after goaway (sent and received)
 *  - Push promise from client
 *
 * Invalid Window update
 * Ping bad length
 * RST stream on idle stream
 */

static void aura_h2_probe_write_frame_header(uint8_t *dest, uint32_t len, uint8_t type, uint8_t flags, uint32_t stream_id) {
    dest = aura_pack_24u(dest, len);
    dest = aura_pack_8u(dest, type);
    dest = aura_pack_8u(dest, flags);
    dest = aura_pack_32u(dest, stream_id);
}

int aura_h2_probe_parse_frame_header(struct aura_h2_frame *frame, const uint8_t *buf, uint64_t len) {
    aura_h2_decode_frame_header(frame, buf);
    return 0;
}
