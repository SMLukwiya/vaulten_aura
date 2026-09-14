#ifndef AURA_H2_FRAME_H
#define AURA_H2_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "error_lib.h"
#include "types_lib.h"

/* H2 errors */
typedef enum {
    A_H2_ERR_NONE = 0x0,
    A_H2_PROTOCOL_ERR = 0x1,
    A_H2_INTERNAL_ERR = 0x2,
    A_H2_FLOW_CONTROL_ERR = 0x3,
    A_H2_SETTINGS_TIMEOUT_ERR = 0x4,
    A_H2_STREAM_CLOSED_ERR = 0x5,
    A_H2_FRAME_SIZE_ERR = 0x6,
    A_H2_REFUSED_STREAM_ERR = 0x7,
    A_H2_CANCEL_ERR = 0x8,
    A_H2_COMPRESSION_ERR = 0x9,
    A_H2_CONNECT_ERR = 0xA,
    A_H2_ENHANCE_YOUR_CALM = 0xB,
    A_H2_INADEQUATE_SEC_ERR = 0xC,
    A_H2_PREFACE_ERR = 0xD,
    A_H2_IN_PROGRESS_ERR = 0xE
} aura_h2_frame_error_t;

/* Frame types */
typedef enum {
    A_H2_FRAME_TYPE_DATA = 0x0,
    A_H2_FRAME_TYPE_HDRS = 0x1,
    A_H2_FRAME_TYPE_PRIO = 0x2,
    A_H2_FRAME_TYPE_RST = 0x3,
    A_H2_FRAME_TYPE_SETTINGS = 0x4,
    A_H2_FRAME_TYPE_PUSH_PROMISE = 0x5,
    A_H2_FRAME_TYPE_PING = 0x6,
    A_H2_FRAME_TYPE_GOAWAY = 0x7,
    A_H2_FRAME_TYPE_WIND_UPDATE = 0x8,
    A_H2_FRAME_TYPE_CONT = 0x9,
    A_H2_FRAME_TYPE_PRIO_UPDATE = 0x10,
} aura_h2_frame_t;

/* Frame flags */
#define A_H2_FRAME_FLAG_END_STREAM 0x1
#define A_H2_FRAME_FLAG_END_HEADERS 0x4
#define A_H2_FRAME_FLAG_PADDED 0x8
#define A_H2_FRAME_FLAG_PRIORITY 0x20
#define A_H2_FRAME_FLAG_ACK 0x1
#define A_H2_FRAME_FLAG_NONE 0

/* Settings Ids */
typedef enum {
    A_H2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    A_H2_SETTINGS_ENABLE_PUSH = 0x2,
    A_H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    A_H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    A_H2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    A_H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
} aura_h2_settings_id;

#define A_H2_FRAME_HEADER_SIZE 9
#define A_H2_FRAME_INCOMPLETE 0xD

#define A_H2_STREAM_ID_MASK 0x7FFFFFFF
#define A_H2_PING_FRAME_PAYLOAD_SZ 64

/* H2 Frame structure */
struct aura_h2_frame {
    const uint8_t *payload;
    uint32_t stream_id;
    uint32_t len;
    uint8_t type;
    uint8_t flags;
};

/* H2 settings frame */
struct aura_h2_settings {
    uint32_t hdr_table_size;
    uint32_t max_conc_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_hdr_list_size;
    bool enable_push;
};

/* Reset payload structure */
struct aura_h2_rst_stream_payload {
    uint32_t error_code;
};

/* Settings payload structure */
struct aura_h2_settings_payload {
    uint32_t value;
    uint16_t settings_id;
};

/* Ping payload structure */
struct aura_h2_ping_payload {
    uint8_t data[8];
};

/* Goaway payload structure */
struct aura_h2_goaway_payload {
    struct aura_iovec debug_data;
    uint32_t last_stream_id;
    uint32_t error_code;
};

/* Wind update payload structure */
struct aura_h2_wind_update_payload {
    uint32_t increment;
};

static inline void aura_h2_frame_dump(struct aura_h2_frame *f, bool _syslog) {
    app_debug(_syslog, 0, "H2 FRAME");
    app_debug(_syslog, 0, "    Length: %lu", f->len);
    app_debug(_syslog, 0, "    Stream id: %lu", f->stream_id);
    app_debug(_syslog, 0, "    Frame Type: %ld", f->type);
    app_debug(_syslog, 0, "    Flags: %ld", f->flags);
    app_debug(_syslog, 0, "    Payload: %p", f->payload);
}

static inline uint8_t a_h2_unpack_8u(const uint8_t *src) {
    return (uint8_t)src[0];
}

static inline uint16_t a_h2_unpack_16u(const uint8_t *src) {
    return (uint16_t)(src[0] << 8 | src[1]);
}

static inline uint32_t a_h2_unpack_24u(const uint8_t *src) {
    return (uint32_t)(src[0] << 16 | src[1] << 8 | src[2]);
}

static inline uint32_t a_h2_unpack_32u(const uint8_t *src) {
    return (uint32_t)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
}

static inline uint8_t *a_h2_pack_8u(uint8_t *dest, uint8_t val) {
    *dest++ = val;
    return dest;
}

static inline uint8_t *a_h2_pack_16u(uint8_t *dest, uint16_t val) {
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

static inline uint8_t *a_h2_pack_24u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

static inline uint8_t *a_h2_pack_32u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 24;
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

/**
 *
 */
static inline void aura_h2_decode_goaway_payload(struct aura_h2_frame *frame, struct aura_h2_goaway_payload *payload) {
    payload->last_stream_id = a_h2_unpack_32u(frame->payload) & A_H2_STREAM_ID_MASK;
    payload->error_code = a_h2_unpack_32u(frame->payload + 4);
    if (frame->len > 8) {
        payload->debug_data.len = frame->len - 8;
        payload->debug_data.base = (char *)(frame->payload + 8);
    } else {
        payload->debug_data.base = NULL;
        payload->debug_data.len = 0;
    }
}

static inline void aura_h2_decode_frame_header(struct aura_h2_frame *frame, const uint8_t *src) {

    frame->len = a_h2_unpack_24u(src);
    frame->type = a_h2_unpack_8u(src + 3);
    frame->flags = a_h2_unpack_8u(src + 4);
    frame->stream_id = a_h2_unpack_32u(src + 5) & A_H2_STREAM_ID_MASK;
    frame->payload = src + A_H2_FRAME_HEADER_SIZE;
}

#endif
