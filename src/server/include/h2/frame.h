#ifndef AURA_SRV_FRAME_H
#define AURA_SRV_FRAME_H

#include "list_lib.h"
#include "mem.h"
#include "sliding_buf.h"
#include "types_lib.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    A_H2_ERR_NONE = 0x0,
    A_H2_PROTOCOL_ERR = -0x1,
    A_H2_INTERNAL_ERR = -0x2,
    A_H2_FLOW_CONTROL_ERR = -0x3,
    A_H2_SETTINGS_TIMEOUT_ERR = -0x4,
    A_H2_STREAM_CLOSED_ERR = -0x5,
    A_H2_FRAME_SIZE_ERR = -0x6,
    A_H2_REFUSED_STREAM_ERR = -0x7,
    A_H2_CANCEL_ERR = -0x8, /* Technically not a real error, more of an indication */
    A_H2_COMPRESSION_ERR = -0x9,
    A_H2_CONNECT_ERR = -0xA,
    A_H2_ENHANCE_YOUR_CALM = -0xB, /* Peer should relax, sip something, light up something to calm its nerves, Ha!! */
    A_H2_INADEQUATE_SEC_ERR = -0xC,
    A_H2_PREFACE_ERR = -0xD,
    A_H2_IN_PROGRESS_ERR = -0xE
} aura_h2_frame_error_t;

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
} aura_h2_frame_t;

#define A_H2_FRAME_FLAG_END_STREAM 0x1
#define A_H2_FRAME_FLAG_END_HEADERS 0x4
#define A_H2_FRAME_FLAG_PADDED 0x8
#define A_H2_FRAME_FLAG_PRIORITY 0x20
#define A_H2_FRAME_FLAG_ACK 0x1
#define A_H2_FRAME_FLAG_NONE 0

typedef enum {
    A_H2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    A_H2_SETTINGS_ENABLE_PUSH = 0x2,
    A_H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    A_H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    A_H2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    A_H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
} aura_h2_settings_id;

#define A_H2_INITIAL_WINDOW_SIZE 65536
#define A_H2_MAX_WINDOW_SIZE 0x7FFFFFFF
#define A_H2_MIN_FRAME_SIZE 16384
#define A_H2_MAX_FRAME_SIZE 16777215
#define A_H2_MAX_HEADER_LEN 0xFFFFFF
#define A_H2_MAX_DEBUG_PAYLOAD_LEN 16376

#define A_H2_FRAME_HEADER_SIZE 9
#define A_H2_FRAME_INCOMPLETE 0xD

#define A_H2_STREAM_ID_MASK 0x7FFFFFFF
#define A_H2_PING_FRAME_PAYLOAD_SZ 64

#define a_h2_priority_is_exclusive(n) (n & 0x80000000)
#define a_h2_connection_is_closing(state) ((state) == A_H2_STATE_CONN_CLOSING)

#define aura_h2_frame_is_padded(flags) ((flags & A_H2_FRAME_FLAG_PADDED) != 0)
#define aura_h2_frame_has_priority(flags) ((flags & A_H2_FRAME_FLAG_PRIORITY) != 0)
#define aura_h2_frame_is_ack(flags) ((flags & A_H2_FRAME_FLAG_ACK) != 0)
#define aura_h2_frame_is_end_stream(flags) (((flags) & A_H2_FRAME_FLAG_END_STREAM) != 0)
#define aura_h2_frame_is_end_headers(flags) (((flags) & A_H2_FRAME_FLAG_END_HEADERS) != 0)

struct aura_h2_frame {
    const uint8_t *payload;
    uint32_t stream_id;
    uint32_t len;
    uint8_t type;
    uint8_t flags;
};

struct aura_h2_settings {
    uint32_t hdr_table_size;
    uint32_t max_conc_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_hdr_list_size;
    bool enable_push;
};

/* Deprecated */
struct aura_h2_priority {
    uint32_t dependency;
    uint8_t exclusive;
    uint8_t weight;
};

struct aura_h2_data_payload {
    const uint8_t *data;
    uint8_t *pad; /* optional */
    size_t len;
    uint8_t pad_len; /* optional */
};

struct aura_h2_hdrs_payload {
    struct aura_h2_priority priority;
    const uint8_t *src;
    uint32_t len;
};

struct aura_h2_rst_stream_payload {
    uint32_t error_code;
};

struct aura_h2_settings_payload {
    uint32_t value;
    uint16_t settings_id;
};

struct aura_h2_push_promise_payload {
    uint32_t stream_id;
    uint16_t pad_len;
    uint8_t *hdr_block;
    uint8_t *padding;
};

struct aura_h2_ping_payload {
    uint8_t data[8];
};

struct aura_h2_goaway_payload {
    struct aura_iovec debug_data;
    uint32_t last_stream_id;
    uint32_t error_code;
};

struct aura_h2_window_update_payload {
    uint32_t increment;
};

struct aura_h2_cont_payload {
    const uint8_t *src;
    uint32_t len;
};

/** Inbound frame structure */
struct aura_h2_in_frame {
    struct aura_h2_frame frame; /* internal h2 frame structure */
    union {
        struct aura_h2_data_payload data_payload;
        struct aura_h2_hdrs_payload hdrs_payload;
        struct aura_h2_rst_stream_payload rst_payload;
        struct aura_h2_settings settings_payload;
        struct aura_h2_push_promise_payload promise_payload;
        struct aura_h2_ping_payload ping_payload;
        struct aura_h2_goaway_payload goaway_payload;
        struct aura_h2_window_update_payload wind_update_payload;
        struct aura_h2_cont_payload cont_payload;
        struct aura_h2_priority prio_payload;
    };
    uint32_t expected_bytes;
    uint8_t pad_len;
    bool frame_hdr_read;
};

static inline bool aura_h2_frame_is_complete(struct aura_h2_in_frame *in_frame, uint32_t len) {
    return (in_frame->frame_hdr_read && len >= in_frame->expected_bytes);
}

/* Reset in_frame for next frame */
static inline void aura_h2_frame_reset_inframe(struct aura_h2_in_frame *in_frame) {
    memset(in_frame, 0, sizeof(*in_frame));
}

static inline int aura_h2_get_frame_error(int rv) {
    return -(rv);
}

/**/
void aura_dump_h2_frame(struct aura_h2_frame *f);
void aura_dump_h2_settings(struct aura_h2_settings *s);

/**
 * Parse frame payload associated with
 * type of frame
 */
int aura_h2_parse_frame_payload(struct aura_h2_in_frame *in_frame);
/**
 * Parse the fixed 9 bytes
 * of the frame header
 */
int aura_h2_parse_frame_header(struct aura_h2_in_frame *in_frame, const uint8_t *src,
                               size_t src_len, size_t max_frame_size);

uint8_t *aura_h2_encode_ctrl_frame(struct aura_sliding_buf *buf, uint8_t type, uint8_t flags,
                                   uint32_t stream_id, uint32_t frame_len, const uint8_t *payload,
                                   uint32_t payload_len);

/** */
int aura_h2_encode_hdr_frame(struct aura_sliding_buf *buf, uint32_t stream_id, uint8_t type,
                             uint8_t flags, const uint8_t *payload, uint32_t payload_len);

int aura_h2_encode_data_frame(struct aura_sliding_buf *buf, uint32_t stream_id, uint8_t flags,
                              const uint8_t *payload, uint32_t payload_len, uint8_t pad_len);

#endif
