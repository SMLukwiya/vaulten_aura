#ifndef AURA_SRV_FRAME_H
#define AURA_SRV_FRAME_H

#include "list_lib.h"
#include "memory_lib.h"
#include "types_lib.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define A_H2_ERROR_NONE 0x0
#define A_H2_PROTOCOL_ERROR 0x1
#define A_H2_INTERNAL_ERROR 0x2
#define A_H2_FLOW_CONTROL_ERROR 0x3
#define A_H2_SETTINGS_TIMEOUT_ERROR 0x4
#define A_H2_STREAM_CLOSED_ERROR 0x5
#define A_H2_FRAME_SIZE_ERROR 0x6
#define A_H2_REFUSED_STREAM_ERROR 0x7
#define A_H2_CANCEL_ERROR 0x8 /* Technically not a real error, more of an indication */
#define A_H2_COMPRESSION_ERROR 0x9
#define A_H2_CONNECT_ERROR 0xA
#define A_H2_ENHANCE_YOUR_CALM 0xB /* Peer should relax, sip something, light up something to calm its nerves, Ha!! */
#define A_H2_INADEQUATE_SEC_ERROR 0xC
#define A_H2_PREFACE_ERROR 0xD

#define AURA_H2_ERROR_IGNORE -100
#define AURA_H2_ERROR_INTERNAL -101

#define A_H2_FRAME_TYPE_DATA 0x0
#define A_H2_FRAME_TYPE_HEADERS 0x1
#define A_H2_FRAME_TYPE_PRIORITY 0x2
#define A_H2_FRAME_TYPE_RST_STREAM 0x3
#define A_H2_FRAME_TYPE_SETTINGS 0x4
#define A_H2_FRAME_TYPE_PUSH_PROMISE 0x5
#define A_H2_FRAME_TYPE_PING 0x6
#define A_H2_FRAME_TYPE_GOAWAY 0x7
#define A_H2_FRAME_TYPE_WINDOW_UPDATE 0x8
#define A_H2_FRAME_TYPE_CONTINUATION 0x9

#define A_H2_FRAME_FLAG_END_STREAM 0x1
#define A_H2_FRAME_FLAG_END_HEADERS 0x4
#define A_H2_FRAME_FLAG_PADDED 0x8
#define A_H2_FRAME_FLAG_PRIORITY 0x20

#define A_H2_FRAME_FLAG_ACK 0x1

#define A_H2_SETTINGS_HEADER_TABLE_SIZE 0x1
#define A_H2_SETTINGS_ENABLE_PUSH 0x2
#define A_H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define A_H2_SETTINGS_INITIAL_WINDOW_SIZE 0x4
#define A_H2_SETTINGS_MAX_FRAME_SIZE 0x5
#define A_H2_SETTINGS_MAX_HEADER_LIST_SIZE 0x6

#define A_H2_INITIAL_WINDOW_SIZE 65536
#define A_H2_MAX_WINDOW_SIZE 0x7FFFFFFF
#define A_H2_MIN_FRAME_SIZE 16384
#define A_H2_MAX_FRAME_SIZE 16777215
#define A_H2_MAX_HEADER_LEN 0xFFFFFF
#define A_H2_MAX_DEBUG_PAYLOAD_LEN 16376

#define A_H2_FRAME_HEADER_SIZE 9
#define A_H2_FRAME_INCOMPLETE 0xD

#define A_H2_STREAM_ID_MASK 0x7FFFFFFF

#define a_h2_priority_is_exclusive(n) (n & 0x80000000)
#define a_h2_connection_is_closing(state) ((state) == A_H2_STATE_CONN_CLOSING)

#define a_h2_frame_is_padded(flags) ((flags & A_H2_FRAME_FLAG_PADDED) != 0)
#define a_h2_frame_has_priority(flags) ((flags & A_H2_FRAME_FLAG_PRIORITY) != 0)
#define a_h2_frame_is_acknowledgement(flags) ((flags & A_H2_FRAME_FLAG_ACK) != 0)
#define a_h2_frame_is_end_stream(flags) (((flags) & A_H2_FRAME_FLAG_END_STREAM) != 0)
#define a_h2_frame_is_end_headers(flags) (((flags) & A_H2_FRAME_FLAG_END_HEADERS) != 0)

#define a_h2_stream_is_push_stream(id) (((id) & 0x1) == 0) /** @todo: remove */
#define a_h2_stream_is_even_numbered(id) (((id) & 0x1) == 0)
#define a_h2_stream_is_odd_numbered(id) (((id) & 0x1) == 1)
// #define a_h2_stream_is_idle(state) (((state) & A_H2_STREAM_STATE_IDLE) != 0)
#define a_h2_stream_is_open(state) (((state) & A_H2_STREAM_STATE_OPEN) != 0)
#define a_h2_stream_is_closed(state) (((state) & A_H2_STREAM_STATE_CLOSED) != 0)
#define a_h2_stream_is_half_closed(state) ((((state) & A_H2_STREAM_STATE_HALF_CLOSED_LOCAL) != 0) || (((state) & A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) != 0))

typedef enum {
    A_H2_HEADER_STARTER, /* Starting header category, the one used for request or response initiation */
    A_H2_HEADER_TRAILER  /* Trailing header category s*/
} aura_h2_frame_hdr_cat_t;

struct aura_h2_frame {
    uint32_t stream_id;
    uint8_t type;
    uint8_t flags;
    uint32_t len;
    const uint8_t *payload;
};

struct aura_frame_builder {
    void *hpack_encoder;

    struct aura_sliding_buf *encode_buf;
};

struct aura_h2_settings {
    uint32_t hdr_table_size;
    bool enable_push;
    uint32_t max_conc_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_hdr_list_size;
};

struct aura_h2_priority {
    uint32_t dependency;
    uint8_t exclusive;
    uint8_t weight;
};

struct aura_h2_data_payload {
    size_t len;
    const uint8_t *data;
    uint8_t *pad;    /* optional */
    uint8_t pad_len; /* optional */
};

struct aura_h2_hdrs_payload {
    uint32_t headers_len;
    const uint8_t *headers;
    struct aura_h2_priority priority;
};

struct aura_h2_rst_stream_payload {
    uint32_t error_code;
};

struct aura_h2_settings_payload {
    uint16_t settings_id;
    uint32_t value;
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
    uint32_t last_stream_id;
    uint32_t error_code;
    struct aura_iovec debug_data;
};

struct aura_h2_window_update_payload {
    uint32_t increment;
};

struct aura_h2_cont_payload {
    uint8_t *hdr_block;
};

struct aura_h2_window {
    int64_t available;
};

/** Inbound frame structure */
struct aura_h2_in_frame {
    struct aura_h2_frame frame; /* internal h2 frame structure */

    bool is_valid; /* frame was parsed without errors */
    bool is_continuation;
    uint8_t pad_len;
    union {
        struct aura_h2_data_payload data_payload;
        struct aura_h2_hdrs_payload headers_payload;
        struct aura_h2_rst_stream_payload rst_stream_payload;
        struct aura_h2_settings settings_payload;
        struct aura_h2_push_promise_payload promise_payload;
        struct aura_h2_ping_payload ping_payload;
        struct aura_h2_goaway_payload goaway_payload;
        struct aura_h2_window_update_payload window_update_payload;
        struct aura_h2_cont_payload continuation_payload;
        struct aura_h2_priority priority_payload;
    };
};

/** Outbound frame structure */
struct aura_h2_out_frame {
    struct aura_h2_frame frame; /* internal h2 frame structure */

    union {
        struct {
            uint8_t *data;
            uint32_t len;
        } encoded; /* data in wire format ready for sending */

        struct {
            uint8_t header[9];
            uint8_t *payload;
            uint32_t payload_len;
            uint8_t pad_len;
        } data; /* data not in wire format, needs assembling during send */
    };
    struct aura_sliding_buf *buf; /* buffer containing this frames bytes */
    struct aura_list_head f_list;
    bool is_urgent;
};

/**/
void aura_dump_h2_frame(struct aura_h2_frame *f);
void aura_dump_h2_settings(struct aura_h2_settings *s);

/**/
void aura_encode_rst_stream_frame(uint8_t *dest, uint32_t frame_len, uint32_t stream_id, uint32_t err_num);
/**/
void aura_h2_encode_ping_frame(uint8_t *dest, uint32_t frame_len, bool is_ack, const uint8_t *opaque_data);
// /**/
void aura_h2_encode_goaway_frame(uint8_t *dest, uint32_t frame_len, uint32_t last_stream_id, int err_num, const struct aura_iovec *additional_data);
// /**/
void aura_h2_encode_settings_frame(uint8_t *dest, uint32_t frame_len, struct aura_h2_settings_payload *settings, size_t num_of_settings);
// /**/
void aura_h2_encode_window_update_frame(uint8_t *dest, uint32_t frame_len, uint32_t stream_id, uint32_t increment_size);
// /**/
uint8_t *aura_encode_frame_header(uint8_t *dest, size_t dest_len, uint8_t type, uint8_t flags, uint32_t stream_id);

/**
 * Parse frame payload associated with
 * type of frame
 */
int aura_h2_parse_frame_payload(struct aura_h2_in_frame *in_frame);
/**
 * Parse the fixed 9 bytes
 * of the frame header
 */
int aura_h2_parse_frame_header(struct aura_h2_in_frame *in_frame,
                               const uint8_t *src, size_t src_len,
                               size_t max_frame_size, int64_t *frame_len);

/* -------------------- */
struct aura_h2_out_frame *aura_encode_control_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf, uint8_t type,
                                                    uint8_t flags, uint32_t stream_id, const uint8_t *payload,
                                                    uint32_t payload_len, uint32_t frame_len);

/** */
struct aura_h2_out_frame *aura_produce_header_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf,
                                                    uint32_t stream_id, uint8_t type, uint8_t flags,
                                                    const uint8_t *payload, uint32_t payload_len);

struct aura_h2_out_frame *aura_encode_data_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf,
                                                 uint32_t stream_id, uint8_t flags, const uint8_t *payload,
                                                 uint32_t payload_len, uint8_t pad_len);
#endif
