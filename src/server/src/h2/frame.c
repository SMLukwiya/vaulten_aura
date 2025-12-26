#include "h2/frame.h"
#include "error_lib.h"
#include "slab_lib.h"
#include "types_lib.h"

const struct aura_h2_priority aura_h2_default_priority = {
  .dependency = 0,
  .exclusive = 0,
  .weight = 16,
};

const struct aura_h2_settings aura_h2_default_settings = {
  .hdr_table_size = 4096,
  .enable_push = false,
  .max_conc_streams = UINT32_MAX,
  .initial_window_size = 65535,
  .max_frame_size = 16384,
  .max_hdr_list_size = 100,
};

void aura_dump_h2_frame(struct aura_h2_frame *f) {
    app_debug(true, 0, "H2 FRAME");
    app_debug(true, 0, "    Length: %lu", f->len);
    app_debug(true, 0, "    Stream id: %lu", f->stream_id);
    app_debug(true, 0, "    Frame Type: %ld", f->type);
    app_debug(true, 0, "    Flags: %ld", f->flags);
    app_debug(true, 0, "    Payload: %p", f->payload);
}

void aura_dump_h2_settings(struct aura_h2_settings *s) {
    app_debug(true, 0, "H2 SETTINGS");
    app_debug(true, 0, "    Hdr Tb Size: %lu", s->hdr_table_size);
    app_debug(true, 0, "    Enable Push: %lu", s->enable_push);
    app_debug(true, 0, "    Max Con Streams: %lu", s->max_conc_streams);
    app_debug(true, 0, "    Initial wind size: %lu", s->initial_window_size);
    app_debug(true, 0, "    Max Frame size: %lu", s->max_frame_size);
    app_debug(true, 0, "    Max Hdr list size: %lu", s->max_hdr_list_size);
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
static int aura_h2_decode_data_payload(struct aura_h2_data_payload *payload, struct aura_h2_frame *frame) {
    uint8_t pad_len;

    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERROR;

    if (a_h2_frame_is_padded(frame->flags)) {
        if (frame->len < 1)
            return A_H2_PROTOCOL_ERROR;

        pad_len = a_h2_unpack_8u(frame->payload);
        /* cater for the pad len byte that is part of the frame len */
        if (pad_len >= frame->len - 1)
            return A_H2_PROTOCOL_ERROR;

        payload->len = frame->len - (1 + pad_len);
        payload->data = frame->payload + 1;
    } else {
        payload->len = frame->len;
        payload->data = frame->payload;
    }
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static inline const uint8_t *a_h2_decode_priority(struct aura_h2_priority *prio, const uint8_t *src) {
    uint32_t p = a_h2_unpack_32u(src);
    prio->exclusive = a_h2_priority_is_exclusive(p);
    prio->dependency = p & A_H2_STREAM_ID_MASK;
    src += 4;
    prio->weight = a_h2_unpack_8u(src) + 1;
    return src++;
}

/**
 *
 */
static int aura_h2_decode_headers_payload(struct aura_h2_hdrs_payload *hdr_payload, struct aura_h2_frame *frame) {
    uint32_t payload_len, f_len = frame->len;
    const uint8_t *src = frame->payload;
    uint8_t pad_len;

    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERROR;

    if (a_h2_frame_is_padded(frame->flags)) {
        if (f_len < 1)
            return A_H2_PROTOCOL_ERROR;

        pad_len = a_h2_unpack_8u(src);
        /* cater for the pad len byte that is part of the frame */
        src++;
        f_len--; /* consume padding */
        if (pad_len >= f_len)
            return A_H2_PROTOCOL_ERROR;

        payload_len = f_len - pad_len;
    }

    if (a_h2_frame_has_priority(frame->flags)) {
        if (f_len < 5)
            return A_H2_FRAME_SIZE_ERROR;

        src = a_h2_decode_priority(&hdr_payload->priority, src);
        if (hdr_payload->priority.dependency == frame->stream_id)
            /* case of stream depending on itself, forbid that level of self-love! */
            return A_H2_PROTOCOL_ERROR;

        /* consume priority */
        f_len -= 5;
    } else
        hdr_payload->priority = aura_h2_default_priority;

    hdr_payload->headers = src;
    hdr_payload->headers_len = f_len;
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_h2_decode_priority_frame(struct aura_h2_priority *payload, struct aura_h2_frame *frame) {
    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERROR;

    if (frame->len != 5)
        return A_H2_FRAME_SIZE_ERROR;

    a_h2_decode_priority(payload, frame->payload);
    if (payload->dependency == frame->stream_id)
        /* case of stream depending on itself, forbid that level of self-love! */
        return A_H2_PROTOCOL_ERROR;

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_h2_decode_rst_stream_frame(struct aura_h2_rst_stream_payload *payload, struct aura_h2_frame *frame) {
    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERROR;

    if (frame->len != 4)
        return A_H2_FRAME_SIZE_ERROR;

    payload->error_code = a_h2_unpack_32u(frame->payload);
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_decode_settings_payload(struct aura_h2_settings *settings, struct aura_h2_frame *frame) {
    uint16_t settings_id;
    uint32_t val;
    const uint8_t *src;
    size_t src_len;

    src = frame->payload;
    src_len = frame->len;
    for (; src_len >= 6; src_len -= 6, src += 6) {
        settings_id = a_h2_unpack_16u(src);
        val = a_h2_unpack_32u(src + 2);

        switch (settings_id) {
        case A_H2_SETTINGS_HEADER_TABLE_SIZE:
            if (val < 0 || val > UINT32_MAX)
                return A_H2_ERROR_NONE;
            settings->hdr_table_size = val;
            break;

        case A_H2_SETTINGS_ENABLE_PUSH:
            if (val < 0 || val > 1)
                return A_H2_PROTOCOL_ERROR;
            settings->enable_push = val;
            break;

        case A_H2_SETTINGS_MAX_CONCURRENT_STREAMS:
            if (val < 0 || val > UINT32_MAX)
                return A_H2_ERROR_NONE;
            settings->max_conc_streams = val;
            break;

        case A_H2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (val < 0 || val > A_H2_MAX_WINDOW_SIZE)
                return A_H2_PROTOCOL_ERROR;
            settings->initial_window_size = val;
            break;

        case A_H2_SETTINGS_MAX_FRAME_SIZE:
            if (val < A_H2_MIN_FRAME_SIZE || val > A_H2_SETTINGS_MAX_FRAME_SIZE)
                return A_H2_PROTOCOL_ERROR;
            settings->max_frame_size = val;

        case A_H2_SETTINGS_MAX_HEADER_LIST_SIZE:
            if (val < 0 || val > UINT32_MAX)
                return 0;
            settings->max_hdr_list_size = val;
            break;

        default:
            /* ignore */
            break;
        }
    }

    if (src_len != 0)
        return A_H2_FRAME_SIZE_ERROR;

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_h2_decode_ping_payload(struct aura_h2_ping_payload *payload, struct aura_h2_frame *frame) {
    if (frame->stream_id != 0)
        return A_H2_PROTOCOL_ERROR;

    if (frame->len != 8)
        return A_H2_FRAME_SIZE_ERROR;

    memcpy(payload->data, frame->payload, sizeof(payload->data));
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_h2_decode_goaway_payload(struct aura_h2_goaway_payload *payload, struct aura_h2_frame *frame) {
    if (frame->stream_id != 0)
        return A_H2_PROTOCOL_ERROR;

    if (frame->len < 8)
        return A_H2_FRAME_SIZE_ERROR;

    payload->last_stream_id = a_h2_unpack_32u(frame->payload) & A_H2_STREAM_ID_MASK;
    payload->error_code = a_h2_unpack_32u(frame->payload + 4);
    if (frame->len > 8) {
        payload->debug_data.len = frame->len - 8;
        payload->debug_data.base = (char *)(frame->payload + 8);
    } else {
        payload->debug_data.base = NULL;
        payload->debug_data.len = 0;
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int aura_h2_decode_window_update_frame(struct aura_h2_window_update_payload *payload, struct aura_h2_frame *frame) {
    if (frame->len != 4)
        return A_H2_PROTOCOL_ERROR;

    payload->increment = a_h2_unpack_32u(frame->payload) & A_H2_STREAM_ID_MASK; /* reuse id mask (2^31) */
    if (payload->increment == 0)
        return A_H2_PROTOCOL_ERROR;

    return A_H2_ERROR_NONE;
}

int aura_h2_parse_frame_header(struct aura_h2_in_frame *in_frame,
                               const uint8_t *src, size_t src_len,
                               size_t max_frame_size, int64_t *frame_len) {
    *frame_len = -1;

    if (src_len < A_H2_FRAME_HEADER_SIZE)
        return A_H2_FRAME_INCOMPLETE;

    in_frame->frame.len = a_h2_unpack_24u(src);
    if (in_frame->frame.len > max_frame_size)
        return A_H2_FRAME_SIZE_ERROR;

    if (src_len < (in_frame->frame.len + A_H2_FRAME_HEADER_SIZE))
        return A_H2_FRAME_INCOMPLETE;

    /** @todo: should I verify if type is end headers and len is incorrect from here */
    in_frame->frame.type = a_h2_unpack_8u(src + 3);
    in_frame->frame.flags = a_h2_unpack_8u(src + 4);
    in_frame->frame.stream_id = a_h2_unpack_32u(src + 5) & A_H2_STREAM_ID_MASK;
    in_frame->frame.payload = src + A_H2_FRAME_HEADER_SIZE;
    *frame_len = A_H2_FRAME_HEADER_SIZE + in_frame->frame.len;
    return A_H2_ERROR_NONE;
}

/**
 *
 */
int aura_h2_parse_frame_payload(struct aura_h2_in_frame *in_frame) {

    switch (in_frame->frame.type) {
    case A_H2_FRAME_TYPE_DATA:
        return aura_h2_decode_data_payload(&in_frame->data_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_HEADERS:
        return aura_h2_decode_headers_payload(&in_frame->headers_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_PRIORITY:
        return aura_h2_decode_priority_frame(&in_frame->priority_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_RST_STREAM:
        return aura_h2_decode_rst_stream_frame(&in_frame->rst_stream_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_SETTINGS:
        return aura_decode_settings_payload(&in_frame->settings_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_PUSH_PROMISE:
        /* Not implemented */
        break;
    case A_H2_FRAME_TYPE_PING:
        return aura_h2_decode_ping_payload(&in_frame->ping_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_GOAWAY:
        return aura_h2_decode_goaway_payload(&in_frame->goaway_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_WINDOW_UPDATE:
        return aura_h2_decode_window_update_frame(&in_frame->window_update_payload, &in_frame->frame);
    case A_H2_FRAME_TYPE_CONTINUATION:
        /* continuation */
        break;
    default:
        /* unknown flag type, ignore */
        break;
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
uint8_t *aura_encode_frame_header(uint8_t *dest, size_t len, uint8_t type, uint8_t flags, uint32_t stream_id) {
    if (len > A_H2_MAX_HEADER_LEN)
        app_exit(true, 0, "Invalid header length: %lu", A_H2_MAX_HEADER_LEN);

    dest = a_h2_pack_24u(dest, (uint32_t)len);
    dest = a_h2_pack_8u(dest, type);
    dest = a_h2_pack_8u(dest, flags);
    dest = a_h2_pack_32u(dest, stream_id);

    return dest;
}

/**
 *
 */
void aura_encode_rst_stream_frame(uint8_t *dest, uint32_t frame_len, uint32_t stream_id, uint32_t err_num) {
    uint8_t *_dest = dest;
    _dest = aura_encode_frame_header(_dest, frame_len, A_H2_FRAME_TYPE_RST_STREAM, 0, stream_id);
    _dest = a_h2_pack_32u(_dest, err_num);
}

/**
 *
 */
void aura_h2_encode_ping_frame(uint8_t *dest, uint32_t frame_len, bool is_ack, const uint8_t *opaque_data) {
    uint8_t *_dest = dest;
    _dest = aura_encode_frame_header(_dest, frame_len, A_H2_FRAME_TYPE_PING, is_ack ? A_H2_FRAME_FLAG_ACK : 0, 0);
    memcpy(_dest, opaque_data, 8); /** @todo: create a wrapper to do the copying */
    _dest += 8;
}

/**
 *
 */
void aura_h2_encode_goaway_frame(uint8_t *dest, uint32_t frame_len, uint32_t last_stream_id, int err_num, const struct aura_iovec *additional_data) {
    uint8_t *_dest = dest;
    _dest = aura_encode_frame_header(_dest, frame_len, A_H2_FRAME_TYPE_GOAWAY, 0, last_stream_id);
    _dest = a_h2_pack_32u(_dest, last_stream_id);
    _dest = a_h2_pack_32u(_dest, err_num);
    if (additional_data->base != NULL)
        memcpy(_dest, additional_data->base, additional_data->len);
}

/**
 *
 */
void aura_h2_encode_settings_frame(uint8_t *dest, uint32_t frame_len, struct aura_h2_settings_payload *settings, size_t num_of_settings) {
    uint8_t *_dest;

    _dest = dest;
    _dest = aura_encode_frame_header(_dest, frame_len, A_H2_FRAME_TYPE_SETTINGS, 0, 0);
    for (int i = 0; i < num_of_settings; ++i) {
        _dest = a_h2_pack_16u(_dest, settings[i].settings_id);
        _dest = a_h2_pack_32u(_dest, settings[i].value);
    }
}

/**
 *
 */
void aura_h2_encode_window_update_frame(uint8_t *dest, uint32_t frame_len, uint32_t stream_id, uint32_t increment_size) {
    uint8_t *_dest = dest;

    _dest = aura_encode_frame_header(_dest, frame_len, A_H2_FRAME_TYPE_WINDOW_UPDATE, 0, stream_id);
    _dest = a_h2_pack_32u(_dest, increment_size);
}

/**
 *
 */
void aura_h2_encode_origin_frame() {}

/* ---------- ENCODING ---------- */
struct aura_h2_out_frame *aura_encode_control_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf,
                                                    uint8_t type, uint8_t flags, uint32_t stream_id,
                                                    const uint8_t *payload, uint32_t payload_len, uint32_t frame_len) {
    struct aura_h2_out_frame *out_frame;
    uint8_t write_ptr;
    size_t frame_size;
    bool res;

    out_frame = aura_alloc(mc, sizeof(*out_frame));
    if (!out_frame)
        return NULL;

    res = aura_sliding_buffer_ensure_capacity(buf, frame_len);
    if (!res) {
        aura_free(out_frame);
        return NULL;
    }

    out_frame->encoded.data = aura_sliding_buffer_write_pointer(buf);
    frame_size = frame_len - A_H2_FRAME_HEADER_SIZE;

    switch (type) {
    case A_H2_FRAME_TYPE_RST_STREAM:
        aura_encode_rst_stream_frame(out_frame->encoded.data, frame_size, stream_id, *(uint32_t *)payload);
        break;
    case A_H2_FRAME_TYPE_SETTINGS:
        aura_h2_encode_settings_frame(out_frame->encoded.data, frame_size, (struct aura_h2_settings_payload *)payload, payload_len);
        break;
    case A_H2_FRAME_TYPE_WINDOW_UPDATE:
        aura_h2_encode_window_update_frame(out_frame->encoded.data, frame_size, stream_id, *(uint32_t *)payload);
        break;
    default:
        break;
    }

    aura_sliding_buffer_commit_write(buf, frame_len);
    out_frame->encoded.len = frame_len;
    out_frame->buf = buf;
    out_frame->frame.type = type;
    out_frame->frame.flags = flags;
    out_frame->frame.stream_id = stream_id;
    // out_frame->bytes_sent = 0;

    return out_frame;
}

struct aura_h2_out_frame *aura_produce_header_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf,
                                                    uint32_t stream_id, uint8_t type, uint8_t flags,
                                                    const uint8_t *payload, uint32_t payload_len) {
    struct aura_h2_out_frame *out_frame;
    uint8_t *dest;
    bool res;

    out_frame = aura_alloc(mc, sizeof(*out_frame));
    if (!out_frame)
        return NULL;

    res = aura_sliding_buffer_ensure_capacity(buf, payload_len + A_H2_FRAME_HEADER_SIZE);
    if (!res) {
        aura_free(out_frame);
        return NULL;
    }

    out_frame->encoded.data = aura_sliding_buffer_write_pointer(buf);
    out_frame->encoded.len = payload_len + A_H2_FRAME_HEADER_SIZE;
    dest = out_frame->encoded.data;
    dest = aura_encode_frame_header(dest, payload_len, type, flags, stream_id);
    aura_sliding_buffer_commit_write(buf, A_H2_FRAME_HEADER_SIZE);

    if (payload && payload_len > 0) {
        aura_sliding_buffer_append(buf, payload, payload_len);
    }
    out_frame->frame.type = type;
    out_frame->frame.flags = flags;
    out_frame->frame.stream_id = stream_id;
    out_frame->buf = buf;
    // out_frame->bytes_sent = 0;

    return out_frame;
}

struct aura_h2_out_frame *aura_encode_data_frame(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf,
                                                 uint32_t stream_id, uint8_t flags, const uint8_t *payload,
                                                 uint32_t payload_len, uint8_t pad_len) {
    struct aura_h2_out_frame *out_frame;
    uint8_t write_ptr;
    bool res;

    out_frame = aura_alloc(mc, sizeof(*out_frame));
    if (!out_frame)
        return NULL;

    res = aura_sliding_buffer_ensure_capacity(buf, payload_len);
    if (!res) {
        aura_free(out_frame);
        return NULL;
    }

    if (payload && payload_len > 0) {
        out_frame->data.payload = aura_sliding_buffer_write_pointer(buf);
        memcpy(out_frame->data.payload, payload, payload_len);
    }
    out_frame->frame.type = A_H2_FRAME_TYPE_DATA;
    out_frame->frame.flags = flags;
    out_frame->frame.stream_id = stream_id;
    out_frame->buf = buf;
    // out_frame->bytes_sent = 0;
    // out_frame->header_sent = false;
    out_frame->data.payload_len = payload_len;
    out_frame->data.pad_len = pad_len;

    aura_encode_frame_header(out_frame->data.header, payload_len, A_H2_FRAME_TYPE_DATA, flags, stream_id);

    return out_frame;
}

void destroy_outbound_frame(struct aura_h2_out_frame *frame) {
    if (!frame)
        return;
}