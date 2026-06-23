#include "h2/frame.h"
#include "error_lib.h"
#include "slab.h"
#include "types_lib.h"
#include "utils_lib.h"

const struct aura_h2_priority aura_h2_default_priority = {
  .dependency = 0,
  .exclusive = 0,
  .weight = 16,
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
static int aura_h2_decode_data_payload(struct aura_h2_in_frame *in_frame) {
    struct aura_h2_frame *frame = &in_frame->frame;
    struct aura_h2_data_payload *payload = &in_frame->data_payload;
    uint32_t f_len = frame->len;
    uint8_t pad_len;

    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERR;

    if (aura_h2_frame_is_padded(frame->flags)) {
        if (f_len < 1)
            return A_H2_PROTOCOL_ERR;

        pad_len = a_h2_unpack_8u(frame->payload);
        /* check for valid length with padding */
        if (pad_len >= f_len - 1)
            return A_H2_PROTOCOL_ERR;

        payload->len = f_len - (1 + pad_len);
        payload->data = frame->payload + 1;
    } else {
        payload->len = f_len;
        payload->data = frame->payload;
    }

    return A_H2_ERR_NONE;
}

/**
 * Deprecated
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
static int aura_h2_decode_headers_payload(struct aura_h2_in_frame *in_frame) {
    struct aura_h2_hdrs_payload *hdr_payload = &in_frame->hdrs_payload;
    struct aura_h2_frame *frame = &in_frame->frame;
    uint32_t payload_len, f_len = frame->len;
    const uint8_t *src = frame->payload;
    uint8_t pad_len;

    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERR;

    if (aura_h2_frame_is_padded(frame->flags)) {
        if (f_len < 1)
            return A_H2_PROTOCOL_ERR;

        pad_len = a_h2_unpack_8u(src);
        /* check for valid length with padding */
        src++;
        if (pad_len >= f_len - 1)
            return A_H2_PROTOCOL_ERR;

        payload_len = f_len - (1 + pad_len);
    }

    if (aura_h2_frame_has_priority(frame->flags)) {
        if (f_len < 5)
            return A_H2_FRAME_SIZE_ERR;

        src = a_h2_decode_priority(&hdr_payload->priority, src);
        if (hdr_payload->priority.dependency == frame->stream_id)
            return A_H2_PROTOCOL_ERR;

        /* consume priority */
        f_len -= 5;
    } else
        hdr_payload->priority = aura_h2_default_priority;

    hdr_payload->src = src;
    hdr_payload->len = f_len;
    return A_H2_ERR_NONE;
}

/**
 * Deprecated
 */
static int aura_h2_decode_priority_payload(struct aura_h2_in_frame *in_frame) {
    struct aura_h2_priority *payload = &in_frame->prio_payload;
    struct aura_h2_frame *frame = &in_frame->frame;
    if (frame->stream_id == 0)
        return A_H2_PROTOCOL_ERR;

    if (frame->len != 5)
        return A_H2_FRAME_SIZE_ERR;

    a_h2_decode_priority(payload, frame->payload);
    if (payload->dependency == frame->stream_id)
        return A_H2_PROTOCOL_ERR;

    return A_H2_ERR_NONE;
}

/**
 *
 */
static int aura_h2_decode_rst_stream_payload(struct aura_h2_in_frame *in_frame) {
    if (in_frame->frame.stream_id == 0)
        return A_H2_PROTOCOL_ERR;

    if (in_frame->frame.len != 4)
        return A_H2_FRAME_SIZE_ERR;

    in_frame->rst_payload.error_code = a_h2_unpack_32u(in_frame->frame.payload);
    return A_H2_ERR_NONE;
}

/**
 *
 */
static int a_decode_settings_payload(struct aura_h2_in_frame *in_frame) {
    struct aura_h2_settings *settings = &in_frame->settings_payload;
    uint16_t settings_id;
    uint32_t val;
    const uint8_t *src;
    size_t src_len;

    src = in_frame->frame.payload;
    src_len = in_frame->frame.len;
    for (; src_len >= 6; src_len -= 6, src += 6) {
        settings_id = a_h2_unpack_16u(src);
        val = a_h2_unpack_32u(src + 2);

        switch (settings_id) {
        case A_H2_SETTINGS_HEADER_TABLE_SIZE:
            if (val < 0 || val > UINT32_MAX)
                return A_H2_ERR_NONE;
            settings->hdr_table_size = val;
            break;

        case A_H2_SETTINGS_ENABLE_PUSH:
            if (val < 0 || val > 1)
                return A_H2_PROTOCOL_ERR;
            settings->enable_push = val;
            break;

        case A_H2_SETTINGS_MAX_CONCURRENT_STREAMS:
            if (val < 0 || val > UINT32_MAX)
                return A_H2_ERR_NONE;
            settings->max_conc_streams = val;
            break;

        case A_H2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (val < 0 || val > A_H2_MAX_WINDOW_SIZE)
                return A_H2_PROTOCOL_ERR;
            settings->initial_window_size = val;
            break;

        case A_H2_SETTINGS_MAX_FRAME_SIZE:
            if (val < A_H2_MIN_FRAME_SIZE || val > A_H2_MAX_FRAME_SIZE)
                return A_H2_PROTOCOL_ERR;
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
        return A_H2_FRAME_SIZE_ERR;

    return A_H2_ERR_NONE;
}

/**
 *
 */
static int aura_h2_decode_ping_payload(struct aura_h2_in_frame *in_frame) {
    if (in_frame->frame.stream_id != 0)
        return A_H2_PROTOCOL_ERR;

    if (in_frame->frame.len != 8)
        return A_H2_FRAME_SIZE_ERR;

    memcpy(in_frame->ping_payload.data, in_frame->frame.payload, A_H2_PING_FRAME_PAYLOAD_SZ);
    return A_H2_ERR_NONE;
}

/**
 *
 */
static int aura_h2_decode_goaway_payload(struct aura_h2_in_frame *in_frame) {
    struct aura_h2_goaway_payload *payload = &in_frame->goaway_payload;
    struct aura_h2_frame *frame = &in_frame->frame;

    if (frame->stream_id != 0)
        return A_H2_PROTOCOL_ERR;

    if (frame->len < 8)
        return A_H2_FRAME_SIZE_ERR;

    payload->last_stream_id = a_h2_unpack_32u(frame->payload) & A_H2_STREAM_ID_MASK;
    payload->error_code = a_h2_unpack_32u(frame->payload + 4);
    if (frame->len > 8) {
        payload->debug_data.len = frame->len - 8;
        payload->debug_data.base = (char *)(frame->payload + 8);
    } else {
        payload->debug_data.base = NULL;
        payload->debug_data.len = 0;
    }

    return A_H2_ERR_NONE;
}

/**
 *
 */
static int aura_h2_decode_wind_update_payload(struct aura_h2_in_frame *in_frame) {
    if (in_frame->frame.len != 4)
        return A_H2_FRAME_SIZE_ERR;

    in_frame->wind_update_payload.increment = a_h2_unpack_32u(in_frame->frame.payload) & A_H2_STREAM_ID_MASK; /* reuse id mask (2^31) */
    if (in_frame->wind_update_payload.increment == 0)
        return A_H2_PROTOCOL_ERR;

    return A_H2_ERR_NONE;
}

static int aura_h2_decode_cont_frame(struct aura_h2_in_frame *in_frame) {
    if (in_frame->frame.stream_id == 0)
        return A_H2_PROTOCOL_ERR;

    in_frame->cont_payload.src = in_frame->frame.payload;
    in_frame->cont_payload.len = in_frame->frame.len;
    return A_H2_ERR_NONE;
}

int aura_h2_parse_frame_header(struct aura_h2_in_frame *in_frame, const uint8_t *src,
                               size_t in_len, size_t max_frame_size) {
    if (in_len < A_H2_FRAME_HEADER_SIZE)
        return A_H2_FRAME_INCOMPLETE;

    in_frame->frame.len = a_h2_unpack_24u(src);
    /* Frame header len is not included in max_frame size check */
    if (((int64_t)in_frame->frame.len - A_H2_FRAME_HEADER_SIZE) > (int64_t)max_frame_size)
        return A_H2_FRAME_SIZE_ERR;

    in_frame->frame.type = a_h2_unpack_8u(src + 3);
    in_frame->frame.flags = a_h2_unpack_8u(src + 4);
    in_frame->frame.stream_id = a_h2_unpack_32u(src + 5) & A_H2_STREAM_ID_MASK;
    in_frame->frame.payload = src + A_H2_FRAME_HEADER_SIZE;
    in_frame->frame_hdr_read = true;
    in_frame->expected_bytes = A_H2_FRAME_HEADER_SIZE + in_frame->frame.len;

    if (in_len >= (in_frame->frame.len + A_H2_FRAME_HEADER_SIZE)) {
        // return A_H2_FRAME_INCOMPLETE;
    }

    return A_H2_ERR_NONE;
}

/**
 *
 */
int aura_h2_parse_frame_payload(struct aura_h2_in_frame *in_frame) {

    switch (in_frame->frame.type) {
    case A_H2_FRAME_TYPE_DATA:
        return aura_h2_decode_data_payload(in_frame);
    case A_H2_FRAME_TYPE_HDRS:
        return aura_h2_decode_headers_payload(in_frame);
    case A_H2_FRAME_TYPE_PRIO:
        return aura_h2_decode_priority_payload(in_frame);
    case A_H2_FRAME_TYPE_RST:
        return aura_h2_decode_rst_stream_payload(in_frame);
    case A_H2_FRAME_TYPE_SETTINGS:
        return a_decode_settings_payload(in_frame);
    case A_H2_FRAME_TYPE_PUSH_PROMISE:
        /* Not implemented */
        break;
    case A_H2_FRAME_TYPE_PING:
        return aura_h2_decode_ping_payload(in_frame);
    case A_H2_FRAME_TYPE_GOAWAY:
        return aura_h2_decode_goaway_payload(in_frame);
    case A_H2_FRAME_TYPE_WIND_UPDATE:
        return aura_h2_decode_wind_update_payload(in_frame);
    case A_H2_FRAME_TYPE_CONT:
        return aura_h2_decode_cont_frame(in_frame);
    default:
        /* unknown flag type, ignore */
        break;
    }

    return A_H2_ERR_NONE;
}

/**
 *
 */
static void aura_encode_frame_header(uint8_t *dest, size_t frame_len, uint8_t type,
                                     uint8_t flags, uint32_t stream_id) {
    if (frame_len > A_H2_MAX_HEADER_LEN)
        app_exit(true, 0, "Invalid header length: %lu", A_H2_MAX_HEADER_LEN);

    dest = a_h2_pack_24u(dest, (uint32_t)frame_len);
    dest = a_h2_pack_8u(dest, type);
    dest = a_h2_pack_8u(dest, flags);
    dest = a_h2_pack_32u(dest, stream_id);
}

/**
 *
 */
static inline void aura_encode_rst_stream_frame(uint8_t *dest, uint32_t frame_len,
                                                uint32_t stream_id, uint32_t err_num) {
    aura_encode_frame_header(
      dest,
      frame_len,
      A_H2_FRAME_TYPE_RST,
      A_H2_FRAME_FLAG_NONE,
      stream_id);
    uint8_t *d = a_h2_pack_32u(dest + A_H2_FRAME_HEADER_SIZE, err_num);
    // memcpy(dest + A_H2_FRAME_HEADER_SIZE, &err_num, sizeof(uint32_t));
}

/**
 *
 */
static inline void aura_h2_encode_ping_frame(uint8_t *dest, uint32_t frame_len, uint8_t flags,
                                             const uint8_t *opaque_data) {
    aura_encode_frame_header(
      dest,
      frame_len,
      A_H2_FRAME_TYPE_PING,
      flags,
      0);
    memcpy(dest + A_H2_FRAME_HEADER_SIZE, opaque_data, 8);
}

/**
 *
 */
static inline void aura_h2_encode_goaway_frame(uint8_t *dest, uint32_t frame_len,
                                               struct aura_h2_goaway_payload *payload) {
    uint8_t *_dest = dest;
    aura_encode_frame_header(
      dest,
      frame_len,
      A_H2_FRAME_TYPE_GOAWAY,
      A_H2_FRAME_FLAG_NONE,
      0);
    _dest += A_H2_FRAME_HEADER_SIZE;
    _dest = a_h2_pack_32u(_dest, payload->last_stream_id);
    _dest = a_h2_pack_32u(_dest, payload->error_code);
    if (payload->debug_data.base != NULL)
        memcpy(_dest, payload->debug_data.base, payload->debug_data.len);
}

/**
 *
 */
static inline void aura_h2_encode_settings_frame(uint8_t *dest, uint32_t frame_len, struct aura_h2_settings_payload *settings, size_t num_of_settings) {
    uint8_t *d;

    aura_encode_frame_header(dest, frame_len, A_H2_FRAME_TYPE_SETTINGS, 0, 0);
    dest += A_H2_FRAME_HEADER_SIZE;

    d = dest;
    for (int i = 0; i < num_of_settings; ++i) {
        d = a_h2_pack_16u(d, settings[i].settings_id);
        d = a_h2_pack_32u(d, settings[i].value);
    }
}

/**
 *
 */
static inline void aura_h2_encode_window_update_frame(uint8_t *dest, uint32_t frame_len, uint32_t stream_id, uint32_t increment_size) {
    aura_encode_frame_header(dest, frame_len, A_H2_FRAME_TYPE_WIND_UPDATE, 0, stream_id);
    uint8_t *d = a_h2_pack_32u(dest + A_H2_FRAME_HEADER_SIZE, increment_size);
}

/* ---------- ENCODING ---------- */

uint8_t *aura_h2_encode_ctrl_frame(struct aura_sliding_buf *buf, uint8_t type, uint8_t flags,
                                   uint32_t stream_id, uint32_t frame_len, const uint8_t *payload,
                                   uint32_t payload_len) {
    uint8_t *write_ptr;
    size_t frame_size;
    bool res;

    if (!aura_sliding_buf_ensure_cap(buf, frame_len)) {
        return NULL;
    }

    write_ptr = aura_sliding_buf_write_ptr(buf);
    /* Deduct the h2 frame header len */
    frame_size = frame_len - A_H2_FRAME_HEADER_SIZE;

    switch (type) {
    case A_H2_FRAME_TYPE_RST:
        aura_encode_rst_stream_frame(write_ptr, frame_size, stream_id, *(uint32_t *)payload);
        break;

    case A_H2_FRAME_TYPE_SETTINGS:
        aura_h2_encode_settings_frame(write_ptr, frame_size, (struct aura_h2_settings_payload *)payload, payload_len);
        break;

    case A_H2_FRAME_TYPE_PING:
        aura_h2_encode_ping_frame(write_ptr, frame_size, flags, payload);
        break;

    case A_H2_FRAME_TYPE_WIND_UPDATE:
        aura_h2_encode_window_update_frame(write_ptr, frame_size, stream_id, *(uint32_t *)payload);
        break;

    case A_H2_FRAME_TYPE_GOAWAY:
        aura_h2_encode_goaway_frame(write_ptr, frame_size, (struct aura_h2_goaway_payload *)payload);
        break;
    default:
        break;
    }

    aura_sliding_buf_commit(buf, frame_len);
    return write_ptr;
}

int aura_h2_encode_hdr_frame(struct aura_sliding_buf *buf, uint32_t stream_id, uint8_t type,
                             uint8_t flags, const uint8_t *payload, uint32_t payload_len) {
    uint8_t *dest;
    bool res;

    res = aura_sliding_buf_ensure_cap(buf, payload_len + A_H2_FRAME_HEADER_SIZE);
    if (!res) {
        return A_H2_INTERNAL_ERR;
    }

    dest = aura_sliding_buf_write_ptr(buf);
    aura_encode_frame_header(dest, payload_len, type, flags, stream_id);
    aura_sliding_buf_commit(buf, A_H2_FRAME_HEADER_SIZE);

    if (payload && payload_len > 0) {
        if (aura_sliding_buf_append(buf, payload, payload_len) < 0) {
            return A_H2_INTERNAL_ERR;
        }
    }

    return A_H2_ERR_NONE;
}

int aura_h2_encode_data_frame(struct aura_sliding_buf *buf, uint32_t stream_id, uint8_t flags,
                              const uint8_t *payload, uint32_t payload_len, uint8_t pad_len) {
    uint8_t *dest;
    bool res;

    if (!aura_sliding_buf_ensure_cap(buf, payload_len + A_H2_FRAME_HEADER_SIZE))
        return A_H2_INTERNAL_ERR;

    dest = aura_sliding_buf_write_ptr(buf);
    aura_encode_frame_header(dest, payload_len, A_H2_FRAME_TYPE_DATA, flags, stream_id);
    aura_sliding_buf_commit(buf, A_H2_FRAME_HEADER_SIZE);
    if (payload && payload_len > 0) {
        if (aura_sliding_buf_append(buf, payload, payload_len) < 0)
            return A_H2_INTERNAL_ERR;
    }

    return A_H2_ERR_NONE;
}
