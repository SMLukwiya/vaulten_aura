#ifndef AURA_H2_STREAM_H
#define AURA_H2_STREAM_H

#include "bug_lib.h"
#include "h2/frame.h"
#include "heap/lib.h"
#include "list_lib.h"
#include "mem.h"
#include "request.h"
#include "runtime/request.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>

#define TEMP_SMALL_BUF_SIZE 256

#define A_H2_STREAM_WIND_UPDATE_THRESHOLD 16384 /* 16KB */

/**
 * RFC 9218: priority extenstion
 * default urgency
 */
#define A_PRI_EXT_DEFAULT_URGENCY 3

/**
 * RFC 9218: highest urgency level
 */
#define A_PRI_EXT_URGENCY_HIGH 7

/**
 * RFC 9218: lowest urgency level
 */
#define A_PRI_EXT_URGENCY_LOW 0

/**
 * RFC 9218: number of urgency levels
 */
#define A_PRI_EXT_NR_URGENCY_LEVELS 8

#define A_H2_STREAM_MAX_VRUNTIME ((uint64_t)A_H2_MAX_FRAME_SIZE)

/* RFC 9218: Priority extension structure */
struct aura_pri_ext {
    uint8_t urgency;
    bool incremental;
};

typedef enum {
    A_H2_STREAM_FLAG_NONE = 0,
    A_H2_STREAM_FLAG_READ_HDRS = 1,
    A_H2_STREAM_FLAG_CONT = 1 << 2,
    A_H2_STREAM_FLAG_HDRS_RECD = 1 << 3,
    A_H2_STREAM_FLAG_READ_DATA = 1 << 4,
    A_H2_STREAM_FLAG_READ_TRAILERS = 1 << 5,
    A_H2_STREAM_FLAG_EXECUTE = 1 << 6,
    A_H2_STREAM_FLAG_PAUSED_FLOW_CTRL = 1 << 7,
    A_H2_STREAM_FLAG_PUSH = 1 << 8,
    A_H2_STREAM_FLAG_SEND_HDRS = 1 << 9,
    A_H2_STREAM_FLAG_HDRS_ENCODED = 1 << 10, /* Has headers already been encoded into frame(s) */
    A_H2_STREAM_FLAG_HDRS_SENT = 1 << 11,
    A_H2_STREAM_FLAG_SEND_DATA = 1 << 12,
    A_H2_STREAM_FLAG_DATA_SENT = 1 << 13,
    A_H2_STREAM_FLAG_SHUTDOWN = 1 << 14,
} aura_h2_stream_flags_t;

typedef enum {
    A_H2_STREAM_SHUTDOWN_FLAG_RST_RECD = 1,
    A_H2_STREAM_SHUTDOWN_FLAG_RST_SENT = 2,
    A_H2_STREAM_SHUTDOWN_FLAG_GRACIOUS = 3,
} aura_h2_stream_shutdown_flag_t;

typedef enum {
    A_H2_STREAM_STATE_IDLE,
    A_H2_STREAM_STATE_OPEN,
    A_H2_STREAM_STATE_RESERVED_LOCAL,
    A_H2_STREAM_STATE_RESERVED_REMOTE,
    A_H2_STREAM_STATE_RESERVED, /* used to cover both local and peer's reserved states  */
    A_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    A_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    A_H2_STREAM_STATE_CLOSING,
    A_H2_STREAM_STATE_CLOSED
} aura_h2_stream_state_t;

#define aura_h2_stream_is_even_numbered(id) (((id) & 0x1) == 0)
#define aura_h2_stream_is_odd_numbered(id) (((id) & 0x1) == 1)

typedef void (*user_data_destructor)(void *user_data);

/* H2 stream structure */
struct aura_h2_stream {
    uint32_t stream_id;
    uint32_t staging_bit_pos; /* stream bit pos in out frame staging area */
    uint32_t received_headers;
    struct aura_h2_core *h2_c; /* ptr back to h2 core stream belongs to */
    aura_h2_stream_state_t state;
    struct aura_heap_ent hp_ent;     /* Intrusive stream entry in priority heap */
    struct aura_sliding_buf sync;    /* Headers buffer */
    struct aura_list_head data_list; /* Linked sliding buffers for data frames */
    struct aura_sliding_buf data;    /* Data buffer */
    int32_t local_window_size;
    int32_t peer_window_size;
    uint32_t bytes_since_wind_update; /* Bytes consumed since last window update */
    uint32_t received_len;            /* content len received so far */
    uint32_t glob_seq;                /* conn global sequence to break ties for same priority streams */
    uint64_t vruntime;                /* Virtual runtime used priorities streams in priority heap */
    struct aura_pri_ext prio;         /* Priority extension structure */
    aura_h2_stream_flags_t flags;     /* Stream flags */
    struct aura_http_req req;         /* Stream request */
    struct aura_http_res res;         /* Stream response */
    struct aura_list_head s_list;
    void *user_data;                     /* user data attached to stream */
    user_data_destructor user_data_dtor; /* callback to free user data */
    struct timespec start_ts;
    bool queued;
};

/**
 * Stream descriptor structure
 * A small structure used by sending
 * engine to determine if stream is
 * legible to send its frames
 */
struct aura_h2_stream_desc {
    struct aura_h2_core *h2_c;
    uint32_t stream_id;
    uint32_t peer_window_sz;
    uint16_t desc_flags;
};

/**
 * Trial urgency weighting
 */
static const uint32_t A_URGENCY_WEIGHTS[] = {
  1024, /* Highest urgency: cheapest execution cost */
  512,
  256,
  128,
  64,
  32,
  16,
  8, /* Lowest Urgency: Costly execution cost */
};

static inline size_t aura_h2_stream_get_local_window_size(struct aura_h2_stream *s) {
    return s->local_window_size;
}

static inline size_t aura_h2_stream_get_peer_window_size(struct aura_h2_stream *s) {
    return s->peer_window_size;
}

static inline void aura_h2_stream_consume_window(struct aura_h2_stream *s, size_t bytes) {
    s->peer_window_size -= bytes;
    s->bytes_since_wind_update += bytes;
}

static inline bool aura_h2_stream_send_wind_update(struct aura_h2_stream *s) {
    return s->bytes_since_wind_update >= A_H2_STREAM_WIND_UPDATE_THRESHOLD;
}

static inline void aura_h2_stream_transition_state(struct aura_h2_stream *s,
                                                   aura_h2_stream_state_t state) {
    s->state = state;
}

/**
 * Return true if stream is allowed to
 * receive data frames
 */
static inline bool aura_h2_stream_can_recv_data(struct aura_h2_stream *s) {
    if (s->state == A_H2_STREAM_STATE_OPEN ||
        s->state == A_H2_STREAM_STATE_HALF_CLOSED_LOCAL)
        return true;
    return false;
}

/**
 * Check if given stream can receive headers
 * Returns true if it can, otherwise false
 */
static inline bool aura_h2_stream_can_recv_hdrs(struct aura_h2_stream *s) {
    if (s->state == A_H2_STREAM_STATE_IDLE ||
        s->state == A_H2_STREAM_STATE_OPEN ||
        s->state == A_H2_STREAM_STATE_RESERVED_REMOTE ||
        s->state == A_H2_STREAM_STATE_HALF_CLOSED_LOCAL)
        return true;

    return false;
}

static inline bool aura_h2_stream_trailing_hdrs(struct aura_h2_stream *s) {
    return s->state == A_H2_STREAM_STATE_CLOSING;
}

/* Check if the stream is currently paused on flow control */
static inline bool aura_h2_stream_is_paused(struct aura_h2_stream *s) {
    return (s->flags & A_H2_STREAM_FLAG_PAUSED_FLOW_CTRL);
}

/* Defer I/O on given stream due to flow control */
static inline void aura_h2_stream_pause(struct aura_h2_stream *s) {
    A_BUG_ON_2(aura_sliding_buf_is_empty(&s->data), true);

    s->flags |= A_H2_STREAM_FLAG_PAUSED_FLOW_CTRL;
}

/* Resume I/O on given stream */
static inline void aura_h2_stream_resume(struct aura_h2_stream *s) {
    s->flags &= ~A_H2_STREAM_FLAG_PAUSED_FLOW_CTRL;
}

/**
 * Return true if stream was can now resume I/O, otherwise false
 * @c: current window size
 * @n: updated window size
 */
static inline bool aura_h2_stream_should_resume_send(int32_t c, int32_t n) {
    return (c <= 0 && n > 0);
}

/**
 * Returns true if stream has pending data to send,
 * otherwise false
 */
static inline bool aura_h2_stream_has_pending_data(struct aura_h2_stream *s) {
    return !aura_sliding_buf_is_empty(&s->data);
}

static inline bool aura_h2_stream_is_push_stream(uint32_t stream_id) {
    return aura_h2_stream_is_even_numbered(stream_id);
}

/**
 * Attach stream staging bit pos
 */
static inline void aura_h2_stream_attach_staging_bit_pos(struct aura_h2_stream *s, uint32_t bit_pos) {
    s->staging_bit_pos = bit_pos;
}

/**
 * Intialize a new stream on the connection
 */
struct aura_h2_stream *aura_h2_stream_open(struct aura_h2_core *core, struct aura_mem_ctx *mc,
                                           uint32_t stream_id, uint8_t initial_state, uint32_t flags,
                                           uint64_t glob_seq, void *user_data, user_data_destructor dtor);

/**/
void aura_h2_stream_destroy(struct aura_h2_stream *stream, bool is_server);

/** */
bool aura_h2_stream_can_send(struct aura_h2_stream *stream, bool is_server);

/** */
void aura_h2_stream_dump(struct aura_h2_stream *stream);

/* Claim values from rt response object */
int aura_h2_stream_claim_rt_response(struct aura_h2_stream *stream, Response *resp,
                                     struct aura_mem_ctx *mc);

/* Claim values from rt response object */
int aura_h2_stream_claim_rt_request(struct aura_mem_ctx *mc, struct aura_h2_stream *stream, Request *req);

/* Stream scheduler compare function */
int aura_h2_stream_cmp_fn(struct aura_heap_ent *e1, struct aura_heap_ent *e2);

#endif