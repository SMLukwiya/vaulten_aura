#ifndef AURA_H2_SESSION_H
#define AURA_H2_SESSION_H

#include "core.h"
#include "dense_pool/dense_pool_static_lib.h"
#include "flight_queue.h"
#include "h2/frame.h"
#include "h2/hpack.h"
#include "h2/scheduler.h"
#include "h2/sentinel.h"
#include "hashmap_lib.h"
#include "list_lib.h"
#include "protocol.h"

#include <stdint.h>

#define A_H2_CONN_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define A_H2_APLN_PROTOCOLS \
    {a_str_lit_static("h2")}, {a_str_lit_static("h2-14")}, {a_str_lit_static("h2-16")}, { NULL }

#define A_H2_DATA_PAYLOAD 16384                    /* 16KB */
#define A_H2_MAX_DEFAULT_HDR_SZ (32 * 1024)        /* 32KB */
#define A_H2_MAX_DEFAULT_DATA_SZ (4 * 1024 * 1024) /* 4MB */
#define A_H2_DEFAULT_HDR_TAB_SZ 4096
#define A_H2_OUT_FRAME_SZ 64
#define A_H2_DEFAULT_MAX_CONC_STREAMS 64
#define A_H2_DEFAULT_MAX_HDR_SZ 100
#define A_H2_CLOSED_STREAM_CNT (A_H2_DEFAULT_MAX_CONC_STREAMS * 2)

#define A_H2_CONN_WIND_UPDATE_THRESHOLD 65536 /* 64KB */

/* Connection Preface */
static const struct aura_iovec aura_h2_conn_preface = {
  .base = A_H2_CONN_PREFACE,
  .len = sizeof(A_H2_CONN_PREFACE) - 1,
};

static const struct aura_h2_settings aura_h2_default_settings = {
  .hdr_table_size = A_H2_DEFAULT_HDR_TAB_SZ,
  .enable_push = false,
  .max_conc_streams = A_H2_DEFAULT_MAX_CONC_STREAMS,
  .initial_window_size = A_H2_INITIAL_WINDOW_SIZE,
  .max_frame_size = A_H2_MIN_FRAME_SIZE, /* use min size as initial */
  .max_hdr_list_size = A_H2_DEFAULT_MAX_HDR_SZ,
};

static const struct aura_iovec aura_h2_err_string[] = {
  a_str_lit_static(NULL),
  a_str_lit_static("INVALID argument"),
  a_str_lit_static("SETTINGS expected"),
  a_str_lit_static("MAX CONCURRENT streams exceeded"),
  a_str_lit_static("Internal server error"),
  a_str_lit_static("Stream closed"),
};

/* Frame lengths */
typedef enum {
    A_H2_RST_STREAM_FRAME_LEN = 4,
    A_H2_SETTINGS_FRAME_LEN = 6,
    A_H2_PING_FRAME_LEN = 8,
    A_H2_GOAWAY_FRAME_LEN = 8,
    A_H2_WINDOW_UPDATE_FRAME_LEN = 4,
} aura_h2_frame_len;

/* Error string indexes */
typedef enum {
    A_H2_ERR_STR_IDX_NONE = 0,
    A_H2_ERR_STR_IDX_INVALID_ARG = 1,
    A_H2_ERR_STR_IDX_SETTINGS_EXPECTED = 2,
    A_H2_ERR_STR_IDX_MAX_CONC_STREAMS = 3,
    A_H2_ERR_STR_IDX_INTERNAL_ERROR = 4,
    A_H2_ERR_STR_IDX_STREAM_CLOSED = 5
} aura_h2_error_idx;

#define A_H2_REQ_PSEUDO_HDRS (A_H2_PSEUDO_HDR_METHOD | A_H2_PSEUDO_HDR_SCHEME | A_H2_PSEUDO_HDR_PATH | A_H2_PSEUDO_HDR_AUTHORITY)
#define A_H2_RES_PSEUDO_HDRS (A_H2_PSEUDO_HDR_STATUS)

/* H2 connection states */
typedef enum {
    A_H2_CONN_STATE_PREFACE,
    A_H2_CONN_STATE_PREFACE_SETTINGS,
    A_H2_CONN_STATE_FRAMES,
    A_H2_CONN_STATE_CONN, /* Special handling */
    A_H2_CONN_STATE_CLOSING,
    A_H2_CONN_STATE_CLEANUP,
} aura_h2_conn_state_t;

typedef enum {
    A_H2_CORE_FLAG_NONE = 0,
    A_H2_CORE_FLAG_CONT = 1,               /* Continuation frame expected */
    A_H2_CORE_FLAG_GOAWAY_QUEUED = 1 << 1, /* Goaway frame queued for sending */
    A_H2_CORE_FLAG_GOAWAY_SENT = 1 << 3,   /* Goaway frame sent */
    A_H2_CORE_FLAG_GOAWAY_RECD = 1 << 4,   /* Goaway frame received */
    A_H2_CORE_FLAG_CLOSING = 1 << 5        /* Core connection closing */
} aura_h2_core_flag_t;

/* Pseudo header flags */
typedef enum {
    A_H2_PSEUDO_HDR_METHOD = 1 << 0,
    A_H2_PSEUDO_HDR_SCHEME = 1 << 1,
    A_H2_PSEUDO_HDR_PATH = 1 << 2,
    A_H2_PSEUDO_HDR_AUTHORITY = 1 << 3,
    A_H2_PSEUDO_HDR_STATUS = 1 << 4,
} aura_h2_pseudo_header_flags;

/* Forward declarations */
struct aura_conn;
struct aura_h2_core;
typedef int (*aura_h2_state_handler)(struct aura_h2_core *h2_conn);

/**
 * H2 callbacks
 */
struct aura_h2_callbacks2 {
    /**
     * callback to receive data from sock
     */
    int (*receive_callback)(struct aura_h2_core *conn);
    /**
     * callback to send data to sock
     */
    int (*send_callback)(struct aura_h2_core *conn);
    /**
     *
     */
    int (*header_begin_callback)(struct aura_h2_core *conn, struct aura_h2_frame *frame, struct aura_h2_stream **stream);
    /**
     * callback when header is received
     */
    int (*header_callback)(struct aura_h2_core *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len);
    /**
     * callback when data is received
     */
    int (*receive_data_callback)(struct aura_h2_core *conn);
    /**
     * callback
     */
    int (*send_data_callback)(struct aura_h2_core *conn);
};

/* Closed stream entry structure */
struct aura_h2_closed_stream_ent {
    uint32_t stream_id;
    uint32_t shutdown_flag;
};

/* Define sched dense pool */
A_DEFINE_DENSE_POOL(h2_sched, A_H2_OUT_FRAME_SZ, struct aura_h2_sched_iov);

/**
 * Define Flight queue staging area bitmap manager
 * Number of slots = max conc streams
 */
A_DEFINE_DENSE_POOL_IDX_MAN(h2_fq_staging, A_H2_DEFAULT_MAX_CONC_STREAMS);

/* Define stream description table */
A_DEFINE_DENSE_POOL(h2_stream_desc, A_H2_DEFAULT_MAX_CONC_STREAMS, struct aura_h2_stream_desc);

/* H2 conn core structure */
struct aura_h2_core {
    struct aura_h2_in_frame in_frame;   /* State of current frame being processed */
    struct aura_rh_map stream_map;      /* streams for this connection */
    struct aura_hpack_decoder dec;      /* Hpack decoder */
    struct aura_hpack_encoder enc;      /* Hpack Encoder */
    struct aura_h2_sched2 scheduler;    /* H2 scheduler */
    struct aura_intern_tab *intern_tab; /* Intern string table */

    int32_t local_window_size;              /* Local window size */
    int32_t peer_window_size;               /* Remote peer window size */
    uint32_t bytes_since_wind_update;       /* Bytes consumed since last window update */
    struct aura_h2_settings peer_settings;  /* connection peer's settings */
    struct aura_h2_settings local_settings; /* our local settings */
    struct aura_h2_sentinel sen;            /* Sentinel to handle conn behaviour */

    uint32_t stream_glob_seq;         /* Incrementing sequence of opened streams */
    uint32_t nr_peer_unack_settings;  /* settings we have sent and not received any ACK for! */
    uint32_t nr_local_unack_settings; /* settings we have received and not yet sent any ACK for! */
    uint64_t nr_closed_streams;       /* Number of closed streams still in stream list */
    uint64_t nr_idle_streams;         /* Number of idle streams still in stream list */
    uint64_t nr_out_streams;          /* outbound streams */
    uint64_t nr_in_streams;           /* inbound streams */
    uint32_t next_stream_id;          /* Max stream id from which we can the next valid stream_id (< 1 << 31) */
    uint32_t max_sent_stream_id;      /* Max stream id initiated from our side, client or server */
    uint32_t max_received_stream_id;  /* Max stream id received from peer */
    uint32_t local_goaway_stream_id;  /* Last stream id we used in a GOAWAY, doubles as last processed stream id */
    uint32_t peer_goaway_stream_id;   /* Last stream id received from a peer's GOAWAY */
    aura_h2_core_flag_t flags;        /* H2 core flags */
    struct {
        struct aura_h2_closed_stream_ent entries[A_H2_CLOSED_STREAM_CNT]; /* Max conc len of recently closed streams */
        uint8_t next;
    } closed_stream_rb; /* Closed stream ring buffer */

    struct aura_h2_stream_desc_dense_pool stream_desc_pool;

    struct aura_h2_sched_dense_pool out_frame_pool; /* Slots for sending frames to peer */
    struct aura_h2_fq_staging_dense_pool_idx_man staging_bitmap;

    struct aura_fq fq; /* Flight queue */
};

static inline aura_error_t aura_h2_get_app_error(int err) {
    switch (err) {
    case A_H2_PROTOCOL_ERR:
    case A_H2_FRAME_SIZE_ERR:
    case A_H2_COMPRESSION_ERR:
    case A_H2_FLOW_CONTROL_ERR:
    case A_H2_SETTINGS_TIMEOUT_ERR:
        return A_ERR_FATAL;

    case A_H2_FRAME_INCOMPLETE:
    case A_H2_IN_PROGRESS_ERR:
        return A_ERR_AGAIN;

    case A_H2_ERR_NONE:
        return A_ERR_NONE;

    default:
        return A_ERR_NONE;
    }
}

static inline aura_h2_frame_error_t aura_h2_translate_hpack_error(int rv) {
    switch (rv) {
    case A_HPACK_COMPRESSION_ERR:
        return A_H2_COMPRESSION_ERR;

    case A_HPACK_INTERNAL_ERR:
        return A_H2_INTERNAL_ERR;

    default:
        return A_H2_ERR_NONE;
    }
}

static inline uint32_t aura_calc_frame_len(uint8_t frame_type, uint32_t cnt, uint32_t additional_len) {
    uint32_t frame_len;

    switch (frame_type) {
    case A_H2_FRAME_TYPE_RST:
        frame_len = A_H2_RST_STREAM_FRAME_LEN + A_H2_FRAME_HEADER_SIZE;
        break;

    case A_H2_FRAME_TYPE_SETTINGS:
        frame_len = A_H2_SETTINGS_FRAME_LEN * cnt;
        frame_len += A_H2_FRAME_HEADER_SIZE;
        break;

    case A_H2_FRAME_TYPE_PING:
        frame_len = A_H2_PING_FRAME_LEN + A_H2_FRAME_HEADER_SIZE;
        break;

    case A_H2_FRAME_TYPE_GOAWAY:
        frame_len = A_H2_GOAWAY_FRAME_LEN + additional_len;
        frame_len += A_H2_FRAME_HEADER_SIZE;
        break;

    case A_H2_FRAME_TYPE_WIND_UPDATE:
        frame_len = A_H2_WINDOW_UPDATE_FRAME_LEN + A_H2_FRAME_HEADER_SIZE;
        break;

    default:
        app_debug(true, 0, "aura_calc_frame_len: Unknown frame type: %d", frame_type);
        frame_len = 0;
    }

    return frame_len;
}

/**
 * Find stream attached to connection stream hashmap
 */
static inline struct aura_h2_stream *aura_h2_conn_find_stream(struct aura_h2_core *h2_c, uint32_t stream_id) {
    struct aura_rh_map_key key;
    aura_rh_map_key_init(&key, stream_id, sizeof(uint64_t), A_RH_KEY_U64);
    return (struct aura_h2_stream *)aura_rh_map_get(&h2_c->stream_map, &key);
}

/**
 * Detach a stream from the connection stream hashmap
 */
static inline void aura_h2_conn_detach_stream(struct aura_h2_core *h2_conn, uint32_t stream_id) {
    struct aura_rh_map_key key;

    aura_rh_map_key_init(&key, (uint64_t)stream_id, sizeof(uint64_t), A_RH_KEY_U64);
    aura_rh_map_del(&h2_conn->stream_map, &key, NULL);
}

/**
 * Insert stream id into recently closed buffer
 */
static inline void aura_h2_conn_closed_stream_rb_add(struct aura_h2_core *h2_c, uint32_t stream_id,
                                                     aura_h2_stream_shutdown_flag_t flag) {
    h2_c->closed_stream_rb.entries[h2_c->closed_stream_rb.next].stream_id = stream_id;
    h2_c->closed_stream_rb.entries[h2_c->closed_stream_rb.next].shutdown_flag = flag;
    h2_c->closed_stream_rb.next = (h2_c->closed_stream_rb.next + 1) & 127;
}

/**
 * Search the recently closed streams for this stream id
 */
static inline struct aura_h2_closed_stream_ent *aura_h2_conn_closed_stream_rb_get(struct aura_h2_core *h2_c,
                                                                                  uint32_t stream_id) {
    for (int i = 0; i < 128; ++i) {
        if (h2_c->closed_stream_rb.entries[i].stream_id != 0 &&
            h2_c->closed_stream_rb.entries[i].stream_id == stream_id)
            return &h2_c->closed_stream_rb.entries[i];
    }
    return NULL;
}

/**
 * Check if number of active outbound streams is
 * larger than peers max_concurrent_streams
 */
static inline bool
aura_h2_conn_max_conc_out_streams_reached(struct aura_h2_core *h2_c) {
    return h2_c->nr_out_streams >= h2_c->peer_settings.max_conc_streams;
}

/**
 * Check if number of active inbpund streams is
 * larger than peers max_concurrent_streams
 */
static inline bool aura_h2_conn_max_conc_in_streams_reached(struct aura_h2_core *h2_c) {
    return h2_c->nr_in_streams >= h2_c->local_settings.max_conc_streams;
}

/* Get local window size */
static inline size_t aura_h2_conn_get_local_window_sz(struct aura_h2_core *h2_c) {
    return h2_c->local_window_size;
}

/* Get remote peer window size */
static inline size_t aura_h2_conn_get_peer_window_sz(struct aura_h2_core *h2_c) {
    return h2_c->peer_window_size;
}

/**
 * Check if new streams are allowed on
 * core structure
 */
static inline bool aura_h2_conn_new_streams_allowed(struct aura_h2_core *h2_c) {
    if (h2_c->flags & (A_H2_CORE_FLAG_GOAWAY_RECD | A_H2_CORE_FLAG_GOAWAY_SENT))
        return false;

    if (h2_c->next_stream_id > A_H2_STREAM_ID_MASK)
        return false;

    return true;
}

/* Returns number of active streams */
static inline uint64_t aura_h2_conn_active_streams(struct aura_h2_core *h2_c) {
    // return (h2_c->nr_streams) - (h2_c->nr_idle_streams + h2_c->nr_closed_streams);
    return aura_rh_map_get_cnt(&h2_c->stream_map);
}

/* Returns true if this is stream id was created by us */
static inline bool aura_h2_conn_stream_is_local(uint32_t stream_id, bool is_server) {
    if (likely(stream_id == 0))
        return false;

    if (is_server)
        return aura_h2_stream_is_even_numbered(stream_id);
    else
        return aura_h2_stream_is_odd_numbered(stream_id);
}

/* Return true if this a new stream id from peer */
static inline bool aura_h2_conn_peer_stream_id_new(struct aura_h2_core *h2_c,
                                                   uint32_t stream_id, bool is_server) {
    if (!aura_h2_conn_stream_is_local(stream_id, is_server))
        return false;

    return stream_id > h2_c->max_received_stream_id;
}

/* Update connection window */
static inline void aura_h2_conn_consume_window(struct aura_h2_core *h2_c, size_t bytes) {
    h2_c->peer_window_size -= bytes;
    h2_c->bytes_since_wind_update += bytes;
}

static inline bool aura_h2_conn_should_send_wind_update(struct aura_h2_core *h2_c) {
    return h2_c->bytes_since_wind_update >= A_H2_CONN_WIND_UPDATE_THRESHOLD;
}

static inline bool aura_h2_conn_stream_state_violation(struct aura_h2_core *h2_c, uint32_t stream_id, bool is_server) {
    if (aura_h2_conn_stream_is_local(stream_id, is_server)) {
        if (stream_id > h2_c->max_sent_stream_id)
            return true;
        return false;
    }

    if (aura_h2_conn_peer_stream_id_new(h2_c, stream_id, is_server))
        return true;

    return false;
}

/**
 * Test if the connection has initiated
 * closing state
 */
static inline bool aura_h2_conn_is_closing(struct aura_h2_core *h2_c) {
    return (h2_c->flags & A_H2_CORE_FLAG_CLOSING);
}

/**
 * Get the max flow control size for data action
 * taking into account stream and connection window sizes
 */
static inline size_t aura_h2_conn_get_flow_control_size(struct aura_h2_core *h2_c,
                                                        struct aura_h2_stream *stream) {
    ssize_t size;

    size = a_min(h2_c->peer_window_size, a_min(stream->peer_window_size, A_H2_DATA_PAYLOAD));
    return a_max(size, 0);
}

/* Transition h2 state */
static inline void aura_h2_conn_transition_state(aura_h2_conn_state_t *old_state, aura_h2_conn_state_t new_state) {
    if (*old_state != new_state)
        *old_state = new_state;
}

/* Transition h2 state handler */
static inline void aura_h2_conn_transition_state_handler(aura_h2_state_handler *old_handler,
                                                         aura_h2_state_handler new_handler) {
    if (old_handler == NULL || (old_handler && *old_handler != new_handler))
        *old_handler = new_handler;
}

static inline uint32_t aura_h2_stream_desc_can_proceed(struct aura_h2_stream_desc *sd, uint32_t stream_id) {
    /* Check if stream closed */
    if (sd->stream_id != stream_id)
        return 0;

    if (sd->desc_flags & A_H2_STREAM_FLAG_PAUSED_FLOW_CTRL | A_H2_STREAM_FLAG_SHUTDOWN)
        return 0;

    struct aura_h2_core *h2_c = sd->h2_c;
    size_t len = a_min(h2_c->peer_window_size, sd->peer_window_sz);
    /* Could store len in sd so I don't have to calculate again in consume_fn */
    return len;
}

/**
 * Get next sequence number for new
 * stream in the connection.
 */
static inline uint32_t aura_h2_conn_get_next_global_seq(struct aura_h2_core *h2_c) {
    return h2_c->stream_glob_seq++;
}

/**
 * Prepare goaway frame and enqueue it for sending
 * on the wire
 */
int aura_h2_conn_enqueue_goaway(struct aura_h2_core *h2_conn, uint32_t last_stream_id,
                                int err_code, const struct aura_iovec *reason);

/**
 * Create and enqueue RST frame for given stream
 */
int aura_h2_conn_enqueue_rst_frame(struct aura_h2_core *h2_c, uint32_t stream_id, int err);

/**
 * Initialize h2 internal shared core structure
 */
int aura_h2_core_init(struct aura_h2_core *core, struct aura_mem_ctx *mc, bool is_server);

/**
 * Open a new stream on the connection
 */
struct aura_h2_stream *aura_h2_conn_stream_open(struct aura_h2_core *core, struct aura_mem_ctx *mc,
                                                uint32_t stream_id, aura_h2_stream_state_t init_state,
                                                uint8_t flags, void *user_data, user_data_destructor dtor,
                                                bool is_server);

/* Send stream reset frame with specifies error */
int aura_h2_conn_send_stream_error(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                   int err_num, bool is_server);

/**
 * Handle settings frame
 */
int aura_h2_conn_process_settings(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                  bool is_server);

int aura_process_priority(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame);

/**
 * Handle incoming PING frame
 */
int aura_h2_conn_process_ping(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame);

/* Process goaway frame */
int aura_h2_conn_process_goaway(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                bool is_server);

/* Process rst stream frame */
int aura_h2_conn_process_rst_stream(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                    bool is_server);

/* Process window  update frame */
int aura_h2_conn_process_wind_update(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                     bool is_server);

/* Process continuation frame */
int aura_h2_conn_process_cont(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                              bool is_server);

int aura_h2_conn_after_frame_sent(struct aura_h2_core *h2_c, uint32_t stream_id,
                                  int type, size_t nbytes, bool end_stream);

/* Release structures held by core */
void aura_h2_core_destroy(struct aura_h2_core *h2_c, bool is_server);

/**
 *
 */
struct aura_h2_stream_desc *aura_h2_conn_stream_desc_get(struct aura_h2_core *h2_c, uint32_t idx);

/*==================*/
int aura_h2_conn_enqueue_wind_update(struct aura_h2_core *h2_c, uint32_t stream_id,
                                     size_t wind_sz);

#endif