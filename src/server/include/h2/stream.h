#ifndef AURA_SRV_STREAM_H
#define AURA_SRV_STREAM_H

#include "h2/frame.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "route_srv.h"
#include <stdint.h>
#include <sys/time.h>

#define TEMP_SMALL_BUF_SIZE 256

typedef enum {
    A_H2_STREAM_FLAG_NONE = 0,
    A_H2_STREAM_FLAG_PREFACE = 1,
    A_H2_STREAM_FLAG_FIRST_SETTINGS = 1 << 1,
    A_H2_STREAM_FLAG_READ_HEADERS = 1 << 2,
    A_H2_STREAM_FLAG_HEADERS_RECEIVED = 1 << 3,
    A_H2_STREAM_FLAG_READ_DATA = 1 << 4,
    A_H2_STREAM_FLAG_CONTINUATION = 1 << 5,
    A_H2_STREAM_FLAG_PAUSED = 1 << 6,
    A_H2_STREAM_FLAG_PUSH = 1 << 7,
    A_H2_STREAM_FLAG_SEND_HEADERS = 1 << 8,
    A_H2_STREAM_FLAG_HEADERS_SENT = 1 << 9
} aura_h2_stream_flags_t;

typedef enum {
    A_H2_STREAM_STATE_IDLE,
    A_H2_STREAM_STATE_OPENING,
    A_H2_STREAM_STATE_OPENED,
    A_H2_STREAM_STATE_RESERVED_LOCAL,
    A_H2_STREAM_STATE_RESERVED_REMOTE,
    A_H2_STREAM_STATE_RESERVED, /* used to cover both server and client settings */
    A_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    A_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    A_H2_STREAM_STATE_CLOSING,
    A_H2_STREAM_STATE_CLOSED
} aura_h2_stream_state_t;

struct aura_h2_stream_outbound_queue {
    struct aura_list_head f_list;
    size_t pending_bytes;
    bool blocked_by_flow_control;
    bool blocked_by_connection;
};

/* H2 stream structure */
struct aura_h2_stream {
    uint32_t stream_id;
    struct aura_h2_conn *conn; /* connection structure this streams belongs to */
    aura_h2_stream_state_t state;
    struct aura_h2_window local_window_size;
    struct aura_h2_window peer_window_size;
    struct aura_h2_priority priority;
    uint32_t consumed_bytes; /* window accumulator */
    uint64_t content_length; /* content len of req/res */
    uint32_t received_len;   /* content len received so far */
    struct timespec start_ts;
    uint16_t status_code; /* server response status code */

    struct aura_sliding_buf sync;
    struct aura_sliding_buf data;
    struct aura_h2_stream_outbound_queue outbound_queue;

    uint8_t small_buf[TEMP_SMALL_BUF_SIZE];
    uint16_t small_buf_len;

    // bool can_proceed : 1;
    bool reset_by_peer : 1;
    bool reset_by_peer_action : 1;

    aura_h2_stream_flags_t flags;

    struct {
        uint8_t start;
        uint8_t cnt;
        uint8_t last_iov_len; /* last iov may not be fully filled up */
    } iov;

    struct aura_http_req req;
    struct aura_http_res res;
    struct aura_list_head s_list;
    bool queued;
};

static inline size_t a_h2_get_stream_local_window_size(struct aura_h2_stream *stream) {
    return stream->local_window_size.available;
}

static inline size_t a_h2_get_stream_peer_window_size(struct aura_h2_stream *stream) {
    return stream->peer_window_size.available;
}

/**
 * Open a new stream on the connection
 */
struct aura_h2_stream *aura_h2_stream_open(struct aura_h2_conn *conn, uint32_t stream_id, uint8_t starting_state, uint32_t flags);

/**/
void aura_h2_stream_reset(struct aura_h2_stream *stream);
/**/
void aura_h2_stream_close(struct aura_h2_stream *stream);
/**/
void aura_stream_resume_paused();
/**/
void aura_stream_pause();
/**/

#endif