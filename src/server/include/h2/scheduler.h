#ifndef AURA_H2_SCHEDULER
#define AURA_H2_SCHEDULER

#include "connection.h"
#include "list_lib.h"
#include <sys/uio.h>

typedef enum {
    AURA_H2_SCHED_OP_NONE,
    AURA_H2_SCHED_OP_URGENT_WRITE,
    AURA_H2_SCHED_OP_CONTROL_WRITE,
    AURA_H2_SCHED_OP_HEADER_WRITE,
    AURA_H2_SCHED_OP_DATA_WRITE,
} aura_h2_scheduler_current_op_t;

/**
 * Sending iov structure
 */
struct aura_h2_send_iov {
    struct iovec iov;
    struct aura_sliding_buf *buf;
    struct aura_list_head list;
};

/** Outbound scheduler event structure */
struct aura_h2_sched_evt {
    aura_h2_scheduler_current_op_t op;
    struct aura_h2_stream *stream; /* stream is null for connection level events */

    union {
        struct {
            uint8_t *data;
            uint32_t len;
        } encoded; /* data in wire format ready for sending */
    };
    struct aura_sliding_buf *buf; /* buffer containing encoded byted */
    struct aura_list_head e_list; /* Link to queue */
    bool end_stream;              /* ENDSTREAM or not */
    bool is_urgent;
};

/**
 * Queues for output frames
 */
struct aura_h2_queues {
    /* Urgent frames (GOAWAY, RST and the likes) */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } urgent;

    /* Control frames (Settings, and the likes) */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } control;

    /* Data frames subject to control flow */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } data;

    aura_h2_scheduler_current_op_t current_op;
    size_t total_frames;
    size_t total_bytes_sent;
};

/**
 * Sender engine responsible for
 * scheduling and sending data to the peer
 */
struct aura_h2_scheduler {
    struct aura_h2_queues queues;
    struct aura_sliding_buf *write_buf;

    struct aura_h2_sched_evt *curr_event;

    uint64_t bytes_sent_this_tick;
    uint64_t last_tick_time;
    size_t max_bytes_per_tick;
};

/**
 *
 */
struct aura_h2_sched_evt *aura_sched_evt_create(struct aura_memory_ctx *mc, struct aura_h2_stream *stream,
                                                struct aura_sliding_buf *buf, aura_h2_scheduler_current_op_t op,
                                                uint8_t *encoded_data, size_t encoded_len, bool end_stream);

/**
 * Select the next frame to transmit based on the
 * some prefered criteria
 */
int aura_h2_schedule(struct aura_conn *conn, void *dest);

/** */
void aura_h2_scheduler_evt_destroy(struct aura_h2_sched_evt *);

#endif