#ifndef AURA_H2_SCHEDULER
#define AURA_H2_SCHEDULER

#include "bitmap_lib.h"
#include "dense_pool/dense_pool_static_lib.h"
#include "flight_queue.h"
#include "heap_lib.h"
#include "list_lib.h"
#include "stream.h"

#include <sys/uio.h>

#define A_H2_SCHED_MIN_LEN 4096         /* 4KB */
#define A_H2_SCHED_BATCH_TARGET 16384UL /* 16KB */

#define A_H2_SCHED_MAX_URG_CTRL_FRAMES_PER_TICK 16 /* Array of urgent/control frame slots */
#define A_H2_SCHED_SPILL_URG_CTRL_RING_SZ 32       /* Ring to hold spilled over frames */
#define A_H2_SCHED_SPILL_MASK (32 - 1)
#define A_H2_CTRL_FRAME_OFF 8
#define A_H2_SCHED_MAX_FRAMES_PER_TICK 64

typedef enum {
    A_H2_SCHED_OP_NONE,
    AURA_H2_SCHED_OP_URGENT_WRITE,
    AURA_H2_SCHED_OP_CONTROL_WRITE,
    AURA_H2_SCHED_OP_HEADER_WRITE,
    AURA_H2_SCHED_OP_DATA_WRITE,
} aura_h2_sched_curr_op_t;

typedef enum {
    A_H2_SCHED_URGENT,
    A_H2_SCHED_CONTROL,
    A_H2_SCHED_HDR,
    A_H2_SCHED_DATA,
} aura_h2_sched_iov_t;

/* scheduler iov send iov structure */
struct aura_h2_sched_iov {
    struct aura_sliding_buf *buf;
    void *data;                /* Data to send to peer */
    struct aura_h2_core *h2_c; /* pointer to core connection */
    uint32_t data_len;
    uint32_t stream_id;
    uint32_t stream_key;      /* Stream */
    uint32_t stream_desc_idx; /* Index into conn stream description table */
    uint32_t allowed_len;     /* Length that can be sent over the wire (<= data_len) */
    bool end_stream;
    uint8_t type; /* Generic type of frame (aura_h2_sched_iov_t) */
};

/* scheduler queue */
struct aura_h2_sched_queue {
    struct aura_h2_sched_iov urg_ctrl_frames[A_H2_SCHED_MAX_URG_CTRL_FRAMES_PER_TICK];
    struct aura_h2_sched_iov urg_ctrl_spill[A_H2_SCHED_SPILL_URG_CTRL_RING_SZ];
    A_BITMAP_CREATE(A_H2_SCHED_SPILL_URG_CTRL_RING_SZ, urg_ctr_spill_bitmap);

    struct aura_heap stream_heap[A_PRI_EXT_NR_URGENCY_LEVELS]; /* 0 - 7 */
    uint8_t urg_frame_cnt;                                     /* Urgent frame count in urg_ctrl_frames */
    uint8_t ctrl_frame_cnt;                                    /* Control frame count in urg_ctrl_frames */
};

/**
 * Sender engine responsible for
 * scheduling and sending data to the peer
 */
struct aura_h2_sched2 {
    struct aura_h2_sched_queue queues;
    struct aura_sliding_buf write_buf;
    size_t bytes_sent_this_tick;
    size_t last_tick_ms;
};

static inline void aura_h2_sched_accum_bytes(struct aura_h2_sched2 *s, struct aura_h2_sched_iov *s_iov) {
    s->bytes_sent_this_tick += s_iov->data_len;
}

/* Initialize H2 scheduler */
int aura_h2_sched_init(struct aura_h2_sched2 *sched, struct aura_mem_ctx *mc);

/* Destroy H2 scheduler */
void aura_h2_sched_destroy(struct aura_h2_sched2 *sched);

/* Create scheduler send_iov structure  */
struct aura_h2_sched_iov *aura_h2_sched_iov_create(struct aura_mem_ctx *mc, struct aura_sliding_buf *buf,
                                                   struct aura_h2_stream *stream, uint8_t *encoded_data,
                                                   size_t encoded_len, aura_h2_sched_iov_t type,
                                                   bool end_stream);

/** */
struct aura_h2_sched_iov *aura_h2_get_sched_iov(struct aura_h2_sched2 *sched, uint8_t type);

/* Destroy scheduler send_iov structure */
void aura_h2_sched_iov_destroy(struct aura_h2_sched_iov *s_iov);

/**
 * Select the next frames to transmit based on the
 * some underlying criteria
 */
int aura_h2_schedule(struct aura_h2_core *h2_c);

#endif