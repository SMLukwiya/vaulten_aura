#ifndef AURA_H2_SCHEDULER
#define AURA_H2_SCHEDULER

#include "bitmap_lib.h"
#include "dense_pool/static.h"
#include "flight_queue/queue.h"
#include "h2/frame.h"
#include "heap/lib.h"
#include "list_lib.h"
#include "stream.h"

#include <sys/uio.h>

#define A_H2_SCHED_MIN_LEN 4096         /* 4KB */
#define A_H2_SCHED_BATCH_TARGET 16384UL /* 16KB */

#define A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ 16     /* Array of urgent/control frame slots */
#define A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ 32       /* Ring to hold spilled over frames */
#define A_H2_SCHED_MAX_URG_CTRL_FRAMES_PER_TICK 32 /* Array of urgent/control frame slots */
#define A_H2_CTRL_FRAME_OFF 8
#define A_H2_SCHED_MAX_FRAMES_PER_TICK 64

#define A_H2_SCHED_PRI_SLOTS_MASK (A_H2_CTRL_FRAME_OFF - 1)
#define A_H2_SCHED_SPILL_SLOTS_MASK (A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ - 1)

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
    A_H2_SCHED_RESPONSE, /* combination of header and data(if present) */
} aura_h2_sched_iov_t;

/* scheduler send iov structure */
struct aura_h2_sched_iov {
    struct aura_sliding_buf *buf;
    void *header;              /* Pointer to header */
    void *data;                /* Data to send to peer */
    struct aura_h2_core *h2_c; /* pointer to core connection */
    uint32_t header_len;
    uint32_t data_len;
    uint32_t stream_id;       /* @todo: may not need it */
    uint32_t stream_key;      /* Stream */
    uint32_t stream_desc_idx; /* Index into conn stream description table */
    uint32_t allowed_len;     /* Length that can be sent over the wire (<= data_len) */
    bool end_stream;          /* Final stream sched iov */
    uint8_t type;             /* Generic type of frame (aura_h2_sched_iov) */
    uint8_t pri_idx;          /* position of sched iov in pri array */
    uint8_t spill_idx;        /* position of sched_iov in spill array */
    uint8_t out_idx;          /* position of sched_iov in core out_frames array pool */
};

/* scheduler queue */
struct aura_h2_sched_queue {
    struct aura_h2_sched_iov urg_ctrl_frames[A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ]; /* urgent and control frames */
    A_BITMAP_CREATE(A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ, urg_ctr_pri_bitmap);      /* primary bitmap */
    struct aura_h2_sched_iov urg_ctrl_spill[A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ];    /* urgent and control spill */
    A_BITMAP_CREATE(A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ, urg_ctr_spill_bitmap);      /* spill bitmap */

    struct aura_heap stream_heap[A_PRI_EXT_NR_URGENCY_LEVELS]; /* 0 - 7 */
    /**
     * Next frame offsets to pick from.
     * Frames can be inserted out of order in both
     * the primary slots and spill slots.
     * To maintain order, required by both the underlying
     * write buffer holding the real bytes and to not delay
     * frames that came first. Offsets track where we are in
     * the whole process.
     */
    uint8_t urg_frame_off;
    uint8_t ctrl_frame_off;
    uint8_t spill_frame_off;
    uint8_t queued_cnt; /* Count of queue streams */
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

static inline bool aura_h2_sched_pri_slot_empty(struct aura_h2_sched2 *s) {
    uint64_t idx = aura_bitmap_find_next_bit(s->queues.urg_ctr_pri_bitmap, 0, A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ);
    return idx == A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ;
}

static inline bool aura_h2_sched_spill_slot_empty(struct aura_h2_sched2 *s) {
    uint64_t idx = aura_bitmap_find_next_bit(s->queues.urg_ctr_spill_bitmap, 0, A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ);
    return idx == A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ;
}

/* Both primary and spill slots are empty */
static inline bool aura_h2_sched_pri_spill_slots_empty(struct aura_h2_sched2 *s) {
    return aura_h2_sched_pri_slot_empty(s) && aura_h2_sched_spill_slot_empty(s);
}

static inline uint8_t *a_buf_pack_8u(uint8_t *dest, uint8_t val) {
    *dest++ = val;
    return dest;
}

static inline uint8_t *a_buf_pack_24u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

static inline uint8_t *a_buf_pack_32u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 24;
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
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
struct aura_h2_sched_iov *aura_h2_get_sched_iov(struct aura_h2_core *h2_c, uint8_t type);

/* Destroy scheduler send_iov structure */
void aura_h2_sched_iov_destroy(struct aura_h2_sched_iov *s_iov);

/**
 * Select the next frames to transmit based on the
 * some underlying criteria
 */
int aura_h2_schedule(struct aura_h2_core *h2_c);

/**/
int64_t aura_h2_sched_iov_create_data(struct aura_h2_sched_iov *s_iov,
                                      struct aura_sliding_buf *scratch,
                                      bool *done);

void aura_h2_sched_iov_dump(struct aura_h2_sched_iov *s_iov);

#endif