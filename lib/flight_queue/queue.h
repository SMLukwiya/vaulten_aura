#ifndef AURA_FLIGHT_QUEUE_LIB_H
#define AURA_FLIGHT_QUEUE_LIB_H

#include "bitmap_lib.h"
#include "mem.h"
#include "slab.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define A_FQ_SZ 64              /* Flight size */
#define A_FQ_MASK (A_FQ_SZ - 1) /* Flight queue mask */

typedef enum {
    A_FQ_SLOT_EMPTY,
    A_FQ_SLOT_FILLED,
} aura_fqe_state_t;

typedef enum {
    A_FQ_OK = 0,
    A_FQ_RELEASED,
    A_FQ_STALLED, /* Back pressure signal */
    A_FQ_ABORTED,
    A_FQ_FATAL,
} aura_fqe_err_t;

typedef uint32_t flight_key_t;

typedef bool (*aura_fq_ready_fn)(void *);
typedef int (*aura_fq_consume_fn)(void *);
/**
 * Completion function to per queue item.
 * @rv value is the value from the consume function
 */
typedef int (*aura_fq_completion_fn)(void *, int rv);

/**
 * Executes at the end of the flush queue operation.
 * Running a final function that applies to the queue
 * as a whole
 */
typedef int (*aura_fq_finalizer_fn)(void *);

struct aura_fq_entry {
    void *payload;    /* Opaque payload containing work ctx */
    flight_key_t key; /* Bit position in the blocked map */
    uint8_t state;    /* entry state */
};

#define A_FQ_ENT_SZ (sizeof(struct aura_fq_entry))

#define A_FQ_ALLOC_SIZE(staging_sz) \
    sizeof(struct aura_fq) + (A_BITS_TO_LONG(staging_sz) * sizeof(uint64_t)) + (A_FQ_ENT_SZ * staging_sz)

/* Flight queue structure */
struct aura_fq {
    struct aura_fq_entry ring[A_FQ_SZ];
    uint64_t head;
    uint64_t tail;
    void *opaque;
    uint32_t staging_sz;
    uint32_t staging_cursor;
    uint8_t *_v[]; /* Opaque variable sized tail */
};

static inline uint64_t *aura_fq_get_blked_bitmap(struct aura_fq *q) {
    if (q->staging_sz == 0)
        return NULL;

    return (uint64_t *)(q->_v);
}

static inline struct aura_fq_entry *aura_fq_get_blocked_entries(struct aura_fq *q) {
    if (q->staging_sz == 0)
        return NULL;
    return (struct aura_fq_entry *)(q->_v + (A_BITS_TO_LONG(q->staging_sz)));
}

static inline void aura_fq_dequeue(struct aura_fq *fq) {
    fq->tail--;
}

/**/
static inline bool aura_fq_is_empty(struct aura_fq *fq) {
    struct aura_fq_entry *staging_ring = aura_fq_get_blocked_entries(fq);
    uint64_t *bitmap = aura_fq_get_blked_bitmap(fq);
    uint64_t idx = aura_bitmap_find_next_bit(bitmap, 0, fq->staging_sz);
    if (idx != fq->staging_sz)
        return false;

    return fq->head == fq->tail;
}

/* Create flush queue */
struct aura_fq *aura_fq_create(struct aura_mem_ctx *mc, uint64_t staging_sz, void *opaque);

void aura_fq_destroy(struct aura_fq *fq);
void aura_fq_destroy2(struct aura_fq *fq);

int aura_fq_enqueue(struct aura_fq *fq, void *payload, flight_key_t key);

int aura_flight_queue_flush(struct aura_fq *fq, aura_fq_ready_fn ready_fn,
                            aura_fq_consume_fn consume_fn,
                            aura_fq_completion_fn comp_fn,
                            aura_fq_finalizer_fn fin_fn);

/* Print the flush queue */
void aura_fq_dump(struct aura_fq *fq);

#endif