#ifndef AURA_TIMER_H
#define AURA_TIMER_H

#include "list_lib.h"
#include <stdint.h>

/**
 * Level 0: Granularity: 1ms, Range 0ms - 1023ms (~1s)
 * Level 1: Granularity: 8ms, Range 1024ms - 9215ms (~1s - ~9s)
 * Level 2: Granularity: 32ms, Range 9216 - 41984ms (~9s - ~40s)
 */

#define A_LVL_BITS 10

#define A_LVL_SIZE (1ULL << A_LVL_BITS)
#define A_LVL_MASK (A_LVL_SIZE - 1)

#define A_LVL0_SHIFT 0
#define A_LVL1_SHIFT 3
#define A_LVL2_SHIFT 5

/* Timer Node structure */
struct aura_timer_node {
    struct aura_list_head t_list; /* Link in timer list */
    uint64_t deadline_ms;         /* Absolute expiry time */
    void *user_data;              /* Opaque user data */
    uint8_t level;                /* Wheel level */
    uint16_t slot;                /* Slot in wheel level */
    void (*callback)(void *);     /* Timer callback */
};

/* Timer Level structure */
struct aura_timer_level {
    struct aura_list_head buckets[A_LVL_SIZE];
    uint64_t granularity;
    uint32_t shift;
    uint32_t cursor;
};

/* Timer wheel structure */
struct aura_timer_wheel {
    struct aura_timer_level l0;
    struct aura_timer_level l1;
    struct aura_timer_level l2;

    uint64_t next_deadline_ms;
    uint64_t timers_processed;
};

/** */
static inline bool a_timer_pending(struct aura_timer_node *tn) {
    return !a_list_is_empty(&tn->t_list);
}

/** */
void aura_timer_wheel_init(struct aura_timer_wheel *tw);

#endif