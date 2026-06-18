#ifndef AURA_TIMER_H
#define AURA_TIMER_H

#include "bitmap_lib.h"
#include "list_lib.h"
#include <stdint.h>
#include <string.h>

/**
 * Level 0: Granularity: 1ms, Range 0ms - 1023ms (~1s)
 * Level 1: Granularity: 8ms, Range 1024ms - 9215ms (~1s - ~9s)
 * Level 2: Granularity: 32ms, Range 9216 - 41984ms (~9s - ~40s)
 */

#define A_LVL_BITS 6
#define A_LVL_CNT 9
#define A_LVL_CLK_SHIFT 3
#define A_LVL_CLK_DIV (1UL << A_LVL_CLK_SHIFT)
#define A_LVL_CLK_MASK (A_LVL_CLK_DIV - 1)

#define A_LVL_SIZE (1ULL << A_LVL_BITS)
#define A_LVL_MASK (A_LVL_SIZE - 1)
#define A_WHEEL_SIZE (A_LVL_SIZE * A_LVL_CNT)
#define A_LVL_SHIFT(n) ((n) * A_LVL_CLK_SHIFT)
#define A_LVL_GRAN(n) (1UL << A_LVL_SHIFT)
#define A_LVL_OFF(n) ((n) * A_LVL_SIZE)

/* The time end value of each level */
#define A_LVL_END(n) ((A_LVL_SIZE << ((n) * A_LVL_CLK_SHIFT)) - 1)

#define A_TIMER_FLAG_ACTIVE 0x1     /* timer is legible for firing */
#define A_TIMER_FLAG_TERMINAL 0x2   /* triggers the terminating stage of the underlying entity */
#define A_TIMER_FLAG_EXTENDABLE 0x4 /* can be pushed forward */

struct aura_timer_node;

typedef void (*timer_cb)(struct aura_timer_node *); /* Timer callback */

/* Timer wheel structure */
struct aura_timer_wheel {
    struct aura_list_head buckets[A_WHEEL_SIZE];
    A_BITMAP_CREATE(A_WHEEL_SIZE, pending_map);

    uint64_t base_clk;
    uint64_t next_deadline;
    uint64_t timers_processed;
};

/* Timer Node structure */
struct aura_timer_node {
    struct aura_list_head t_list; /* Link in timer list */
    uint64_t deadline;            /* Absolute expiry time */
    void *user_data;              /* Opaque user data */
    timer_cb callback;            /* Timer callback */
    uint16_t idx;                 /* Slot in wheel level */
};

/* Aura generic deadline structure */
struct aura_deadline {
    uint64_t at; /* Fires at */
    uint8_t flags;
};

/* Initialize timer wheel */
void aura_timer_wheel_init(struct aura_timer_wheel *w);

/* Queue timer node into wheel */
void aura_timer_add(struct aura_timer_wheel *tw, struct aura_timer_node *tn);

/**
 * Initialize timer node.
 * @tn: timer node to init
 * @func: callback to run on timer deadline
 * @deadline: deadline in ms
 * @user_data: pointer to userdata structure
 */
void aura_timer_node_init(struct aura_timer_node *tn, void (*func)(struct aura_timer_node *),
                          uint64_t deadline, void *user_data);

/**
 * Adjust timer node's deadline to new dealine
 * Can change the position of the timer node in the wheel.
 * @tn: timer node to adjust
 * @deadline: new deadline to change to
 */
int aura_timer_modify(struct aura_timer_wheel *tw, struct aura_timer_node *tn, uint64_t deadline);

/**
 * Temporarily remove the timer from the
 * timer wheel. Timer can still be rescheduled
 * later.
 */
int aura_timer_deactivate(struct aura_timer_wheel *tw, struct aura_timer_node *tn);

/**
 * Permanently remove the timer from the
 * timer wheel. Timer is can not rescheduled
 * afterwards.
 */
int aura_timer_shutdown(struct aura_timer_wheel *tw, struct aura_timer_node *tn);

/**
 * Run the timers in the timer wheel
 * and execute the callbacks attached.
 */
void aura_timers_run(struct aura_timer_wheel *tw);

/**
 * Update the deadline to a new deadline
 */
void aura_timer_node_deadline_forward(struct aura_deadline *dl, uint64_t deadline);

/**
 * Returns true if timer is currently queued.
 */
static inline bool a_timer_pending(struct aura_timer_node *tn) {
    return !aura_list_is_empty(&tn->t_list);
}

static inline void aura_timer_modify_callback(struct aura_timer_node *tn, timer_cb cb) {
    tn->callback = cb;
}

#endif