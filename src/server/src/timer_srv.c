#include "timer_srv.h"
#include "time_lib.h"

static void a_timer_level_init(struct aura_timer_level *l, uint32_t shift, uint32_t gran) {
    for (int i = 0; i < A_LVL_SIZE; ++i)
        a_list_head_init(&l->buckets[i]);

    l->granularity = gran;
    l->shift = shift;
    l->cursor = 0;
}

void aura_timer_wheel_init(struct aura_timer_wheel *tw) {
    int i;

    a_timer_level_init(&tw->l0, A_LVL0_SHIFT, 1);
    a_timer_level_init(&tw->l1, A_LVL1_SHIFT, 8);
    a_timer_level_init(&tw->l2, A_LVL2_SHIFT, 32);

    tw->next_deadline_ms = UINT64_MAX;
    tw->timers_processed = 0;
}

static inline uint64_t a_timer_slot_calc(struct aura_timer_level *lvl, uint64_t deadline, uint64_t *bucket_deadline) {
    /**
     * Round up to bucket granularity
     * This way wake ups are not chaotic
     * as would be the case with exact timings
     */
    deadline = (deadline >> lvl->shift) + 1;
    *bucket_deadline = deadline << lvl->shift;
    return deadline & A_LVL_MASK;
}

void aura_timer_insert(struct aura_timer_wheel *tw, struct aura_timer_node *tn) {
    uint64_t delta, bucket_deadline, slot;
    struct aura_timer_level *lvl;

    delta = tn->deadline_ms - aura_now_ms(CLOCK_MONOTONIC);

    if (delta < (A_LVL_SIZE << A_LVL0_SHIFT)) {
        lvl = &tw->l0;
    } else if (delta < (A_LVL_SIZE << A_LVL1_SHIFT)) {
        lvl = &tw->l1;
    } else if (delta < (A_LVL_SIZE << A_LVL2_SHIFT)) {
        lvl = &tw->l2;
    } else {
        /* maybe heap */
    }

    slot = a_timer_slot_calc(lvl, tn->deadline_ms, &bucket_deadline);
    a_list_add_tail(&lvl->buckets[slot], &tn->t_list);

    if (a_time_before(bucket_deadline, tw->next_deadline_ms))
        tw->next_deadline_ms = bucket_deadline;
}

static void inline a_timer_detach(struct aura_timer_node *tn) {
    a_list_delete(&tn->t_list);
}

static void a_timer_detach_if_pending(struct aura_timer_node *tn) {
    if (!a_timer_pending(tn))
        return;

    a_timer_detach(tn);
}

/**
 * Modifies a queued timer
 * We simply detach if already enqueued
 * and enqueue again after modification
 */
int aura_timer_modify(struct aura_timer_wheel *tw, struct aura_timer_node *tn, uint64_t deadline) {
    a_timer_detach_if_pending(tn);

    tn->deadline_ms = deadline;
    aura_timer_insert(tw, tn);
    return 0;
}

static void a_timer_next_expire_recalc(struct aura_timer_wheel *tw, uint64_t now) {
    uint64_t next_exp;
    uint32_t cursor, tick;

    next_exp = UINT64_MAX;
    cursor = (tw->l0.cursor + 1) & A_LVL_MASK;
    tick = 1;
    while (cursor != tw->l0.cursor) {
        if (!a_list_is_empty(&tw->l0.buckets[cursor])) {
            uint64_t tmp = now + (tw->l0.granularity * tick);
            tmp = (tmp >> tw->l0.shift) + 1;
            tmp <<= tw->l0.shift;

            if (a_time_before(tmp, next_exp)) {
                next_exp = tmp;
                break;
            }
        }
        tick++;
        cursor = (tw->l0.cursor + 1) & A_LVL_MASK;
    }

    /* LVL 1 */
    if (next_exp == UINT64_MAX) {
        cursor = (tw->l1.cursor + 1) & A_LVL_MASK;
        tick = 1;
        while (cursor != tw->l1.cursor) {
            if (!a_list_is_empty(&tw->l1.buckets[cursor])) {
                uint64_t tmp = now + (tw->l1.granularity * tick);
                tmp = (tmp >> tw->l1.shift) + 1;
                tmp <<= tw->l1.shift;

                if (a_time_before(tmp, next_exp)) {
                    next_exp = tmp;
                    break;
                }
            }
            tick++;
            cursor = (tw->l1.cursor + 1) & A_LVL_MASK;
        }
    }

    /* LVL 2 */
    if (next_exp == UINT64_MAX) {
        cursor = (tw->l2.cursor + 1) & A_LVL_MASK;
        tick = 1;
        while (cursor != tw->l2.cursor) {
            if (!a_list_is_empty(&tw->l2.buckets[cursor])) {
                uint64_t tmp = now + (tw->l2.granularity * tick);
                tmp = (tmp >> tw->l2.shift) + 1;
                tmp <<= tw->l2.shift;

                if (a_time_before(tmp, next_exp)) {
                    next_exp = tmp;
                    break;
                }
            }
            tick++;
            cursor = (tw->l2.cursor + 1) & A_LVL_MASK;
        }
    }

    tw->next_deadline_ms = next_exp;
}

static void a_timers_expire(struct aura_list_head *head, uint64_t now) {
    while (!a_list_is_empty(head)) {
        struct aura_timer_node *timer;

        timer = a_list_first_entry(head, struct aura_timer_node, t_list);

        if (timer->deadline_ms <= now) {
            /* Call timer callback function */
            a_timer_detach(timer);
        }
    }
}

static void a_timer_expire_level(struct aura_timer_level *lvl, uint64_t now) {
    uint32_t new_cursor = (now >> lvl->shift) & A_LVL_MASK;

    while (lvl->cursor != new_cursor) {
        struct aura_list_head *bucket;

        lvl->cursor = (lvl->cursor + 1) & A_LVL_MASK;

        bucket = &lvl->buckets[lvl->cursor];
        a_timers_expire(bucket, now);
    }
}

void aura_timers_process(struct aura_timer_wheel *tw, uint64_t now) {
    a_timer_expire_level(&tw->l0, now);
    a_timer_expire_level(&tw->l1, now);
    a_timer_expire_level(&tw->l2, now);

    a_timer_next_expire_recalc(tw, now);
}
