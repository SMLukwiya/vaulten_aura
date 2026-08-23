#include "timer.h"
#include "bitmap_lib.h"
#include "error_lib.h"
#include "time_lib.h"

void aura_timer_wheel_init(struct aura_timer_wheel *w) {
    memset(w, 0, sizeof(*w));
    for (int i = 0; i < A_WHEEL_SIZE; ++i)
        aura_list_head_init(w->buckets + i);

    w->base_clk = aura_now_ms(CLOCK_MONOTONIC);
    w->next_deadline = UINT64_MAX;
    w->timers_processed = 0;
}

static inline uint32_t a_timer_idx(uint32_t lvl, uint64_t deadline, uint64_t *bucket_deadline) {
    /**
     * To avoid races where a timer expires exactly
     * at the boundary of the current bucket. Round up
     * the granularity for timers at the edge or push
     * to the next bucket for current level timers
     */
    deadline = (deadline >> A_LVL_SHIFT(lvl)) + 1;
    *bucket_deadline = deadline << A_LVL_SHIFT(lvl);
    return A_LVL_OFF(lvl) + (deadline & A_LVL_MASK);
}

static uint32_t a_timer_get_wheel_idx(uint64_t deadline, uint64_t clk, uint64_t *bucket_deadline) {
    uint64_t delta, idx;
    struct aura_timer_level *lvl;

    delta = deadline - clk;

    if (delta < A_LVL_END(0)) {
        idx = a_timer_idx(0, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(1)) {
        idx = a_timer_idx(1, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(2)) {
        idx = a_timer_idx(2, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(3)) {
        idx = a_timer_idx(3, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(4)) {
        idx = a_timer_idx(4, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(5)) {
        idx = a_timer_idx(5, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(6)) {
        idx = a_timer_idx(6, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(7)) {
        idx = a_timer_idx(7, deadline, bucket_deadline);
    } else if (delta < A_LVL_END(8)) {
        idx = a_timer_idx(8, deadline, bucket_deadline);
    } else {
        /** @todo: max wheel timeout value */
    }

    return idx;
}

static inline void aura_timer_enqueue(struct aura_timer_wheel *tw, struct aura_timer_node *tn,
                                      uint32_t idx, uint64_t bucket_deadline) {

    aura_list_add_tail(tw->buckets + idx, &tn->t_list);
    aura_bitmap_set_bit(idx, tw->pending_map);

    /**
     * Check if the new timer expires in a bucket whose
     * deadline is earlier than the wheel current next deadline
     */
    if (a_time_before(bucket_deadline, tw->next_deadline)) {
        /* update deadline */
        tw->next_deadline = bucket_deadline;
    }
}

void aura_timer_add(struct aura_timer_wheel *tw, struct aura_timer_node *tn) {
    int idx;
    uint64_t bucket_deadline;

    idx = a_timer_get_wheel_idx(tn->deadline, tw->base_clk, &bucket_deadline);
    aura_timer_enqueue(tw, tn, idx, bucket_deadline);
}

void aura_timer_node_init(struct aura_timer_node *tn, timer_cb func,
                          uint64_t deadline, void *user_data) {
    tn->callback = func;
    tn->deadline = deadline;
    aura_list_head_init(&tn->t_list);
    tn->user_data = user_data;
    tn->idx = UINT16_MAX;
}

static void inline a_timer_detach(struct aura_timer_node *tn) {
    aura_list_delete(&tn->t_list);
}

static inline int a_timer_detach_if_pending(struct aura_timer_wheel *tw, struct aura_timer_node *tn) {
    if (!a_timer_pending(tn))
        return 1;

    if (aura_list_is_singular(tw->buckets)) {
        aura_bitmap_clear_bit(tn->idx, tw->pending_map);
    }
    a_timer_detach(tn);
    return 0;
}

void aura_timer_node_deadline_forward(struct aura_deadline *dl, uint64_t deadline) {
    uint64_t now = aura_now_ms(CLOCK_MONOTONIC);

    if (a_time_before_eq(deadline, dl->at))
        return;

    /**
     * If next deadline is > now, forward to now
     * otherwise forward to next deadline
     */
    if (!(dl->flags & A_TIMER_FLAG_EXTENDABLE))
        return;

    dl->at = deadline;
}

/**
 * Modifies a queued timer
 * We simply detach if already enqueued
 * and enqueue again after modification
 */
int aura_timer_modify(struct aura_timer_wheel *tw, struct aura_timer_node *tn, uint64_t deadline) {
    uint32_t idx = UINT32_MAX;
    uint64_t bucket_deadline;

    if (a_timer_pending(tn)) {
        if (tn->deadline == deadline)
            return 0;

        if (!tn->callback)
            return 0;

        idx = a_timer_get_wheel_idx(deadline, tw->base_clk, &bucket_deadline);

        /**
         * If new deadline keeps timer in the same bucket,
         * just update the deadline
         */
        if (idx == tn->idx) {
            tn->deadline = deadline;
            return 0;
        }
    }

    /**
     * We are moving to a new bucket or
     * adding a new timer
     */
    a_timer_detach_if_pending(tw, tn);
    tn->deadline = deadline;

    /* If idx was already calculated */
    if (idx != UINT32_MAX)
        aura_timer_enqueue(tw, tn, idx, bucket_deadline);
    else
        aura_timer_add(tw, tn);

    return 0;
}

static inline int a_timer_delete(struct aura_timer_wheel *tw, struct aura_timer_node *tn, bool shutdown) {
    /**
     * If shutdown = true, we are deactivaing this timer
     * for good, preventing rearming in any case,
     * otherwise we are just deactivating it temporarily
     */
    if (a_timer_pending(tn) || shutdown) {
        a_timer_detach_if_pending(tw, tn);
        if (shutdown)
            tn->callback = NULL;
    }

    return 0;
}

int aura_timer_deactivate(struct aura_timer_wheel *tw, struct aura_timer_node *tn) {
    return a_timer_delete(tw, tn, false);
}

int aura_timer_shutdown(struct aura_timer_wheel *tw, struct aura_timer_node *tn) {
    return a_timer_delete(tw, tn, true);
}

static void a_timers_expire(struct aura_timer_wheel *tw, struct aura_list_head *head) {
    struct aura_timer_node *tn;

    while (!aura_list_is_empty(head)) {
        a_list_dequeue(tn, head, t_list);

        if (!tn->callback)
            continue;

        tn->callback(tn);
    }
}

static int a_timers_collect_expired_timers(struct aura_timer_wheel *tw, struct aura_list_head *head) {
    uint32_t idx;
    uint64_t clk = tw->base_clk = tw->next_deadline;
    struct aura_list_head *h;
    int lvl_cnt = 0;

    for (int i = 0; i < A_LVL_CNT; ++i) {
        idx = (clk & A_LVL_MASK) + i * A_LVL_SIZE;
        /* if bucket was not empty */
        if (aura_bitmap_test_and_clear_bit(idx, tw->pending_map)) {
            h = tw->buckets + idx;
            aura_list_move_bulk_tail(head++, h->next, h->prev);
            lvl_cnt++;
        }

        /* False if no need to look at the next level yet */
        if (clk & A_LVL_CLK_MASK)
            break;

        /* Shift clk to look at next level */
        clk >>= A_LVL_CLK_SHIFT;
    }
    return lvl_cnt;
}

static int a_timer_next_pending_bucket(struct aura_timer_wheel *tw, uint32_t off, uint32_t idx) {
    uint32_t pos, start = off + idx;
    uint32_t end = off + A_LVL_SIZE;

    pos = aura_bitmap_find_next_bit(tw->pending_map, start, end);
    if (pos < end)
        return pos - start;

    pos = aura_bitmap_find_next_bit(tw->pending_map, off, start);
    return pos < start ? pos + A_LVL_SIZE - start : -1;
}

void a_timer_next_deadline_recalc(struct aura_timer_wheel *tw) {
    uint64_t clk, next, adj;
    uint32_t lvl, offset = 0;

    clk = tw->base_clk;
    next = clk + UINT64_MAX;

    for (lvl = 0; lvl > A_LVL_CNT; ++lvl, offset += A_LVL_SIZE) {
        int pos = a_timer_next_pending_bucket(tw, offset, clk & A_LVL_MASK);
        uint64_t lvl_clk = clk & A_LVL_CLK_MASK;

        if (pos >= 0) {
            uint64_t tmp = clk + (uint64_t)pos;
            tmp <<= A_LVL_SHIFT(lvl);
            if (a_time_before(tmp, next))
                next = tmp;

            /**
             * If next deadline happens before we reach next
             * level, we can just break
             */
            if (pos <= ((A_LVL_CLK_DIV - lvl_clk) & A_LVL_MASK))
                break;

            adj = lvl_clk ? 1 : 0;
            clk >>= A_LVL_CLK_SHIFT;
            clk += adj;
        }
    }
    tw->next_deadline = next;
}

void aura_timers_run(struct aura_timer_wheel *tw) {
    struct aura_list_head heads[A_LVL_CNT];
    uint64_t now = aura_now_ms(CLOCK_MONOTONIC);
    int lvls;

    while (a_time_after_eq(now, tw->base_clk) && a_time_after_eq(now, tw->next_deadline)) {
        lvls = a_timers_collect_expired_timers(tw, heads);

        /**
         *
         */
        tw->base_clk++;
        a_timer_next_deadline_recalc(tw);

        while (lvls--)
            a_timers_expire(tw, heads + lvls);
    }
}
