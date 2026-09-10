#include "queue.h"
#include "bug_lib.h"
#include <stdint.h>
#include <string.h>

struct aura_fq *aura_fq_create(struct aura_mem_ctx *mc, uint64_t staging_sz, void *opaque) {
    struct aura_fq *fq = aura_alloc(mc, A_FQ_ALLOC_SIZE(staging_sz));
    if (!fq)
        return NULL;
    memset(fq, 0, A_FQ_ALLOC_SIZE(staging_sz));
    fq->staging_sz = staging_sz;
    fq->opaque = opaque;

    return fq;
}

void aura_fq_destroy(struct aura_fq *fq) {
    if (!fq)
        return;

    memset(fq, 0, sizeof(*fq));
}

void aura_fq_destroy2(struct aura_fq *fq) {
    if (!fq)
        return;
    aura_free(fq);
}

int aura_fq_enqueue(struct aura_fq *fq, void *payload, flight_key_t key) {
    struct aura_fq_entry *fqe;

    app_debug(true, 0, "aura_fq_enqueue_A");
    if (fq->tail - fq->head == A_FQ_SZ) {
        return A_FQ_STALLED;
    }

    fqe = fq->ring + (fq->tail & A_FQ_MASK);
    fqe->key = key;
    fqe->payload = payload;
    fqe->state = A_FQ_SLOT_FILLED;
    fq->tail++;

    return 0;
}

static bool is_fqe_staged(struct aura_fq *fq, uint64_t bit_pos) {
    uint64_t *bitmap = aura_fq_get_blked_bitmap(fq);
    uint64_t bitword = A_BIT_WORD(bit_pos);
    uint64_t offset = bit_pos - (bitword * A_BITS_PER_LONG);
    return aura_bitmap_test_bit(offset, bitmap + bitword);
}

static inline int a_fq_process_curr_bitword(struct aura_fq_entry *staging_ring, uint64_t *bitmap,
                                            uint64_t active_bit, uint64_t end_pos,
                                            uint64_t word_idx, aura_fq_ready_fn ready_fn,
                                            aura_fq_consume_fn consume_fn,
                                            aura_fq_completion_fn comp_fn) {
    struct aura_fq_entry *fqe;
    uint64_t target_idx;
    int rv;

    /* Get the target index in the blocked entries array */
    target_idx = (word_idx * A_BITS_PER_LONG) + active_bit;
    fqe = &staging_ring[target_idx];

    /* Check the entry's readiness to proceed */
    if (ready_fn(fqe->payload)) {
        /* Do work */
        rv = consume_fn(fqe->payload);
        if (rv != 0)
            return rv;

        /* Run completion function if any was given */
        if (comp_fn)
            comp_fn(fqe->payload, rv);
        fqe->state = A_FQ_SLOT_EMPTY;
        fqe->payload = NULL;
        aura_bitmap_clear_bit(active_bit, bitmap + word_idx);
    }

    return 0;
}

int aura_flight_queue_flush(struct aura_fq *fq, aura_fq_ready_fn ready_fn,
                            aura_fq_consume_fn consume_fn,
                            aura_fq_completion_fn comp_fn,
                            aura_fq_finalizer_fn fin_fn) {
    A_BUG_ON_2(!ready_fn, true);
    A_BUG_ON_2(!consume_fn, true);

    struct aura_fq_entry *staging_ring = aura_fq_get_blocked_entries(fq);
    uint64_t *bitmap = aura_fq_get_blked_bitmap(fq);
    struct aura_fq_entry *fqe;
    uint64_t bitmap_word_cnt, start_word;
    uint64_t start, end;
    uint64_t offset, active_bit, target_idx;
    bool staging_cursor_set = false;
    int rv;

    if (aura_fq_is_empty(fq))
        return A_FQ_OK;

    app_debug(true, 0, ">>>> aura_flight_queue_flush");
    bitmap_word_cnt = A_BITS_TO_LONG(fq->staging_sz);
    start = fq->staging_cursor;
    end = A_BITS_PER_LONG;
    start_word = A_BIT_WORD(start);
    offset = start - (start_word * A_BITS_PER_LONG);

    /* Sweep the blocked list */
    if (bitmap && staging_ring) {
        for (int i = start_word; i < bitmap_word_cnt; ++i) {
            active_bit = aura_bitmap_find_next_bit(bitmap + i, offset, end);
            /* Fast path, Empty word */
            if (active_bit == end)
                continue;
            app_debug(true, 0, "aura_flight_queue_flush staging ring: word=%d, idx=%d", i, active_bit);

            /* Loop until we are done with this word */
            while (active_bit < end) {
                /* Get the target index in the blocked entries array */
                target_idx = (i * A_BITS_PER_LONG) + active_bit;
                fqe = &staging_ring[target_idx];

                /* Check the entry's readiness to proceed */
                if (ready_fn(fqe->payload)) {
                    /* Do work */
                    rv = consume_fn(fqe->payload);
                    switch (rv) {
                    case A_FQ_RELEASED:
                    case A_FQ_ABORTED:
                    case A_FQ_FATAL:
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        fqe->state = A_FQ_SLOT_EMPTY;
                        fqe->payload = NULL;
                        aura_bitmap_clear_bit(active_bit, bitmap + i);

                        break;

                    case A_FQ_STALLED:
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        return A_FQ_STALLED;

                    case A_FQ_OK:
                        /**
                         * Some progress was probably made,
                         * but the entry stays in the same slot
                         */
                        break;
                    }
                } else {
                    /**
                     * We set the staging cursor to the oldest
                     * staged work position, even if it's the
                     * same position as the current one
                     */
                    if (!staging_cursor_set) {
                        staging_cursor_set = true;
                        fq->staging_cursor = target_idx;
                    }
                }

                /* Move to the next possible slot */
                offset = active_bit + 1;
                active_bit = aura_bitmap_find_next_bit(bitmap + i, offset, end);
            }
            /**
             * When the current word is done processing,
             * We set the offset to 0, since we want to
             * the next word scan to start from the very
             * first bit
             */
            offset = 0;
        }

        /**
         * Loop around the bitmap and scan the
         * leading bits of the staging cursor,
         * Since our cursor moves strictly forward,
         * we scan upto the start_word since work
         * could have added to positions before the
         * original cursor position in the same word.
         * Each of the words before the starting word,
         * we scan the entire word from bit 0 till 63
         */
        offset = 0;
        end = A_BITS_PER_LONG;
        for (int i = 0; i <= start_word; ++i) {
            /**
             * When we reach the start word, the end becomes
             * the original cursor position, starting offset
             * still remains the very first bit
             * this represents a complete cycle around the
             * staging aread.
             * @todo: add illustration to make comment clearer!
             */
            if (i == start_word)
                end = start;
            active_bit = aura_bitmap_find_next_bit(bitmap + i, offset, end);
            /* Fast path, Empty word */
            if (active_bit == end)
                continue;

            app_debug(true, 0, "aura_flight_queue_flush looping around: word=%d, idx=%d", i, active_bit);

            /* Loop until we are done with this word */
            while (active_bit < end) {
                /* Get the target index in the blocked entries array */
                target_idx = (i * A_BITS_PER_LONG) + active_bit;
                fqe = &staging_ring[target_idx];

                /* Check the entry's readiness to proceed */
                if (ready_fn(fqe->payload)) {
                    /* Do work */
                    rv = consume_fn(fqe->payload);
                    switch (rv) {
                    case A_FQ_RELEASED:
                    case A_FQ_ABORTED:
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        fqe->state = A_FQ_SLOT_EMPTY;
                        fqe->payload = NULL;
                        aura_bitmap_clear_bit(active_bit, bitmap + i);
                        break;

                    case A_FQ_STALLED:
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        return A_FQ_STALLED;

                    case A_FQ_FATAL:
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        return A_FQ_FATAL;

                    case A_FQ_OK:
                        /**
                         * Some progress was probably made,
                         * but the entry stays in the same slot
                         */
                        if (comp_fn)
                            comp_fn(fqe->payload, rv);

                        break;
                    }
                } else {
                    /**
                     * We set the staging cursor to the oldest
                     * staged work position, even if it's the
                     * same position as the current one
                     */
                    if (!staging_cursor_set) {
                        staging_cursor_set = true;
                        fq->staging_cursor = target_idx;
                    }
                }

                /* Move to the next possible slot */
                offset = active_bit + 1;
                active_bit = aura_bitmap_find_next_bit(bitmap + i, offset, end);
            }
        }
    }

    /**
     * If we scan the staging area and all the entries
     * were cleared, set the staging cursor to 0
     */
    if (!staging_cursor_set)
        fq->staging_cursor = 0;

    app_debug(true, 0, "aura_flight_queue_flush process ring");
    aura_fq_dump(fq);
    /* Sweep the normal list */
    uint64_t curr = fq->head;
    uint64_t bit_pos, word_pos;
    while (curr != fq->tail) {
        fqe = fq->ring + (curr & A_FQ_MASK);
        if (fqe->state == A_FQ_SLOT_EMPTY) {
            curr++;
            continue;
        }

        if (!ready_fn(fqe->payload)) {
            bit_pos = fqe->key;
            /**
             * Check if there is already an entry in staging list
             * We do not skip over work that can not be moved to
             * staging.
             * Halt the entire system since we have experience a
             * hard block
             */
            if (is_fqe_staged(fq, bit_pos)) {
                fq->head = curr;
                return A_FQ_STALLED;
            }

            /* Add to staging list */
            staging_ring[bit_pos] = *fqe;
            word_pos = A_BIT_WORD(bit_pos);
            offset = bit_pos - (word_pos * A_BITS_PER_LONG);
            aura_bitmap_set_bit(offset, bitmap + word_pos);

            /* Mark slot as empty */
            fqe->state = A_FQ_SLOT_EMPTY;
            fqe->payload = NULL;

            curr++;
            continue;
        }

        /* Entry can proceed with work */
        rv = consume_fn(fqe->payload);
        switch (rv) {
        case A_FQ_RELEASED:
        case A_FQ_ABORTED:
            if (comp_fn)
                comp_fn(fqe->payload, rv);

            fqe->state = A_FQ_SLOT_EMPTY;
            fqe->payload = NULL;
            break;

        case A_FQ_STALLED:
            if (comp_fn)
                comp_fn(fqe->payload, rv);

            return A_FQ_STALLED;

        case A_FQ_FATAL:
            if (comp_fn)
                comp_fn(fqe->payload, rv);
            return A_FQ_FATAL;

        case A_FQ_OK:
            /**
             * Not everything was flushed,
             * move to staging area if the stream
             * does not already have an entry in the staging list.
             * If entry already exists, halt the system since we
             * have experienced a hard block
             */
            if (comp_fn)
                comp_fn(fqe->payload, rv);

            bit_pos = fqe->key;

            if (is_fqe_staged(fq, bit_pos)) {
                fq->head = curr;
                return A_FQ_STALLED;
            } else {
                /* Add to staging list */
                // staging_ring->ring[bit_pos] = *fqe;
                staging_ring[bit_pos] = *fqe;
                word_pos = A_BIT_WORD(bit_pos);
                offset = bit_pos - (word_pos * A_BITS_PER_LONG);
                aura_bitmap_set_bit(offset, bitmap + word_pos);

                /* Mark slot as empty */
                fqe->state = A_FQ_SLOT_EMPTY;
                fqe->payload = NULL;
            }

            break;
        }

        curr++;
    }

    /* Run completion function if any was given */
    bool run_fin = curr != fq->head;
    fq->head = curr;
    app_debug(true, 0, "aura_flight_queue_flush <<<< F_END comp=%p, run=%d", fin_fn, run_fin);
    if (fin_fn && run_fin)
        fin_fn(fq->opaque);

    return A_FQ_OK;
}

void aura_fq_dump(struct aura_fq *fq) {
    app_debug(true, 0, "AURA FLUSH QUEUE");
    app_debug(true, 0, "    Fq head=%d, Fq tail=%d", fq->head, fq->tail);
    app_debug(true, 0, "    Staging size=%u", fq->staging_sz);
    app_debug(true, 0, "    Staging cursor=%u", fq->staging_cursor);
    app_debug(true, 0, "    Fq empty=%d", aura_fq_is_empty(fq));
}
