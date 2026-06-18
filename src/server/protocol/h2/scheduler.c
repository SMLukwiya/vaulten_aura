#include "h2/scheduler.h"
#include "h2/server.h"
#include "h2/stream.h"
#include "list_lib.h"
#include "time_lib.h"

/**
 * @todo: add max buffer size per stream out buffer,
 * and signal back pressure when it fills up
 */

#define A_H2_SCHED_MIN_CTRL_DELTA_MS 10UL

int aura_h2_sched_init(struct aura_h2_sched2 *sched, struct aura_mem_ctx *mc) {
    int i;

    memset(sched, 0, sizeof(*sched));
    /* Allocate enough for client connection preface and settings */
    if (aura_sliding_buf_init(&sched->write_buf, mc, 0, A_SLIDING_BUF_FL_NONE) < 0)
        return -1;

    for (i = 0; i < A_PRI_EXT_NR_URGENCY_LEVELS; ++i)
        if (aura_heap_init(&sched->queues.stream_heap[i], mc, 0, aura_h2_stream_cmp_fn, A_HP_TYPE_MIN_HEAP) < 0)
            break;

    /* error initializing stream heap */
    if (i < A_PRI_EXT_NR_URGENCY_LEVELS) {
        while (i-- > -1)
            aura_heap_destroy(&sched->queues.stream_heap[i]);
    }

    // aura_list_head_init(&sched->queues.urgent.head);
    // aura_list_head_init(&sched->queues.control.head);

    return 0;
}

void aura_h2_sched_destroy(struct aura_h2_sched2 *sched) {
    struct aura_h2_sched_iov *s_iov;

    if (!sched)
        return;

    aura_sliding_buf_destroy(&sched->write_buf);

    for (int i = 0; i < A_PRI_EXT_NR_URGENCY_LEVELS; ++i) {
        aura_heap_destroy(&sched->queues.stream_heap[i]);
    }
}

struct aura_h2_sched_iov *aura_h2_get_sched_iov(struct aura_h2_sched2 *sched, uint8_t type) {
    struct aura_h2_sched_iov *s_iov;
    uint8_t idx, urg_f_cnt, ctrl_f_cnt;

    ctrl_f_cnt = sched->queues.ctrl_frame_cnt;
    urg_f_cnt = sched->queues.urg_frame_cnt;
    s_iov = NULL;

    /**
     * Get slot in 16 entry discriminate fast path
     */
    if (type == A_H2_SCHED_URGENT) {
        if (urg_f_cnt < A_H2_CTRL_FRAME_OFF) {
            idx = sched->queues.urg_frame_cnt++;
            s_iov = &sched->queues.urg_ctrl_frames[idx];
        }
    } else {
        if (ctrl_f_cnt < A_H2_CTRL_FRAME_OFF) {
            idx = (A_H2_CTRL_FRAME_OFF + sched->queues.ctrl_frame_cnt++);
            s_iov = &sched->queues.urg_ctrl_frames[idx];
        }
    }

    /* Get slot in 32 entry indiscriminate backup */
    if (!s_iov) {
        idx = aura_bitmap_find_next_empty_bit(
          sched->queues.urg_ctr_spill_bitmap,
          0,
          A_H2_SCHED_SPILL_URG_CTRL_RING_SZ);
        if (idx != A_H2_SCHED_SPILL_URG_CTRL_RING_SZ)
            s_iov = &sched->queues.urg_ctrl_spill[idx];
    }

    return s_iov;
}

void aura_h2_sched_iov_destroy(struct aura_h2_sched_iov *s_iov) {
    if (!s_iov)
        return;

    aura_sliding_buf_consume(s_iov->buf, s_iov->data_len);
    /* delete buffer ref */
    aura_sliding_buf_destroy(s_iov->buf);
    /* Detach from whatever list */
    // aura_list_delete(&s_iov->iov_list);

    // aura_free(s_iov);
}

static inline int a_h2_sched_pick_stream2(struct aura_h2_core *h2_c, struct aura_h2_sched_iov *s_iov) {
    struct aura_h2_sched2 *sched;
    struct aura_h2_stream *s;
    struct aura_heap_ent *e;
    struct aura_heap *hp;
    uint8_t *src_in, flags;
    size_t in_len, offset, chunk, data_sz;
    bool is_first_frame, has_body, end_stream;
    aura_h2_frame_t f_type;
    size_t stream_cnt;
    int rv;

    sched = &h2_c->scheduler;
    /* Pick from most urgent level first */
    for (int i = 0; i < A_PRI_EXT_DEFAULT_URGENCY; ++i) {
        hp = &sched->queues.stream_heap[i];

        if (aura_heap_is_empty(hp))
            continue;

        stream_cnt = 0;

        while (stream_cnt < hp->size) {
            e = aura_heap_peek(hp);
            s = aura_container_of(e, struct aura_h2_stream, hp_ent);

            if (!aura_h2_stream_can_send(s, true)) {
                stream_cnt++;
                continue;
            }

            /**
             * Check if headers were encoded in a previous run
             */
            if (!(s->flags & A_H2_STREAM_FLAG_HDRS_SENT)) {
                /* Encode headers fully into frames */
                if (!(s->flags & A_H2_STREAM_FLAG_HDRS_ENCODED)) {
                    rv = aura_hpack_encoder_adjust_tab_size(&h2_c->enc);
                    if (rv != A_HPACK_OK)
                        return aura_h2_translate_hpack_error(rv);

                    aura_hpack_encode_status(&h2_c->enc, s->res.status_code);

                    rv = aura_hpack_encode_headers(
                      &h2_c->enc,
                      h2_c->intern_tab,
                      s->res.headers.entries,
                      s->res.headers.cnt);
                    if (rv != A_HPACK_OK)
                        return aura_h2_translate_hpack_error(rv);

                    has_body = false;
                    if (s->res.content_length != SIZE_MAX && s->res.content_length != 0 && s->res.body) {
                        has_body = true;

                        rv = aura_hpack_encode_content_length(&h2_c->enc, s->res.content_length);
                        if (rv != A_HPACK_OK)
                            return aura_h2_translate_hpack_error(rv);
                    }

                    src_in = aura_sliding_buf_read_ptr(&h2_c->enc.enc_buf);
                    in_len = aura_sliding_buf_read_len(&h2_c->enc.enc_buf);

                    offset = 0;
                    rv = 0;
                    is_first_frame = true;
                    end_stream = !has_body;
                    while (in_len > 0) {
                        chunk = a_min(in_len, h2_c->peer_settings.max_frame_size);
                        f_type = is_first_frame ? A_H2_FRAME_TYPE_HDRS : A_H2_FRAME_TYPE_CONT;
                        flags = in_len == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
                        /* defer sending END_STREAM until final headers block */
                        flags |= (end_stream && (flags & A_H2_FRAME_FLAG_END_HEADERS)) ? A_H2_FRAME_FLAG_END_STREAM : 0;
                        rv = aura_h2_encode_hdr_frame(
                          &s->sync,
                          s->stream_id,
                          f_type,
                          flags,
                          src_in + offset,
                          chunk);
                        if (rv < 0)
                            break;

                        is_first_frame = false;
                        offset += chunk;
                        in_len -= chunk;
                    }

                    if (rv != A_H2_ERR_NONE) {
                        aura_sliding_buf_reset(&h2_c->enc.enc_buf);
                        return rv;
                    }

                    s->flags |= A_H2_STREAM_FLAG_HDRS_ENCODED;
                }

                aura_sliding_buf_reset(&h2_c->enc.enc_buf);
                /**
                 * Because stream out buffer was empty
                 * The encoded headers are the only bytes
                 * in the out buffer, so we can safely reference
                 * its start and length as the frame data and length
                 */
                src_in = aura_sliding_buf_read_ptr(&s->sync);
                in_len = aura_sliding_buf_read_len(&s->sync);

                s_iov->buf = &s->sync;
                s_iov->data = src_in;
                s_iov->data_len = in_len;
                s_iov->type = A_H2_SCHED_HDR;
                s_iov->stream_id = s->stream_id;
                s_iov->end_stream = end_stream;

                aura_h2_sched_accum_bytes(sched, s_iov);

                /* headers only stream  */
                if (!has_body) {
                    /* Delete if we are done with stream */
                    aura_heap_del(hp, e);
                    /**
                     * No need to update stream flag
                     * since stream will no longer be scheduled
                     */
                }

                aura_h2_conn_after_frame_sent(h2_c, s->stream_id, A_H2_FRAME_TYPE_HDRS, in_len, end_stream);
                s->flags |= A_H2_STREAM_FLAG_HDRS_SENT;

                return A_H2_ERR_NONE;
            }

            /**
             * At this point, if this was the first run,
             * we have encoded headers and have data to bundle up,
             * if not the first run, this is data only run
             */
            const char *start;
            uint8_t *data_out;
            size_t target_budget;

            /**
             * We have the end of data in a data only run
             * Send 0 length data frame
             */
            if (s->res.content_length == 0) {
                s_iov->buf = &s->sync;
                s_iov->data = NULL;
                s_iov->data_len = 0;
                s_iov->type = A_H2_SCHED_DATA;
                s_iov->stream_id = s->stream_id;
                s_iov->stream_key = s->staging_bit_pos;
                s_iov->end_stream = true;

                aura_h2_conn_after_frame_sent(h2_c, s->stream_id, A_H2_FRAME_TYPE_DATA, 0, true);
                return A_H2_ERR_NONE;
            }

            target_budget = A_H2_SCHED_BATCH_TARGET - sched->bytes_sent_this_tick;
            /**
             * If budget left is too small.
             * Allow some soft overflow
             */
            data_sz = a_max(target_budget, A_H2_SCHED_MIN_LEN);
            data_sz = a_min(data_sz, s->res.content_length);

            start = s->res.body;
            flags = 0;
            end_stream = s->res.content_length == data_sz;

            /**
             * If incremental stream, encode one possibly
             * max frame chunk and return
             */
            if (s->prio.incremental) {
                chunk = a_min(data_sz, h2_c->peer_settings.max_frame_size);
                end_stream = data_sz == chunk && end_stream;
                flags |= end_stream ? A_H2_FRAME_FLAG_END_STREAM : 0;
                /* get data frame position in out buffer */
                data_out = aura_sliding_buf_write_ptr(&s->sync);
                if (aura_sliding_buf_append(&s->sync, start, chunk) < 0) {
                    return A_H2_INTERNAL_ERR;
                }

                s_iov->buf = &s->sync;
                s_iov->data = data_out;
                s_iov->data_len = chunk;
                s_iov->type = A_H2_SCHED_DATA;
                s_iov->stream_id = s->stream_id;
                s_iov->stream_key = s->staging_bit_pos;
                s_iov->end_stream = end_stream;
                aura_h2_sched_accum_bytes(sched, s_iov);

                if (end_stream) {
                    aura_heap_pop(hp);
                } else {
                    /* update stream vruntime and reschedule if needed */
                    uint32_t weight = A_URGENCY_WEIGHTS[s->prio.urgency];
                    s->vruntime += (uint64_t)(chunk * 1024) / weight;

                    /* reposition in heap */
                    /** @todo: reschedule */
                    // aura_h2_stream_reschedule(sched, s);
                    s->res.body += chunk;
                    s->res.content_length -= chunk;
                }

                // aura_h2_conn_after_frame_sent(h2_c, s, A_H2_FRAME_TYPE_DATA, chunk, end_stream);
            } else {
                /**
                 * Non incremental, encoded as much as
                 * we can
                 */
                offset = 0;
                /* get data frame position in out buffer */
                data_out = aura_sliding_buf_write_ptr(&s->sync);
                if (aura_sliding_buf_append(&s->sync, start, data_sz) < 0)
                    return A_H2_INTERNAL_ERR;

                s->res.content_length -= data_sz;
                s->res.body += data_sz;

                s_iov->buf = &s->sync;
                s_iov->data = data_out;
                s_iov->data_len = offset;
                s_iov->type = A_H2_SCHED_DATA;
                s_iov->stream_id = s->stream_id;
                s_iov->stream_key = s->staging_bit_pos;
                s_iov->end_stream = end_stream;
                aura_h2_sched_accum_bytes(sched, s_iov);

                /* Remove when stream body is done */
                if (end_stream) {
                    aura_heap_pop(hp);
                } else {
                    /* update stream vruntime and reschedule */
                    // uint32_t weight = A_URGENCY_WEIGHTS[s->prio.urgency];
                    // s->vruntime += (uint64_t)(offset * 1024) / weight;
                    /* maintain current position */
                }

                /* offset = actual data frame len */
                // aura_h2_conn_after_frame_sent(h2_c, s, A_H2_FRAME_TYPE_DATA, offset, end_stream);
            }
        }
    }
}

int aura_h2_schedule(struct aura_h2_core *h2_c) {
    struct aura_h2_sched2 *sched;
    struct aura_h2_sched_iov *s_iov;
    uint32_t s_idx;
    bool end_stream;
    int rv, i;

    app_debug(true, 0, "aura_h2_schedule <<<");

    sched = &h2_c->scheduler;
    rv = A_H2_ERR_NONE;

    /**
     * For urgent and control frames, just loop
     * over the array and create flight queue entrues
     */
    for (i = 0; i < A_H2_SCHED_MAX_URG_CTRL_FRAMES_PER_TICK; ++i) {
        s_idx = aura_h2_sched_dense_pool_lease(&h2_c->out_frame_pool);
        /* All out frame slots */
        if (s_idx == A_DENSE_POOL_INVALID_IDX) {
            /* trigger flush */
            break;
        }
        s_iov = aura_h2_sched_dense_pool_get_slot(&h2_c->out_frame_pool, s_idx);
        *s_iov = sched->queues.urg_ctrl_frames[i];
    }

    /* start where urg and control frames stopped */
    while (sched->bytes_sent_this_tick < A_H2_SCHED_BATCH_TARGET && i < A_H2_SCHED_MAX_FRAMES_PER_TICK) {
        s_idx = aura_h2_sched_dense_pool_lease(&h2_c->out_frame_pool);
        /* All out frame slots */
        if (s_idx == A_DENSE_POOL_INVALID_IDX) {
            /* trigger flush */
            break;
        }
        s_iov = aura_h2_sched_dense_pool_get_slot(&h2_c->out_frame_pool, s_idx);

        /* Pick stream and prepare it for transmission */
        rv = a_h2_sched_pick_stream2(h2_c, s_iov);
        if (rv < 0)
            break;

        if (aura_fq_enqueue(&h2_c->fq, s_iov, s_iov->stream_key) == A_FQ_STALLED) {
            /* activate back pressure */
            return rv;
        }
    }

    return aura_h2_get_app_error(rv);
}