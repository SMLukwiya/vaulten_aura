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
    if (aura_sliding_buf_init(&sched->write_buf, mc, 0, A_SLIDING_BUF_FL_SHARED) < 0)
        return -1;

    for (i = 0; i < A_PRI_EXT_NR_URGENCY_LEVELS; ++i)
        if (aura_heap_init(&sched->queues.stream_heap[i], mc, 0, aura_h2_stream_cmp_fn, A_HP_TYPE_MIN_HEAP) < 0)
            break;

    /* error initializing stream heap */
    if (i < A_PRI_EXT_NR_URGENCY_LEVELS) {
        while (i-- > -1)
            aura_heap_destroy(&sched->queues.stream_heap[i]);
    }

    return 0;
}

void aura_h2_sched_destroy(struct aura_h2_sched2 *sched) {
    struct aura_h2_sched_iov *s_iov;
    uint32_t idx;

    if (!sched)
        return;

    while (true) {
        idx = aura_bitmap_find_next_bit(sched->queues.urg_ctr_pri_bitmap, 0, A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ);
        if (idx == A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ)
            break;

        s_iov = &sched->queues.urg_ctrl_frames[idx];
        aura_h2_sched_iov_dump(s_iov);
        aura_h2_sched_iov_destroy(s_iov);
        aura_bitmap_clear_bit(idx, sched->queues.urg_ctr_pri_bitmap);
    }

    while (true) {
        idx = aura_bitmap_find_next_bit(sched->queues.urg_ctr_spill_bitmap, 0, A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ);
        if (idx == A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ)
            break;

        s_iov = &sched->queues.urg_ctrl_spill[idx];
        aura_h2_sched_iov_destroy(s_iov);
        aura_bitmap_clear_bit(idx, sched->queues.urg_ctr_spill_bitmap);
    }

    aura_sliding_buf_destroy(&sched->write_buf);

    for (int i = 0; i < A_PRI_EXT_NR_URGENCY_LEVELS; ++i) {
        aura_heap_destroy(&sched->queues.stream_heap[i]);
    }
}

void aura_h2_stream_reschedule(struct aura_h2_sched2 *sched, struct aura_h2_stream *stream, uint64_t len) {
    struct aura_heap *hp;
    uint32_t urgency = stream->prio.urgency;
    bool inc = stream->prio.incremental;
    uint32_t weight = A_URGENCY_WEIGHTS[urgency];

    hp = &sched->queues.stream_heap[urgency];
    if (!stream->prio.incremental || aura_heap_get_size(hp) == 1)
        return;

    aura_heap_del(hp, &stream->hp_ent);
    stream->vruntime += (uint64_t)(len * 1024) / weight;
    A_BUG_ON_2(aura_heap_push(hp, &stream->hp_ent) != 0, true);
}

struct aura_h2_sched_iov *aura_h2_get_sched_iov(struct aura_h2_core *h2_c, uint8_t type) {
    struct aura_h2_sched2 *sched = &h2_c->scheduler;
    struct aura_h2_sched_iov *s_iov;
    uint8_t idx, urg_off, ctrl_off, spill_off;

    s_iov = NULL;

    app_debug(true, 0, ">>>> aura_h2_get_sched_iov");
    /**
     * Get slot in 16 entry discriminate fast path
     * Urgent frames take the first 8 slots
     * while control frame take the last 8
     */
    if (type == A_H2_SCHED_URGENT) {
        idx = aura_bitmap_find_next_empty_bit(
          sched->queues.urg_ctr_pri_bitmap,
          A_H2_CTRL_FRAME_OFF,
          A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ);

        app_debug(true, 0, "aura_h2_get_sched_iov urgent idx=%d", idx);
        if (idx != A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ) {
            aura_bitmap_set_bit(idx, sched->queues.urg_ctr_pri_bitmap);
            s_iov = &sched->queues.urg_ctrl_frames[idx];
            memset(s_iov, 0, sizeof(*s_iov));
            s_iov->pri_idx = idx;
            s_iov->spill_idx = A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ;
        }
    } else {
        idx = aura_bitmap_find_next_empty_bit(
          sched->queues.urg_ctr_pri_bitmap,
          0,
          A_H2_CTRL_FRAME_OFF);

        app_debug(true, 0, "aura_h2_get_sched_iov control idx=%d", idx);
        if (idx != A_H2_CTRL_FRAME_OFF) {
            aura_bitmap_set_bit(idx, sched->queues.urg_ctr_pri_bitmap);
            s_iov = &sched->queues.urg_ctrl_frames[idx];
            memset(s_iov, 0, sizeof(*s_iov));
            s_iov->pri_idx = idx;
            s_iov->spill_idx = A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ;
        }
    }

    /* Get slot in 32 entry indiscriminate backup */
    if (!s_iov) {
        idx = aura_bitmap_find_next_empty_bit(
          sched->queues.urg_ctr_spill_bitmap,
          0,
          A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ);

        if (idx != A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ) {
            aura_bitmap_set_bit(idx, sched->queues.urg_ctr_spill_bitmap);
            s_iov = &sched->queues.urg_ctrl_spill[idx];
            memset(s_iov, 0, sizeof(*s_iov));
            s_iov->spill_idx = idx;
            app_debug(true, 0, "aura_h2_get_sched_iov spill idx=%d", idx);
        }
    }

    if (s_iov) {
        s_iov->h2_c = h2_c;
        s_iov->stream_desc_idx = UINT32_MAX;
        s_iov->stream_key = UINT32_MAX;
        s_iov->out_idx = UINT8_MAX;
    }

    return s_iov;
}

void aura_h2_sched_iov_destroy(struct aura_h2_sched_iov *s_iov) {
    if (!s_iov)
        return;

    if (s_iov->header)
        aura_sliding_buf_consume(s_iov->buf, s_iov->header_len);
    if (s_iov->data)
        aura_sliding_buf_consume(s_iov->buf, s_iov->data_len);

    if (s_iov->out_idx != UINT8_MAX)
        aura_h2_sched_dense_pool_release(&s_iov->h2_c->out_frame_pool, s_iov->out_idx);
    /* delete buffer ref */
    aura_sliding_buf_destroy(s_iov->buf);
}

static inline struct aura_h2_sched_iov *a_sched_h2_get_s_iov(struct aura_h2_core *h2_c) {
    uint32_t s_idx = aura_h2_sched_dense_pool_lease(&h2_c->out_frame_pool);
    struct aura_h2_sched_iov *s_iov;

    /* All out frame slots */
    if (s_idx == A_DENSE_POOL_INVALID_IDX) {
        /* trigger flush */
        return NULL;
    }

    s_iov = aura_h2_sched_dense_pool_get_slot(&h2_c->out_frame_pool, s_idx);
    memset(s_iov, 0, sizeof(*s_iov));
    s_iov->out_idx = s_idx;

    /* Imediately try to enqueue to the flush queue */
    if (aura_fq_enqueue(h2_c->fq, s_iov, s_iov->stream_key) == A_FQ_STALLED) {
        /* @todo: activate back pressure (can flush handle this) */
        aura_h2_sched_dense_pool_release(&h2_c->out_frame_pool, s_idx);
        return NULL;
    }

    return s_iov;
}

void a_sched_h2_release_s_iov(struct aura_h2_core *h2_c, uint32_t idx) {
    aura_h2_sched_dense_pool_release(&h2_c->out_frame_pool, idx);
}

static inline int a_h2_sched_pick_stream(struct aura_h2_core *h2_c, int frame_cnt) {
    struct aura_h2_sched2 *sched;
    struct aura_h2_stream *stream;
    struct aura_heap_ent *hp_ent;
    struct aura_h2_sched_iov *s_iov;
    struct aura_heap *hp;
    uint8_t *src_in, flags;
    size_t in_len, offset, chunk, data_sz;
    bool is_first_frame, has_body, end_stream, first_run = false;
    aura_h2_frame_t f_type;
    size_t stream_cnt;
    int rv = A_H2_ERR_NONE;

    app_debug(true, 0, ">>>> a_h2_sched_pick_stream");
    sched = &h2_c->scheduler;
    /* Pick from most urgent level first */
    for (int i = 0; i < A_PRI_EXT_NR_URGENCY_LEVELS && frame_cnt < A_H2_SCHED_MAX_FRAMES_PER_TICK; ++i) {
        hp = &sched->queues.stream_heap[i];

        if (aura_heap_is_empty(hp))
            continue;

        stream_cnt = 0;

        while (stream_cnt < aura_heap_get_size(hp) && frame_cnt < A_H2_SCHED_MAX_FRAMES_PER_TICK) {

            hp_ent = aura_heap_peek(hp);
            stream = aura_container_of(hp_ent, struct aura_h2_stream, hp_ent);

            if (!aura_h2_stream_can_send(stream, true)) {
                stream_cnt++;
                continue;
            }

            s_iov = a_sched_h2_get_s_iov(h2_c);
            if (!s_iov) {
                /* flush */
                return A_H2_ERR_NONE;
            }
            s_iov->h2_c = h2_c;

            /**
             * Check if headers were encoded in a previous run
             */
            if (!(stream->flags & A_H2_STREAM_FLAG_HDRS_SENT)) {
                app_debug(true, 0, "a_h2_sched_pick_stream header not sent");
                /* Encode headers fully into frames */
                if (!(stream->flags & A_H2_STREAM_FLAG_HDRS_ENCODED)) {
                    app_debug(true, 0, "a_h2_sched_pick_stream encoding header");
                    rv = aura_hpack_encoder_adjust_tab_size(&h2_c->enc);
                    if (rv != A_HPACK_OK) {
                        rv = aura_h2_translate_hpack_error(rv);
                        goto err;
                    }

                    aura_hpack_encode_status(&h2_c->enc, stream->res.status_code);

                    rv = aura_hpack_encode_headers(
                      &h2_c->enc,
                      h2_c->intern_tab,
                      stream->res.headers.entries,
                      stream->res.headers.cnt);
                    if (rv != A_HPACK_OK) {
                        rv = aura_h2_translate_hpack_error(rv);
                        goto err;
                    }

                    has_body = false;
                    if (stream->res.content_length != SIZE_MAX &&
                        stream->res.content_length != 0 &&
                        stream->res.body) {
                        has_body = true;

                        rv = aura_hpack_encode_content_length(&h2_c->enc, stream->res.content_length);
                        if (rv != A_HPACK_OK) {
                            rv = aura_h2_translate_hpack_error(rv);
                            goto err;
                        }
                    }

                    src_in = aura_sliding_buf_read_ptr(&h2_c->enc.enc_buf);
                    in_len = aura_sliding_buf_read_len(&h2_c->enc.enc_buf);

                    offset = 0;
                    rv = A_H2_ERR_NONE;
                    is_first_frame = true;
                    end_stream = !has_body;
                    while (in_len > 0) {
                        chunk = a_min(in_len, h2_c->peer_settings.max_frame_size);
                        f_type = is_first_frame ? A_H2_FRAME_TYPE_HDRS : A_H2_FRAME_TYPE_CONT;
                        flags = in_len == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
                        /* defer sending END_STREAM until final headers block */
                        flags |= (end_stream && (flags & A_H2_FRAME_FLAG_END_HEADERS)) ? A_H2_FRAME_FLAG_END_STREAM : 0;
                        rv = aura_h2_encode_hdr_frame(
                          stream->out_buf,
                          stream->stream_id,
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
                        goto err;
                    }

                    stream->flags |= A_H2_STREAM_FLAG_HDRS_ENCODED;
                    aura_sliding_buf_reset(&h2_c->enc.enc_buf);
                }

                /**
                 * Because stream out buffer was empty
                 * The encoded headers are the only bytes
                 * in the out buffer, so we can safely reference
                 * its start and length as the frame data and length
                 */
                src_in = aura_sliding_buf_read_ptr(stream->out_buf);
                in_len = aura_sliding_buf_read_len(stream->out_buf);

                s_iov->buf = stream->out_buf;
                aura_sliding_buf_reference(stream->out_buf);
                s_iov->header = src_in;
                s_iov->header_len = in_len;
                s_iov->stream_id = stream->stream_id;
                s_iov->stream_desc_idx = stream->stream_desc_idx;

                aura_h2_sched_accum_bytes(sched, s_iov);
                stream->flags |= A_H2_STREAM_FLAG_HDRS_SENT;

                /* only header response */
                if (!has_body) {
                    s_iov->type = A_H2_SCHED_HDR;
                    s_iov->end_stream = end_stream;
                    s_iov->data = NULL;
                    s_iov->data_len = 0;
                    app_debug(true, 0, "a_h2_sched_pick_stream header_only");
                    aura_h2_sched_iov_dump(s_iov);
                    return A_H2_ERR_NONE;
                } else
                    /* Body is present */
                    s_iov->type = A_H2_SCHED_RESPONSE;

                first_run = true;
            }

            /**
             * At this point, if this was the first run,
             * we have encoded headers and have data to bundle up,
             * if not the first run, this is data only run
             */
            const char *start;
            uint8_t *data_out;
            size_t target_budget;
            app_debug(true, 0, "a_h2_sched_pick_stream body len=%ld", stream->res.content_length);

            /**
             * We have the end of data in a data only run.
             * If the stream was headers only, it would not
             * reach here since the 'after frame sent' routine
             * would clear it from the scheduler, otherwise,
             * Send 0 length data frame
             */
            if (stream->res.content_length == 0) {
                if (first_run) {
                    s_iov->buf = stream->out_buf;
                    aura_sliding_buf_reference(stream->out_buf);
                    s_iov->stream_id = stream->stream_id;
                    s_iov->stream_desc_idx = stream->stream_desc_idx;
                    s_iov->stream_key = stream->staging_bit_pos;
                    s_iov->end_stream = true;
                    s_iov->type = A_H2_SCHED_DATA;
                }
                s_iov->data = NULL;
                s_iov->data_len = 0;

                return A_H2_ERR_NONE;
            }

            target_budget = A_H2_SCHED_BATCH_TARGET - sched->bytes_sent_this_tick;
            /**
             * If budget left is too small.
             * Allow some soft overflow
             */
            // data_sz = a_max(target_budget, A_H2_SCHED_MIN_LEN);
            // data_sz = a_min(data_sz, s->res.content_length);
            data_sz = stream->res.content_length;

            start = stream->res.body;
            flags = 0;
            end_stream = stream->res.content_length == data_sz;

            /**
             * If incremental stream, encode one possibly
             * max frame chunk and return
             */
            app_debug(true, 0, "a_h2_sched_pick_stream urgency=%d, inc=%d", stream->prio.urgency, stream->prio.incremental);
            if (stream->prio.incremental) {
                chunk = a_min(data_sz, h2_c->peer_settings.max_frame_size);
                end_stream = data_sz == chunk && end_stream;
                flags |= end_stream ? A_H2_FRAME_FLAG_END_STREAM : 0;
                /* get data frame position in out buffer */
                data_out = aura_sliding_buf_write_ptr(stream->out_buf);
                rv = aura_sliding_buf_append(stream->out_buf, start, chunk);
                if (rv < 0) {
                    rv = A_H2_INTERNAL_ERR;
                    goto err;
                }

                if (first_run) {
                    s_iov->buf = stream->out_buf;
                    aura_sliding_buf_reference(stream->out_buf);
                    s_iov->type = A_H2_SCHED_DATA;
                    s_iov->stream_id = stream->stream_id;
                    s_iov->stream_key = stream->staging_bit_pos;
                    s_iov->stream_desc_idx = stream->stream_desc_idx;
                }
                s_iov->data = data_out;
                s_iov->data_len = chunk;
                s_iov->end_stream = end_stream;
                stream->last_write = chunk;
                aura_h2_sched_accum_bytes(sched, s_iov);

                if (!end_stream) {
                    /* update stream vruntime and reschedule if needed */
                    aura_h2_stream_reschedule(&h2_c->scheduler, stream, chunk);

                    stream->res.body += chunk;
                    stream->res.content_length -= chunk;
                } // else do nothing, 'after frame sent' routine will take care of cleanup

            } else {
                /**
                 * Non incremental, encoded as much as
                 * we can
                 */
                offset = 0;
                /* get data frame position in out buffer */
                data_out = aura_sliding_buf_write_ptr(stream->out_buf);
                rv = aura_sliding_buf_append(stream->out_buf, start, data_sz);
                if (rv < 0) {
                    rv = A_H2_INTERNAL_ERR;
                    goto err;
                }

                stream->res.content_length -= data_sz;
                stream->res.body += data_sz;

                if (first_run) {
                    s_iov->buf = stream->out_buf;
                    aura_sliding_buf_reference(stream->out_buf);
                    s_iov->type = A_H2_SCHED_DATA;
                    s_iov->stream_id = stream->stream_id;
                    s_iov->stream_desc_idx = stream->stream_desc_idx;
                    s_iov->stream_key = stream->staging_bit_pos;
                }
                s_iov->data = data_out;
                s_iov->data_len = offset;
                s_iov->end_stream = end_stream;
                stream->last_write = data_sz;
                aura_h2_sched_accum_bytes(sched, s_iov);

                /* Remove when stream body is done */
                if (!end_stream) {
                    aura_h2_stream_reschedule(&h2_c->scheduler, stream, chunk);
                } // else: do nothing, 'after frame sent' routine will handle cleanup
            }

            return A_H2_ERR_NONE;
        }
    }

    app_debug(true, 0, ">>>> a_h2_sched_pick_stream END");
    return rv;

err:
    aura_sliding_buf_reset(&h2_c->enc.enc_buf);
    a_sched_h2_release_s_iov(h2_c, s_iov->out_idx);
    aura_fq_dequeue(h2_c->fq);
    app_debug(true, 0, ">>>> a_h2_sched_pick_stream error=%d", rv);
    return rv;
}

int aura_h2_schedule(struct aura_h2_core *h2_c) {
    struct aura_h2_sched2 *sched = &h2_c->scheduler;
    struct aura_h2_sched_iov *s_iov;
    uint32_t out_idx;
    int rv = A_H2_ERR_NONE;
    int i, idx;

    app_debug(true, 0, ">>>> aura_h2_schedule");

    /** @todo: send left over control frames at the very beginning of the connection, when handling residual data */

    /**
     * For urgent and control frames, just loop
     * over the array and create flight queue entrues
     */
    int frame_cnt = 0;
    while (frame_cnt < A_H2_SCHED_MAX_URG_CTRL_FRAMES_PER_TICK && !aura_h2_sched_pri_spill_slots_empty(sched)) {
        /**
         * Look into the primary slot array, and
         * handle urgent frames first
         */
        idx = aura_bitmap_find_next_bit(
          sched->queues.urg_ctr_pri_bitmap,
          A_H2_CTRL_FRAME_OFF + +sched->queues.urg_frame_off,
          A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ);

        if (idx != A_H2_SCHED_URG_CTRL_PRIMARY_SLOT_SZ) {
            s_iov = a_sched_h2_get_s_iov(h2_c);
            if (!s_iov) {
                /* flush */
                return rv;
            }
            /* preserve out index */
            out_idx = s_iov->out_idx;
            /* Update search offset for the next frame to maintain order */
            sched->queues.urg_frame_off = (sched->queues.urg_frame_off + 1) & A_H2_SCHED_PRI_SLOTS_MASK;
            aura_bitmap_clear_bit(idx, sched->queues.urg_ctr_pri_bitmap);
            *s_iov = sched->queues.urg_ctrl_frames[idx];
            /* restore out idx */
            s_iov->out_idx = out_idx;
            frame_cnt++;
            app_debug(true, 0, ">>>> aura_h2_schedule urgent frame: idx=%d >>>>", idx);
            aura_h2_sched_iov_dump(s_iov);
            continue;
        }

        /**
         * Look into the primary slot array, and
         * handle control frames next
         */
        idx = aura_bitmap_find_next_bit(
          sched->queues.urg_ctr_pri_bitmap,
          0 + sched->queues.ctrl_frame_off,
          A_H2_CTRL_FRAME_OFF);

        if (idx != A_H2_CTRL_FRAME_OFF) {
            s_iov = a_sched_h2_get_s_iov(h2_c);
            if (!s_iov) {
                /* flush */
                return rv;
            }
            /* preserve out index */
            out_idx = s_iov->out_idx;
            /* Update search offset for the next frame to maintain order */
            sched->queues.ctrl_frame_off = (sched->queues.ctrl_frame_off + 1) & A_H2_SCHED_PRI_SLOTS_MASK;
            *s_iov = sched->queues.urg_ctrl_frames[idx];
            /* restore out idx */
            s_iov->out_idx = out_idx;
            frame_cnt++;
            aura_bitmap_clear_bit(idx, sched->queues.urg_ctr_pri_bitmap);
            app_debug(true, 0, ">>>> aura_h2_schedule control frame: idx=%d >>>>", idx);
            aura_h2_sched_iov_dump(s_iov);
            continue;
        }

        /**
         * Look into the spilled slot array, and
         * whatever is there next
         */
        idx = aura_bitmap_find_next_bit(
          sched->queues.urg_ctr_spill_bitmap,
          0 + sched->queues.spill_frame_off,
          A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ);
        if (idx == A_H2_SCHED_URG_CTRL_SPILL_SLOT_SZ)
            break;

        s_iov = a_sched_h2_get_s_iov(h2_c);
        if (!s_iov) {
            /* flush */
            return rv;
        }
        /* preserve out index */
        out_idx = s_iov->out_idx;
        *s_iov = sched->queues.urg_ctrl_spill[idx];
        /* Update search offset for the next frame to maintain order */
        sched->queues.spill_frame_off = (sched->queues.spill_frame_off + 1) & A_H2_SCHED_SPILL_SLOTS_MASK;
        aura_bitmap_clear_bit(idx, sched->queues.urg_ctr_spill_bitmap);
        /* restore out index */
        s_iov->out_idx = out_idx;
        frame_cnt++;
        app_debug(true, 0, ">>>> aura_h2_schedule spill frame: idx=%d >>>>", idx);
        aura_h2_sched_iov_dump(s_iov);
    }

    /* start where urg and control frames stopped */
    if (sched->queues.queued_cnt > 0)
        rv = a_h2_sched_pick_stream(h2_c, frame_cnt);

    app_debug(true, 0, ">>>> aura_h2_schedule END");

    return aura_h2_get_app_error(rv);
}

int64_t aura_h2_sched_iov_create_data(struct aura_h2_sched_iov *s_iov,
                                      struct aura_sliding_buf *scratch,
                                      bool *done) {
    uint32_t scratch_len, data_len;
    bool end_stream;
    int64_t rv = 0;

    scratch_len = aura_sliding_buf_write_len(scratch);
    if (scratch_len == 0)
        return rv;

    if (s_iov->type == A_H2_SCHED_RESPONSE) {
        /**
         * Pack header.
         * If entire header can fit, adjust the type to purely
         * data, and try to squeeze data if possible;
         */
        if (s_iov->header_len <= scratch_len) {
            aura_sliding_buf_append(scratch, s_iov->header, s_iov->header_len);

            rv = s_iov->header_len;
            data_len = s_iov->allowed_len - s_iov->header_len;
            s_iov->header = NULL;
            s_iov->header_len == 0;
            s_iov->type = A_H2_SCHED_DATA;
            aura_sliding_buf_consume(s_iov->buf, s_iov->header_len);

            scratch_len = aura_sliding_buf_write_len(scratch);
            /* If scratch len can accomodate the data frame header and 9 or more bytes of data */
            if (scratch_len >= 18 && data_len > 0) {
                char frame_header[A_H2_FRAME_HEADER_SIZE], *ptr = frame_header;

                data_len = a_min(data_len, scratch_len - A_H2_FRAME_HEADER_SIZE);
                *done = data_len == s_iov->data_len;
                end_stream = s_iov->end_stream && *done;

                /* Frame header len is not part of the frame length */
                ptr = a_buf_pack_24u(ptr, data_len);
                ptr = a_buf_pack_8u(ptr, A_H2_FRAME_TYPE_DATA);
                ptr = a_buf_pack_8u(ptr, end_stream ? A_H2_FRAME_FLAG_END_STREAM : 0);
                ptr = a_buf_pack_32u(ptr, s_iov->stream_id);

                aura_sliding_buf_append(scratch, frame_header, A_H2_FRAME_HEADER_SIZE);
                aura_sliding_buf_append(scratch, s_iov->data, data_len);
                aura_sliding_buf_consume(s_iov->buf, data_len);
                if (*done) {
                    s_iov->data = NULL;
                    s_iov->data_len = 0;
                } else {
                    s_iov->data += data_len;
                    s_iov->data_len -= data_len;
                }
                aura_h2_conn_after_frame_sent(s_iov->h2_c, s_iov->stream_id, s_iov->type, data_len, end_stream);
                rv += data_len;
            }
        } else {
            /**
             * Not entire header can fit, encode what can fit
             */
            aura_sliding_buf_append(scratch, s_iov->header, scratch_len);
            aura_sliding_buf_consume(s_iov->buf, scratch_len);
            s_iov->header += scratch_len;
            s_iov->header_len -= scratch_len;
            rv = scratch_len;
        }
    } else if (s_iov->type == A_H2_SCHED_DATA) {
        /* If scratch len can accomodate the data frame header and 9 or more bytes of data */
        A_BUG_ON_2(s_iov->header, true);
        A_BUG_ON_2(s_iov->header_len, true);
        if (scratch_len >= 18) {
            char frame_header[A_H2_FRAME_HEADER_SIZE], *ptr = frame_header;

            data_len = a_min(s_iov->allowed_len, scratch_len - A_H2_FRAME_HEADER_SIZE);
            *done = data_len == s_iov->data_len;
            end_stream = s_iov->end_stream && *done;

            /* Frame header len is not part of the frame length */
            ptr = a_buf_pack_24u(ptr, data_len);
            ptr = a_buf_pack_8u(ptr, A_H2_FRAME_TYPE_DATA);
            ptr = a_buf_pack_8u(ptr, end_stream ? A_H2_FRAME_FLAG_END_STREAM : 0);
            ptr = a_buf_pack_32u(ptr, s_iov->stream_id);

            aura_sliding_buf_append(scratch, frame_header, A_H2_FRAME_HEADER_SIZE);
            aura_sliding_buf_append(scratch, s_iov->data, data_len);
            aura_sliding_buf_consume(s_iov->buf, data_len);
            if (*done) {
                s_iov->data = NULL;
                s_iov->data_len = 0;
            } else {
                s_iov->data += data_len;
                s_iov->data_len -= data_len;
            }
            aura_h2_conn_after_frame_sent(s_iov->h2_c, s_iov->stream_id, s_iov->type, data_len, end_stream);
            rv = data_len;
        }
    }
    if (s_iov->type == A_H2_SCHED_HDR) {
        /* header only frame */
        data_len = a_min(s_iov->header_len, scratch_len);
        aura_sliding_buf_append(scratch, s_iov->header, data_len);
        aura_sliding_buf_consume(s_iov->buf, data_len);
        *done = data_len == s_iov->header_len;
        if (*done) {
            s_iov->header = NULL;
            s_iov->header_len = 0;
        } else {
            s_iov->header += data_len;
            s_iov->header_len -= data_len;
        }
        /* endstream is used to release the s_iov here */
        rv = data_len;
        aura_h2_conn_after_frame_sent(s_iov->h2_c, s_iov->stream_id, s_iov->type, data_len, end_stream);

    } else {
        /* control and urgent frames */
        data_len = a_min(s_iov->data_len, scratch_len);
        aura_sliding_buf_append(scratch, s_iov->data, data_len);
        aura_sliding_buf_consume(s_iov->buf, data_len);
        *done = data_len == s_iov->data_len;
        if (*done) {
            s_iov->data = NULL;
            s_iov->data_len = 0;
        } else {
            s_iov->data += data_len;
            s_iov->data_len -= data_len;
        }
        /* endstream is used to release the s_iov here */
        rv = data_len;
    }

    return rv;
}

void aura_h2_sched_iov_dump(struct aura_h2_sched_iov *s_iov) {
    app_debug(true, 0, "AURA_SCHED_IOV");
    app_debug(true, 0, "    stream id=%u", s_iov->stream_id);
    app_debug(true, 0, "    stream key=%u", s_iov->stream_key);
    app_debug(true, 0, "    stream desc index=%u", s_iov->stream_desc_idx);
    app_debug(true, 0, "    type=%u", s_iov->type);
    app_debug(true, 0, "    h2 core=%p", s_iov->h2_c);
    app_debug(true, 0, "    allowed length=%u", s_iov->allowed_len);
    app_debug(true, 0, "    header=%p", s_iov->header);
    app_debug(true, 0, "    header length=%u", s_iov->header_len);
    app_debug(true, 0, "    data=%p", s_iov->data);
    app_debug(true, 0, "    data length=%u", s_iov->data_len);
    app_debug(true, 0, "    end stream=%d", s_iov->end_stream);
    app_debug(true, 0, "    pri index=%d", s_iov->pri_idx);
}
