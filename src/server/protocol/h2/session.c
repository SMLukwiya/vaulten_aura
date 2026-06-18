#include "h2/session.h"

/* update connection window size */
static inline int a_update_window_size(int64_t *avail, uint32_t n) {
    int64_t new_sz;

    new_sz = *avail + n;
    if (new_sz > INT32_MAX)
        return A_H2_FLOW_CONTROL_ERR;
    *avail = new_sz;

    return A_H2_ERR_NONE;
}

/**
 * Update stream window size
 */
static inline int a_update_stream_peer_window_size(struct aura_h2_stream *stream, uint32_t n) {
    int64_t *avail;
    int64_t cur_sz, updated_sz;
    int rv;

    avail = (int64_t *)&stream->peer_window_size;
    cur_sz = *avail;
    if ((rv = a_update_window_size(avail, n)) != A_H2_ERR_NONE)
        return rv;

    updated_sz = *avail;
    if (aura_h2_stream_should_resume_send(cur_sz, updated_sz)) {
        aura_h2_stream_resume(stream);
    }

    return A_H2_ERR_NONE;
}

int aura_h2_conn_enqueue_wind_update(struct aura_h2_core *h2_c, uint32_t stream_id,
                                     size_t wind_sz) {
    size_t wind_flen;
    uint8_t *out_data;
    struct aura_h2_sched_iov *s_iov;

    wind_flen = aura_calc_frame_len(A_H2_FRAME_TYPE_WIND_UPDATE, 0, 0);

    out_data = aura_h2_encode_ctrl_frame(
      &h2_c->scheduler.write_buf,
      A_H2_FRAME_TYPE_WIND_UPDATE,
      A_H2_FRAME_FLAG_NONE,
      0,
      wind_flen,
      (uint8_t *)&wind_sz,
      0);
    if (!out_data)
        return A_H2_INTERNAL_ERR;

    s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_CONTROL);
    if (!s_iov) {
        /* @todo: close connection */
    }

    s_iov->type = A_H2_SCHED_CONTROL;
    s_iov->buf = &h2_c->scheduler.write_buf;
    s_iov->data = out_data;
    s_iov->data_len = wind_flen;
    s_iov->stream_id = stream_id;
    s_iov->end_stream = false;

    return A_H2_ERR_NONE;
}

int aura_h2_conn_enqueue_goaway(struct aura_h2_core *h2_c, uint32_t last_stream_id,
                                int err_code, const struct aura_iovec *reason) {
    struct aura_h2_goaway_payload payload;
    struct aura_h2_sched_iov *s_iov;
    uint32_t frame_len;
    uint8_t *out_data;
    int rv;

    if (h2_c->flags & A_H2_CORE_FLAG_GOAWAY_SENT)
        return A_H2_ERR_NONE;

    payload.error_code = aura_h2_get_frame_error(err_code);
    payload.last_stream_id = last_stream_id;
    payload.debug_data.base = reason->base;
    payload.debug_data.len = reason->len;

    s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_URGENT);
    if (!s_iov) {
        /* @todo: close connection */
    }

    frame_len = aura_calc_frame_len(A_H2_FRAME_TYPE_GOAWAY, 0, reason ? reason->len : 0);
    out_data = aura_h2_encode_ctrl_frame(
      &h2_c->scheduler.write_buf,
      A_H2_FRAME_TYPE_GOAWAY,
      A_H2_FRAME_FLAG_NONE,
      0,
      frame_len,
      (const uint8_t *)&payload,
      0);
    if (!out_data)
        return A_H2_INTERNAL_ERR;

    s_iov->type = A_H2_SCHED_URGENT;
    s_iov->buf = &h2_c->scheduler.write_buf;
    s_iov->data = out_data;
    s_iov->data_len = frame_len;
    s_iov->stream_id = 0;
    s_iov->end_stream = false;

    // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_CLOSING);
    h2_c->flags |= A_H2_CORE_FLAG_GOAWAY_SENT;

    return A_H2_ERR_NONE;
}

int aura_h2_conn_enqueue_rst_frame(struct aura_h2_core *h2_c, uint32_t stream_id, int err) {
    struct aura_h2_sched_iov *s_iov;
    uint32_t frame_len;
    uint8_t *out_data;

    frame_len = aura_calc_frame_len(A_H2_FRAME_TYPE_RST, 0, 0);

    s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_URGENT);
    if (!s_iov) {
        /* @todo: close connection */
    }

    out_data = aura_h2_encode_ctrl_frame(
      &h2_c->scheduler.write_buf,
      A_H2_FRAME_TYPE_RST,
      A_H2_FRAME_FLAG_NONE,
      stream_id,
      frame_len,
      (uint8_t *)&err,
      sizeof(int));
    if (!out_data)
        return A_H2_INTERNAL_ERR;

    s_iov->type = A_H2_SCHED_URGENT;
    s_iov->buf = &h2_c->scheduler.write_buf;
    s_iov->data = out_data;
    s_iov->data_len = frame_len;
    s_iov->stream_id = 0;
    s_iov->end_stream = false;

    aura_h2_conn_closed_stream_rb_add(h2_c, stream_id, A_H2_STREAM_SHUTDOWN_FLAG_RST_SENT);

    return A_H2_ERR_NONE;
}

int aura_h2_core_init(struct aura_h2_core *core, struct aura_mem_ctx *mc, bool is_server) {
    int rv = 0;

    memset(core, 0, sizeof(*core));
    if (aura_hpack_encoder_init(&core->enc, mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) < 0) {
        return -1;
    }

    if (aura_hpacK_decoder_init(&core->dec, mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) < 0) {
        aura_hpack_encoder_destroy(&core->enc);
        return -1;
    }

    aura_fq_init(&core->fq, A_H2_DEFAULT_MAX_CONC_STREAMS);
    core->peer_window_size = A_H2_INITIAL_WINDOW_SIZE;
    core->local_window_size = A_H2_INITIAL_WINDOW_SIZE;
    core->local_goaway_stream_id = A_H2_STREAM_ID_MASK;
    core->peer_goaway_stream_id = A_H2_STREAM_ID_MASK;
    core->next_stream_id = is_server ? 2 : 1;
    core->peer_settings = aura_h2_default_settings;
    core->local_settings = aura_h2_default_settings;

    if (aura_rh_map_init(&core->stream_map, mc, aura_h2_default_settings.max_conc_streams, A_RH_KEY_U64, false) < 0) {
        rv = -1;
        goto err_hpack;
    }

    if (aura_h2_sched_init(&core->scheduler, mc) < 0) {
        rv = -1;
        goto err_map;
    }

    core->intern_tab = aura_intern_tab_create(mc, 128);
    if (!core->intern_tab) {
        rv = -1;
        goto err_sched;
    }

    return rv;

err_sched:
    aura_h2_sched_destroy(&core->scheduler);

err_map:
    aura_rh_map_destroy(&core->stream_map);

err_hpack:
    aura_hpack_encoder_destroy(&core->enc);
    aura_hpack_decoder_destroy(&core->dec);
    return rv;
}

void aura_h2_core_destroy(struct aura_h2_core *h2_c, bool is_server) {
    struct aura_h2_stream *stream;

    aura_hpack_encoder_destroy(&h2_c->enc);
    aura_hpack_decoder_destroy(&h2_c->dec);
    aura_h2_sched_destroy(&h2_c->scheduler);
    aura_intern_tab_destroy2(h2_c->intern_tab);
    aura_fq_destroy(&h2_c->fq);

    for (int i = 0; i < h2_c->stream_map.cap; ++i) {
        stream = h2_c->stream_map.buckets[i].data;
        if (stream) {
            aura_h2_stream_destroy(stream, is_server);
        }
    }

    aura_rh_map_destroy(&h2_c->stream_map);
}

/**
 * Get the staging bit position for new stream
 * This is guaranteed to succeed because bit
 * positions = max conc streams, and each stream
 * only get a single staging slot
 */
static inline uint32_t aura_h2_stream_get_staging_bit_pos(struct aura_h2_fq_staging_dense_pool_idx_man *pool) {
    return aura_h2_fq_staging_dense_pool_idx_man_lease(pool);
}

static inline void aura_h2_stream_release_staging_bit_pos(
  struct aura_h2_fq_staging_dense_pool_idx_man *pool,
  uint32_t idx) {
    aura_h2_fq_staging_dense_pool_idx_man_release(pool, idx);
}

/**
 * Allocate stream description entry for this stream
 * This is guaranteed to success since it matches
 * max conc streams
 */
static void aura_h2_conn_stream_desc_alloc(struct aura_h2_core *h2_c, uint32_t stream_id) {
    struct aura_h2_stream_desc *sd;

    uint32_t idx = aura_h2_stream_desc_dense_pool_lease(&h2_c->stream_desc_pool);
    A_BUG_ON_2(idx == A_DENSE_POOL_INVALID_IDX, true);
    sd = aura_h2_stream_desc_dense_pool_get_slot(&h2_c->stream_desc_pool, idx);

    sd->desc_flags = 0;
    sd->h2_c = h2_c;
    sd->peer_window_sz = h2_c->peer_window_size;
    sd->stream_id = stream_id;
}

struct aura_h2_stream_desc *aura_h2_conn_stream_desc_get(struct aura_h2_core *h2_c, uint32_t idx) {
    return aura_h2_stream_desc_dense_pool_get_slot(&h2_c->stream_desc_pool, idx);
}

struct aura_h2_stream *aura_h2_conn_stream_open(struct aura_h2_core *h2_c, struct aura_mem_ctx *mc,
                                                uint32_t stream_id, aura_h2_stream_state_t init_state,
                                                uint8_t flags, void *user_data, user_data_destructor dtor,
                                                bool is_server) {
    // struct aura_slab_cache *sc;
    struct aura_h2_stream *s;
    uint32_t bit_pos;

    s = aura_h2_stream_open(
      h2_c,
      mc,
      stream_id,
      init_state,
      flags,
      aura_h2_conn_get_next_global_seq(h2_c),
      user_data,
      dtor);
    if (!s)
        return NULL;

    struct aura_rh_map_key key;
    aura_rh_map_key_init(&key, (uint64_t)stream_id, sizeof(uint64_t), A_RH_KEY_U64);
    if (aura_rh_map_put(&h2_c->stream_map, &key, s) < 0) {
        aura_h2_stream_destroy(s, is_server);
        return NULL;
    }

    aura_h2_conn_stream_desc_alloc(h2_c, stream_id);

    h2_c->next_stream_id += 2;
    if (init_state == A_H2_STREAM_STATE_IDLE)
        h2_c->nr_idle_streams++;

    if (is_server) {
        bit_pos = aura_h2_stream_get_staging_bit_pos(&h2_c->staging_bitmap);
        aura_h2_stream_attach_staging_bit_pos(s, bit_pos);
        h2_c->max_received_stream_id = stream_id;
    } else
        h2_c->max_sent_stream_id = stream_id;

    return s;
}

int aura_h2_conn_send_stream_error(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                   int err_num, bool is_server) {
    uint8_t *rst_frame;
    uint32_t frame_len;

    if (stream->state == A_H2_STREAM_STATE_CLOSING)
        return A_H2_ERR_NONE;

    if (aura_h2_conn_enqueue_rst_frame(h2_c, stream->stream_id, err_num) < 0)
        return A_H2_INTERNAL_ERR;

    aura_h2_conn_detach_stream(h2_c, stream->stream_id);
    aura_h2_stream_transition_state(stream, A_H2_STREAM_STATE_CLOSING);

    if (is_server) {
        h2_c->nr_out_streams--;
        aura_h2_stream_release_staging_bit_pos(&h2_c->staging_bitmap, stream->staging_bit_pos);
    } else
        h2_c->nr_in_streams--;

    aura_h2_stream_destroy(stream, is_server);

    return A_H2_ERR_NONE;
}

int aura_h2_conn_process_settings(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                  bool is_server) {
    struct aura_h2_frame *frame;
    struct aura_h2_sched_iov *s_iov;
    struct aura_h2_stream *stream;
    const struct aura_iovec *reason;
    uint8_t *out_data;
    uint32_t prev_window_sz, delta, frame_len;
    int rv;

    frame = &in_frame->frame;
    if (frame->stream_id != 0) {
        rv = A_H2_PROTOCOL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    if (aura_h2_frame_is_ack(frame->flags) && frame->len != 0) {
        rv = A_H2_FRAME_SIZE_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    } else {
        /* Store prev window size before updating it */
        prev_window_sz = h2_c->peer_settings.initial_window_size;
        // in_frame->settings_payload = h2_c->peer_settings;
        rv = aura_h2_parse_frame_payload(in_frame);
        if (rv != A_H2_ERR_NONE) {
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
            goto goaway;
        }

        /* Copy over parsed settings */
        memcpy(&h2_c->peer_settings, &in_frame->settings_payload, sizeof(h2_c->peer_settings));
        /* Update encoder table if neccesary */
        aura_hpack_enc_update_tab_settings_sz(&h2_c->enc, h2_c->peer_settings.hdr_table_size);

        /* schedule ack */
        frame_len = aura_calc_frame_len(A_H2_FRAME_TYPE_SETTINGS, 0, 0);

        out_data = aura_h2_encode_ctrl_frame(
          &h2_c->scheduler.write_buf,
          A_H2_FRAME_TYPE_SETTINGS,
          A_H2_FRAME_FLAG_ACK,
          0,
          frame_len,
          NULL, 0);
        if (!out_data) {
            rv = A_H2_INTERNAL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
            goto goaway;
        }

        s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_CONTROL);
        if (!s_iov) {
            /* @todo: close connection */
        }

        s_iov->type = A_H2_SCHED_CONTROL;
        s_iov->buf = &h2_c->scheduler.write_buf;
        s_iov->data = out_data;
        s_iov->data_len = frame_len;
        s_iov->stream_id = frame->stream_id;
        s_iov->end_stream = false;

        /* Check prev window against updated window */
        if (prev_window_sz != h2_c->peer_settings.initial_window_size) {
            delta = h2_c->peer_settings.initial_window_size - prev_window_sz;
            for (int i = 0; i < h2_c->stream_map.cap; ++i) {
                stream = h2_c->stream_map.buckets[i].data;
                if (stream) {
                    rv = a_update_stream_peer_window_size(stream, delta);
                    if (rv != 0) {
                        /* schedule stream reset FLOW CONTROL ERROR for all violators */
                        aura_h2_conn_send_stream_error(h2_c, stream, rv, is_server);
                    }
                }
            }
        }
    }

    return A_H2_ERR_NONE;

goaway:
    aura_h2_conn_enqueue_goaway(
      h2_c,
      h2_c->local_goaway_stream_id,
      rv,
      reason);
    return rv;
}

/**
 *
 */
int aura_process_priority(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame) {
    return A_H2_ERR_NONE;
}

int aura_h2_conn_process_ping(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_frame *frame;
    struct aura_h2_ping_payload payload;
    const struct aura_iovec *reason;
    struct aura_h2_sched_iov *s_iov;
    uint8_t *out_data;
    uint32_t frame_len;
    int rv;

    frame = &in_frame->frame;
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    if (!aura_h2_frame_is_ack(frame->flags)) {
        out_data = aura_h2_encode_ctrl_frame(
          &h2_c->scheduler.write_buf,
          A_H2_FRAME_TYPE_PING,
          0, 0,
          frame_len,
          payload.data,
          64);

        if (!out_data) {
            rv = A_H2_INTERNAL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
            goto goaway;
        }

        s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_URGENT);
        if (!s_iov) {
            /* @todo: close connection */
        }

        s_iov->type = A_H2_SCHED_URGENT;
        s_iov->buf = &h2_c->scheduler.write_buf;
        s_iov->data = out_data;
        s_iov->data_len = frame_len;
        s_iov->stream_id = frame->stream_id;
        s_iov->end_stream = false;
    }

    return rv;

goaway:
    aura_h2_conn_enqueue_goaway(
      h2_c,
      h2_c->peer_goaway_stream_id,
      rv,
      reason);

    return rv;
}

/**
 *
 */
int aura_h2_conn_process_goaway(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                bool is_server) {
    struct aura_h2_goaway_payload payload;
    struct aura_h2_frame *frame;
    struct aura_h2_stream *stream;
    int rv;

    frame = &in_frame->frame;
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE)
        return rv;

    payload = in_frame->goaway_payload;
    /**
     * check if peer sent their own local last stream id OR
     * if peer increased last stream id
     */
    if ((payload.last_stream_id > 0 &&
         !aura_h2_conn_stream_is_local(payload.last_stream_id, is_server)) ||
        payload.last_stream_id > h2_c->peer_goaway_stream_id) {
        /* Hard close connection*/

        return A_H2_PROTOCOL_ERR;
    }

    h2_c->flags |= (A_H2_CORE_FLAG_GOAWAY_RECD | A_H2_CORE_FLAG_CLOSING);
    h2_c->peer_goaway_stream_id = payload.last_stream_id;

    // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_CLOSING);

    /* collect streams to terminate and call terminate on them */
    if (aura_rh_map_is_empty(&h2_c->stream_map)) {
        // aura_conn_transition_state(h2_c->conn, A_CONN_STATE_CLOSING);
        return rv;
    }

    void *data;
    if (payload.error_code == 0x0) {
        /* Fail streams with stream id above peer max processed stream */
        if (!aura_rh_map_is_empty(&h2_c->stream_map)) {
            for (int i = 0; i < h2_c->stream_map.cap; ++i) {
                stream = (struct aura_h2_stream *)(h2_c->stream_map.buckets[i].data);
                if (stream && stream->stream_id > payload.last_stream_id) {
                    aura_rh_map_del(&h2_c->stream_map, &h2_c->stream_map.buckets[i].key, NULL);
                    aura_h2_stream_destroy(stream, is_server);
                }
            }
        }
    } else {
        /* Fail all streams */
        if (!aura_rh_map_is_empty(&h2_c->stream_map)) {
            for (int i = 0; i < h2_c->stream_map.cap; ++i) {
                aura_rh_map_del(&h2_c->stream_map, &h2_c->stream_map.buckets[i].key, &data);
                stream = (struct aura_h2_stream *)data;
                if (stream)
                    aura_h2_stream_destroy(stream, is_server);
            }
        }
    }

    return rv;
}

/**
 *
 */
int aura_h2_conn_process_rst_stream(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                    bool is_server) {
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int rv;

    frame = &in_frame->frame;
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        aura_h2_conn_enqueue_goaway(
          h2_c,
          h2_c->local_goaway_stream_id,
          rv,
          &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);
        return rv;
    }

    if (aura_h2_conn_stream_state_violation(h2_c, frame->stream_id, is_server)) {
        aura_h2_conn_enqueue_goaway(
          h2_c,
          h2_c->local_goaway_stream_id,
          A_H2_PROTOCOL_ERR,
          &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);
        return rv;
    }

    stream = aura_h2_conn_find_stream(h2_c, frame->stream_id);
    if (!stream)
        return A_H2_ERR_NONE;

    aura_h2_stream_destroy(stream, is_server);
    h2_c->nr_closed_streams++;

    return A_H2_ERR_NONE;
}

/**
 *
 */
int aura_h2_conn_process_wind_update(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                                     bool is_server) {
    struct aura_h2_window_update_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int rv;
    bool is_stream_level;
    const struct aura_iovec *reason;

    frame = &in_frame->frame;
    is_stream_level = frame->stream_id != 0;
    rv = aura_h2_parse_frame_payload(in_frame);

    if (rv == A_H2_FRAME_SIZE_ERR) {
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    if (rv == A_H2_PROTOCOL_ERR) {
        if (is_stream_level) {
            stream = aura_h2_conn_find_stream(h2_c, frame->stream_id);
            if (!stream) {
                /* Look in map */
                /* Penalize if rst was received */

                return A_H2_ERR_NONE;
            }

            aura_h2_conn_send_stream_error(h2_c, stream, rv, is_server);
            /* Do not end processing on stream error */
            return A_H2_ERR_NONE;
        }

        /* Connection level error */
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    /* connection level update */
    if (!is_stream_level) {
        rv = a_update_window_size((int64_t *)&h2_c->peer_window_size, payload.increment);
        if (rv != A_H2_ERR_NONE) {
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
            goto goaway;
        }
        return A_H2_ERR_NONE;
    }

    if (!aura_h2_conn_stream_state_violation(h2_c, frame->stream_id, is_server)) {
        stream = aura_h2_conn_find_stream(h2_c, frame->stream_id);
        if (!stream) {
            /* Look at hash */
            /* Penalize if breaking rules */

            return A_H2_ERR_NONE;
        }

        rv = A_H2_PROTOCOL_ERR;
        goto goaway;
    }
    /* update stream window */
    rv = a_update_stream_peer_window_size(stream, payload.increment);
    if (rv != 0) {
        aura_h2_conn_send_stream_error(h2_c, stream, rv, is_server);
    }
    return A_H2_ERR_NONE;

goaway:
    aura_h2_conn_enqueue_goaway(
      h2_c,
      h2_c->local_goaway_stream_id,
      rv,
      reason);
    return rv;
}

int aura_h2_conn_process_cont(struct aura_h2_core *h2_c, struct aura_h2_in_frame *in_frame,
                              bool is_server) {
    struct aura_h2_stream *stream;
    size_t avail_read;
    uint8_t *read_ptr;
    const struct aura_iovec *reason;
    int rv;

    rv = A_H2_ERR_NONE;
    /* Check if we expect continuation frame */
    if ((h2_c->flags & A_H2_CORE_FLAG_CONT) == 0) {
        rv = A_H2_PROTOCOL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    stream = aura_h2_conn_find_stream(h2_c, in_frame->frame.stream_id);
    if (!stream || !(stream->flags & A_H2_STREAM_FLAG_CONT)) {
        rv = A_H2_PROTOCOL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    stream->received_headers += in_frame->cont_payload.len;
    if (avail_read + in_frame->frame.len > A_MAX_REQ_LEN) {
        aura_h2_conn_send_stream_error(h2_c, stream, A_H2_REFUSED_STREAM_ERR, is_server);
        return A_H2_ERR_NONE;
    }

    // if (aura_sliding_buf_append(h2_conn->headers_to_parse, in_frame->frame.payload, in_frame->frame.len) < 0) {
    //     rv = A_H2_INTERNAL_ERR;
    //     reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
    //     goto goaway;
    // }

    if (in_frame->frame.flags & A_H2_FRAME_FLAG_END_HEADERS) {
        stream->flags &= ~A_H2_STREAM_FLAG_CONT;
        stream->flags |= A_H2_STREAM_FLAG_HDRS_RECD;
    }

    return rv;

goaway:
    aura_h2_conn_enqueue_goaway(
      h2_c,
      h2_c->local_goaway_stream_id,
      rv,
      reason);
    return rv;
}

int aura_h2_conn_after_frame_sent(struct aura_h2_core *h2_c, uint32_t stream_id,
                                  int type, size_t nbytes, bool end_stream) {
    struct aura_rh_map_key key;
    struct aura_h2_stream *stream;
    bool stream_closed;

    if (type == A_H2_SCHED_DATA) {
        aura_rh_map_key_init(&key, stream_id, sizeof(uint32_t), A_RH_KEY_U64);
        stream = aura_rh_map_get(&h2_c->stream_map, &key);

        aura_h2_conn_consume_window(h2_c, nbytes);
        aura_h2_stream_consume_window(stream, nbytes);

        if (end_stream) {
            stream_closed = stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;

            if (stream_closed) {
                aura_rh_map_key_init(&key, (uint64_t)stream->stream_id, sizeof(uint64_t), A_RH_KEY_U64);
                aura_rh_map_del(&h2_c->stream_map, &key, NULL);
                aura_h2_stream_destroy(stream, true);
            }
        }
        return 0;
    }

    if (type == A_H2_SCHED_HDR) {
        if (end_stream) {
            aura_rh_map_key_init(&key, stream_id, sizeof(uint32_t), A_RH_KEY_U64);
            stream = aura_rh_map_get(&h2_c->stream_map, &key);

            stream_closed = stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;

            if (stream_closed) {
                // aura_rh_map_key_init(&key, (uint64_t)stream->stream_id, sizeof(uint64_t), A_RH_KEY_U64);
                aura_rh_map_del(&h2_c->stream_map, &key, NULL);
                aura_h2_stream_destroy(stream, true);
            }
        }
        return 0;
    }

    return 0;
}

static void inline a_h2_stream_remove_from_heap(struct aura_h2_sched2 *sched, struct aura_h2_stream *s) {
    A_BUG_ON_2(s->queued == false, true);

    aura_heap_del(&sched->queues.stream_heap[s->prio.urgency], &s->hp_ent);
}

/* ============================================ */
static int a_h2_conn_update_stream_priority(struct aura_h2_core *h2_c,
                                            struct aura_h2_stream *stream,
                                            struct aura_pri_ext *prio) {
    if (stream->prio.incremental == prio->incremental &&
        stream->prio.urgency == prio->urgency)
        return 0;
}