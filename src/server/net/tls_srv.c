#include "tls_srv.h"
#include "socket_srv.h"
#include "utils_lib.h"

int aura_tls_send_close_notify(ptls_t *ptls, int sock_fd) {
    ptls_buffer_t send_buf;
    char buf[32];

    memset(buf, 0, sizeof(buf));
    ptls_buffer_init(&send_buf, buf, sizeof(buf));
    ptls_send_alert(ptls, &send_buf, PTLS_ALERT_LEVEL_FATAL, PTLS_ALERT_CLOSE_NOTIFY);

    return aura_write(sock_fd, send_buf.base, send_buf.off);
}

int aura_tls_input_decode(ptls_t *ptls, struct aura_sliding_buf *buf, bool *close_notify) {
    char *src, *write_ptr;
    ptls_buffer_t plain_buf;
    size_t consumed, avail_write, off, len;
    int rv;

    app_debug(true, 0, ">>>> aura_tls_input_decode");
    /* Mutate inplace */
    write_ptr = buf->data; /* @todo: move to inline fn call */
    avail_write = aura_sliding_buf_cap(buf);

    ptls_buffer_init(&plain_buf, write_ptr, avail_write);
    off = 0;

    len = aura_sliding_buf_read_len(buf);
    src = aura_sliding_buf_read_ptr(buf);
    aura_hex_dump_syslog(LOG_DEBUG, "aura[]", (void *)src, len);

    do {
        src = aura_sliding_buf_read_ptr(buf);
        consumed = len;

        rv = ptls_receive(ptls, &plain_buf, src, &consumed);
        if (rv != 0)
            break;
        len -= consumed;
        aura_sliding_buf_consume(buf, consumed);
    } while (len > 0);
    app_debug(true, 0, "aura_tls_input_decode rv = 0x%x", rv);

    *close_notify = false;
    if (rv == (PTLS_ERROR_CLASS_PEER_ALERT + PTLS_ALERT_CLOSE_NOTIFY)) {
        *close_notify = true;
        app_debug(true, 0, "RECEIVED CLOSE NOTIFY");
    }

    if (plain_buf.is_allocated) {
        if (plain_buf.off == 0)
            return -1;

        aura_sliding_buf_reset(buf);
        if (aura_sliding_buf_append(buf, plain_buf.base, plain_buf.off) < 0)
            return -1;

        ptls_buffer_dispose(&plain_buf);
    } else {
        aura_sliding_buf_reset(buf);
        buf->end = plain_buf.off;
    }

    rv = PTLS_ERROR_TO_ALERT(rv);

    /* Client initiates clean tls teardown */
    if (rv != PTLS_ALERT_CLOSE_NOTIFY)
        return -1;

    return 0;
}

static int64_t a_generate_tls_record(ptls_t *ptls, struct aura_sliding_buf *scratch_buf,
                                     struct aura_sliding_buf *enc_buf) {
    uint64_t scratch_rd_len, wrt_len;
    uint8_t *wrt_ptr, *scratch_ptr;
    ptls_buffer_t wrt_buf;
    int rv;

    app_debug(true, 0, ">>>> a_generate_tls_record");
    scratch_rd_len = aura_sliding_buf_read_len(scratch_buf);
    scratch_ptr = aura_sliding_buf_read_ptr(scratch_buf);
    if (scratch_rd_len > wrt_len) {
        /* Accomodate whatever is possible */
        scratch_rd_len = wrt_len;
    }

    wrt_ptr = aura_sliding_buf_write_ptr(enc_buf);
    wrt_len = aura_sliding_buf_write_len(enc_buf);

    ptls_buffer_init(&wrt_buf, wrt_ptr, wrt_len);

    rv = ptls_send(ptls, &wrt_buf, scratch_ptr, scratch_rd_len);
    app_debug(true, 0, "a_generate_tls_record: ptls_send err: 0x%x", rv);
    if (rv != 0) {
        return -1;
    }

    if (wrt_buf.is_allocated) {
        app_debug(true, 0, "a_generate_tls_record: encrypt allocated");
    }
    aura_sliding_buf_commit(enc_buf, wrt_buf.off);
    aura_sliding_buf_consume(scratch_buf, scratch_rd_len);
    /* compact just incase */
    aura_sliding_buf_compact(scratch_buf);

    return 0;
}

int64_t aura_tls_encode(struct aura_tls_ctx *tls, struct aura_mem_ctx *mc,
                        struct aura_h2_sched_iov *s_iov, bool *done, bool final) {
    static const size_t MAX_REC_PAYLOAD_SZ = 16 * 1024;
    static const size_t LARGE_REC_OVERHEAD = 5 + 32;
    uint8_t *wrt_ptr;
    uint32_t wrt_len, scratch_rd_len;
    int64_t ret_val;
    int rv;

    wrt_ptr = aura_sliding_buf_write_ptr(&tls->encrypted_write_buf);
    wrt_len = aura_sliding_buf_write_len(&tls->encrypted_write_buf);

    app_debug(true, 0, ">>>> aura_tls_encode");
    if (!wrt_ptr) {
        if (aura_sliding_buf_init(
              &tls->encrypted_write_buf,
              mc,
              MAX_REC_PAYLOAD_SZ + LARGE_REC_OVERHEAD,
              A_SLIDING_BUF_FL_COMPACTABLE) < 0)
            return -1;
        wrt_len = aura_sliding_buf_write_len(&tls->encrypted_write_buf);
    }

    if (!tls->scratch_buf) {
        tls->scratch_buf = aura_sliding_buf_create(
          mc,
          A_SUGGESTED_TLS_RECORD_PAYLOAD_SZ - tls->record_overhead,
          A_SLIDING_BUF_FL_COMPACTABLE);
        if (!tls->scratch_buf)
            return -1;
    }

    scratch_rd_len = aura_sliding_buf_read_len(tls->scratch_buf);
    if (scratch_rd_len > wrt_len && wrt_len < A_TLS_SLICE_FLOOR) {
        /* Trigger flush */
        return 0;
    }

    /**
     * Since there is not yet a way to detech the final s_iov,
     * 'final' is used when the flush queue has processed all
     * its payloads to handle any residual encoding left in
     * the scratch buffer. And as suc s_iov is NULL when 'final'.
     * The 'else' case encodes everytime the scratch buffer
     * can no longer accomodate anymore data.
     */
    if (final) {
        app_debug(true, 0, ">>>> aura_tls_encode final");
        *done = true;
        return a_generate_tls_record(tls->ptls, tls->scratch_buf, &tls->encrypted_write_buf);
    } else {
        ret_val = aura_h2_sched_iov_create_data(s_iov, tls->scratch_buf, done);

        /**
         * If encryption fails,whatever data was organised is
         * represented by ret_val, and as such, can be safely
         * removed and s_iov discarded. Or perhaps no need since
         * we consider it fatal anyway.
         */
        if (ret_val == 0)
            if (a_generate_tls_record(tls->ptls, tls->scratch_buf, &tls->encrypted_write_buf) < 0) {
                // aura_sliding_buf_uncommit(tls->scratch_buf, ret_val);
                return -1;
            }

        /* Otherwise, return the data len encrypted on the s_iov */
        return ret_val;
    }
}

void aura_tls_free(struct aura_tls_ctx *tls_ctx) {
    A_BUG_ON_2(tls_ctx->async.in_flight, true);
    A_BUG_ON_2(tls_ctx->async.w_buf.base, true);

    ptls_free(tls_ctx->ptls);
    aura_sliding_buf_destroy(&tls_ctx->encrypted_read_buf);
    aura_sliding_buf_destroy(&tls_ctx->encrypted_write_buf);
}