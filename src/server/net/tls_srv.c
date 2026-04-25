#include "tls_srv.h"
#include "h2/scheduler.h"
#include "utils_lib.h"

int aura_tls_input_decode(ptls_t *ptls, struct aura_sliding_buf *in_buf, struct aura_sliding_buf *out_buf) {
    app_debug(true, 0, ">>> aura_decode_tls_input");
    char *src, *write_ptr;
    ptls_buffer_t read_buf;
    size_t consumed, len, avail_write;
    int res;

    if (!aura_sliding_buffer_is_empty(in_buf)) {
        len = aura_sliding_buffer_available_read(in_buf);
        avail_write = aura_sliding_buffer_available_write(out_buf);
        write_ptr = aura_sliding_buffer_write_pointer(out_buf);

        if (!write_ptr) {
            /* initialize plainbuf for the first time */
            res = aura_sliding_buffer_ensure_capacity(out_buf, 16384);
            if (!res)
                return -1;
            avail_write = aura_sliding_buffer_available_write(out_buf);
            write_ptr = aura_sliding_buffer_write_pointer(out_buf);
        }

        ptls_buffer_init(&read_buf, write_ptr, avail_write);

        do {
            src = aura_sliding_buffer_read_pointer(in_buf);
            consumed = len;

            res = ptls_receive(ptls, &read_buf, src, &consumed);
            if (res != 0)
                break;
            len -= consumed;
            aura_sliding_buffer_consume(in_buf, consumed);
        } while (len > 0);

        if (read_buf.is_allocated) {
            len = aura_sliding_buffer_append(out_buf, read_buf.base, read_buf.off);
            if (len == 0)
                return -1;

            ptls_buffer_dispose(&read_buf);
        } else {
            aura_sliding_buffer_commit_write(out_buf, read_buf.off);
        }

        if (res == PTLS_ERROR_IN_PROGRESS)
            return PTLS_ERROR_IN_PROGRESS;

        if (res != 0)
            return -1;
    }

    return 0;
}

static inline int a_calculate_tls_payload_size(bool is_tls, size_t record_overhead, int suggested_tls_record_size) {
    uint16_t ps = suggested_tls_record_size;
    if (is_tls && record_overhead < ps)
        ps -= record_overhead;
    return ps;
}

/**
 * Calculate maybe optimal record size for wire transmission
 * taking into account record overhead for tls payloads
 */
static inline size_t calculate_tls_write_size(size_t record_overhead, size_t buf_size) {
    size_t rec_size;

    /** @todo: are there any other optimizations around tls record size */
    rec_size = a_calculate_tls_payload_size(false, record_overhead, 1400);
    return a_min(rec_size, buf_size);
}

/* Check if there is still tls data not sent */
static inline bool a_has_pending_tls_bytes(struct aura_tls_ctx *tls_ctx) {
    size_t avail_read;

    if (!tls_ctx)
        return false;

    return aura_sliding_buffer_available_read(tls_ctx->encrypted_write_buf);
}

/**
 * Generate tls records for line transmission from input buffer
 */
static size_t a_generate_tls_records_from_one_frame(struct aura_tls_ctx *tls_ctx, const void *input, size_t in_len) {
    static const size_t MAX_RECORD_PAYLOAD_SIZE = 16 * 1024;
    static const size_t LARGE_RECORD_OVERHEAD = 5 + 32;
    size_t tls_write_size, avail_write, rec_capacity;
    uint8_t *write_ptr;
    ptls_buffer_t write_buf;
    int res;

    tls_write_size = calculate_tls_write_size(tls_ctx->record_overhead, in_len);
    avail_write = aura_sliding_buffer_available_write(tls_ctx->encrypted_write_buf);
    write_ptr = aura_sliding_buffer_write_pointer(tls_ctx->encrypted_write_buf);
    if (write_ptr == NULL) {
        res = aura_sliding_buffer_ensure_capacity(tls_ctx->encrypted_write_buf, a_max(tls_write_size, MAX_RECORD_PAYLOAD_SIZE + LARGE_RECORD_OVERHEAD)); /** @todo: check how to optimize this size */
        if (!res)
            return 0;
        write_ptr = aura_sliding_buffer_write_pointer(tls_ctx->encrypted_write_buf);
        avail_write = aura_sliding_buffer_available_write(tls_ctx->encrypted_write_buf);
    }

    if (tls_write_size < in_len) {
        /* Writing small TLS records, one by one bailing out on failure */
        if (avail_write < tls_write_size + LARGE_RECORD_OVERHEAD)
            return 0;
    } else {
        rec_capacity = 1;
        tls_write_size = MAX_RECORD_PAYLOAD_SIZE * rec_capacity;
        if (tls_write_size > in_len)
            tls_write_size = in_len;
    }

    ptls_buffer_init(&write_buf, write_ptr, avail_write);
    res = ptls_send(tls_ctx->ptls, &write_buf, input, tls_write_size);
    if (res != 0)
        app_exit(true, 0, "Failed to encrypt tls record with error: %s", res);
    if (write_buf.is_allocated) {
        app_debug(true, 0, ">>>> Allocated ptls buffer for ptls_send");
    }
    aura_sliding_buffer_commit_write(tls_ctx->encrypted_write_buf, write_buf.off);

    return tls_write_size;
}

/* Encrypts plain data into tls records for wire transmission */
static int a_generate_tls_records(struct aura_tls_ctx *tls_ctx, struct aura_list_head *head) {
    size_t bytes_newly_written;
    size_t avail_len, offset;
    uint8_t *read_ptr;
    struct aura_h2_send_iov *send_iov;
    int rv = 0;

    /* Ensure tls buffer is cleared before next generation */
    A_BUG_ON_2(a_has_pending_tls_bytes(tls_ctx), true);

    while (!a_list_is_empty(head)) {
        a_list_dequeue(send_iov, head, list);
        avail_len = send_iov->iov.iov_len;

        offset = 0;
        while (avail_len > 0) {
            bytes_newly_written = a_generate_tls_records_from_one_frame(tls_ctx, send_iov->iov.iov_base + offset, avail_len);
            if (bytes_newly_written == 0) {
                rv = -1;
                break;
            }
            avail_len -= bytes_newly_written;
        }
        aura_sliding_buffer_consume(send_iov->buf, bytes_newly_written);
        /* Free send_iov */
        if (avail_len == 0) {
            aura_free(send_iov);
        }
    }

    return rv;
}

ssize_t aura_tls_input_encode(struct aura_tls_ctx *tls_ctx, struct aura_list_head *head) {
    ssize_t encrypted_written;
    uint8_t *read_ptr;
    size_t write_len;
    ptls_buffer_t *w_buf;

    if (a_list_is_empty(head))
        return 0;
    app_debug(true, 0, "aura_tls_input_encode <<< ");

    if (a_generate_tls_records(tls_ctx, head) < 0)
        return -1;

    if (!a_has_pending_tls_bytes(tls_ctx)) {
        /* nothing to write */
        return 0;
    }

    write_len = aura_sliding_buffer_available_read(tls_ctx->encrypted_write_buf);

    return write_len;
}

static inline void a_tls_out_buf_dispose(struct aura_tls_ctx *tls_ctx) {
    aura_sliding_buffer_destroy(tls_ctx->encrypted_read_buf);
    aura_sliding_buffer_destroy(tls_ctx->encrypted_write_buf);
}

void aura_tls_free(struct aura_tls_ctx *tls_ctx) {
    A_BUG_ON_2(tls_ctx->async.in_flight, true);
    A_BUG_ON_2(tls_ctx->async.w_buf.base, true);

    ptls_free(tls_ctx->ptls);
    a_tls_out_buf_dispose(tls_ctx);

    aura_free(tls_ctx);
}