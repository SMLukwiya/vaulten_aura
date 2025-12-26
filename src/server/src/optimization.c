#define _GNU_SOURCE
#include "connection.h"
#include "optimization_srv.h"
#include "socket_srv.h"

void aura_calculate_optimal_record_size(struct aura_tls_record_config *config) {
    uint16_t mtu;

    mtu = config->tcp_mss ? config->tcp_mss : A_ETHERNET_MTU - (config->is_ipv6 ? A_TCP_V6_HEADER_SIZE : A_TCP_V4_HEADER_SIZE);
    switch (config->strategy) {
    case A_TLS_SIZE_CONSERVATIVE:
        config->optimal_cipher_text = mtu;
        config->optimal_plaintext = mtu - A_TLS_RECORD_OVERHEAD;
        break;

    case A_TLS_SIZE_AGGRESSIVE:
        config->optimal_plaintext = 16384;
        config->optimal_cipher_text = config->optimal_plaintext + A_TLS_RECORD_OVERHEAD;
        break;

    case A_TLS_SIZE_DYNAMIC:
        /* Adapt based on network condition */
        if (config->rtt_us > 100000) {
            /* High Latency > 100ms */
            config->optimal_plaintext = 8192;
        } else if (config->loss_rate > 0.01) {
            /* Lossy network */
            config->optimal_plaintext = 1024;
        } else {
            /* Good network */
            config->optimal_plaintext = mtu - A_TLS_RECORD_OVERHEAD;
        }
        config->optimal_cipher_text = config->optimal_plaintext + A_TLS_RECORD_OVERHEAD;
        break;

    case A_TLS_SIZE_STREAMING:
        /* Streaming responses */
        config->optimal_plaintext = 4096;
        config->optimal_cipher_text = config->optimal_plaintext + A_TLS_RECORD_OVERHEAD;
        config->max_records_per_call = 8;
        break;
    }

    /* Maintain bounds */
    if (config->optimal_plaintext > A_TLS_MAX_PLAINTEXT) {
        config->optimal_plaintext = A_TLS_MAX_PLAINTEXT;
        config->optimal_cipher_text = A_TLS_MAX_PLAINTEXT + A_TLS_RECORD_OVERHEAD;
    }
}

/**/
static inline struct aura_tls_record_batch *a_tls_record_batch_create(struct aura_memory_ctx *mc) {
    struct aura_tls_record_batch *batch;

    batch = aura_alloc(mc, sizef(*batch));
    if (!batch)
        return NULL;

    a_list_head_init(&batch->record_list);
    batch->cnt = 0;
    batch->iovecs = NULL;
    batch->iovec_cnt = 0;
    batch->iov_ready = false;
    batch->total_plaintext = 0;
    batch->total_ciphertext = 0;

    return batch;
}

static inline void a_destroy_tls_record_batch(struct aura_tls_record_batch *batch) {
    /**/
}

/**/
struct aura_tls_record *a_tls_record_create(struct aura_memory_ctx *mc, struct aura_tls_record_config *config) {
    struct aura_tls_record *record;
    size_t plaintext_cap, ciphertext_cap;
    bool res;

    record = aura_alloc(mc, sizeof(*record));
    if (!record)
        return NULL;
    a_list_head_init(&record->t_list);
    /* permit some head room */
    plaintext_cap = config->optimal_plaintext + 256;
    ciphertext_cap = config->optimal_cipher_text + 256;

    res = aura_sliding_buffer_create(mc, &record->plaintext, plaintext_cap);
    if (res == false) {
        aura_free(record);
        return NULL;
    }

    res = aura_sliding_buffer_create(mc, &record->ciphertext, ciphertext_cap);
    if (res == false) {
        aura_free(record);
        aura_sliding_buffer_destroy(&record->plaintext);
        return NULL;
    }

    record->enqueued_at = aura_now_ms();
    // record->needs_immediate_ack
    // record->priority
    return record;
}

/**
 * Encrypt plain text into tls text ready for wire
 * transmission. Each record is already in optimal tls
 * record size, so we encrypt as a whole!
 */
static inline bool a_tls_encrypt_record(struct aura_sock_tls_ctx *tls_ctx, struct aura_tls_record *record) {
    ptls_buffer_t write_buf;
    uint8_t *write_ptr, *read_ptr;
    size_t avail_write, avail_read;
    int res;

    write_ptr = aura_sliding_buffer_write_pointer(&record->ciphertext);
    avail_write = aura_sliding_buffer_available_write(&record->ciphertext);
    read_ptr = aura_sliding_buffer_read_pointer(&record->plaintext);
    avail_read = aura_sliding_buffer_available_read(&record->plaintext);
    ptls_buffer_init(&write_buf, (void *)write_ptr, avail_write);

    res = ptls_send(tls_ctx->ptls, &write_buf, read_ptr, avail_read);
    if (res != 0)
        /* Hmmmmm! Exiting seems a little dramatic here, but i'm not sure */
        app_exit(true, 0, "Failed to encrypt tls record error: %d", res);

    if (write_buf.is_allocated) {
        aura_sliding_buffer_commit_write(&record->ciphertext, write_buf.off);
        aura_sliding_buffer_append(&record->ciphertext, write_buf.base, write_buf.off);
    } else {
        aura_sliding_buffer_commit_write(&record->ciphertext, write_buf.off);
    }

    return true;
}

struct aura_tls_record_batch *aura_frame_to_tls_records(struct aura_srv_sock *sock) {
    struct aura_h2_out_frame *out_frame;
    struct aura_tls_record_config *config;
    struct aura_tls_record_batch *batch;
    struct aura_tls_record *curr;
    size_t plaintext_in_record, frame_size;
    size_t data_remaining, data_offset, chunk;

    /* Ensure tls buffer is cleared before next generation */
    A_BUG_ON_2(a_has_pending_tls_bytes(sock), true);

    batch = a_tls_record_batch_create(sock->h2_conn->mc);
    if (!batch)
        return NULL;

    config = &sock->tls_ctx->tls_config;
    curr = NULL;
    for (;;) {
        out_frame = aura_schedule_next_frame(&sock->h2_conn->sender);
        if (!out_frame)
            break;

        /* Group control frames, usually small records, pack if possible */
        if (out_frame->frame.type != A_H2_FRAME_TYPE_DATA) {
            frame_size = out_frame->encoded.len;

            if (plaintext_in_record + frame_size <= config->optimal_plaintext) {
                /* Add to current record */
                if (!curr) {
                    curr = a_tls_record_create(sock->h2_conn->mc, config);
                    if (!curr)
                        goto err_out;
                }

                /* Append frame to records plaintext */
                aura_sliding_buffer_append(&curr->plaintext, out_frame->encoded.data, frame_size);
                /* consume from whatever buffer we are copying from */
                aura_sliding_buffer_consume(out_frame->buf, frame_size);
                plaintext_in_record += frame_size;
                batch->total_plaintext += frame_size;
                continue;
            }
        }

        /* Record has config data, encrypt and reset */
        if (curr) {
            a_tls_encrypt_record(sock->tls_ctx, curr);
            a_list_add_tail(&batch->record_list, &curr->t_list);
            batch->total_ciphertext += curr->ciphertext.end;
            plaintext_in_record = 0;
            curr = NULL;
        }

        /* Handle data frames as seperate record(s) (could span multiple records) */
        if (out_frame->frame.type == A_H2_FRAME_TYPE_DATA) {
            data_remaining = out_frame->data.payload_len;
            data_offset = 0;

            while (data_remaining > 0) {
                curr = a_tls_record_create(sock->h2_conn->mc, config);
                if (!curr)
                    goto err_out;
                chunk = a_min(data_remaining, config->optimal_plaintext);
                /* We shall reuse the header of the outframe */
                aura_encode_frame_header(
                  out_frame->data.header,
                  chunk, out_frame->frame.type,
                  out_frame->frame.flags & (chunk == data_remaining ? A_H2_FRAME_FLAG_END_STREAM : 0),
                  out_frame->frame.stream_id);
                /* Append header */
                aura_sliding_buffer_append(&curr->plaintext, out_frame->data.header, 9);
                aura_sliding_buffer_append(&curr->plaintext, out_frame->data.payload + data_offset, chunk);
                aura_sliding_buffer_consume(out_frame->buf, chunk);

                /* Encrypt immediatey for pipelining */
                a_tls_encrypt_record(sock->tls_ctx, curr);
                a_list_add_tail(&batch->record_list, &curr->t_list);

                batch->total_plaintext += 9 + chunk;
                batch->total_ciphertext += curr->ciphertext.end;
                data_offset += chunk;
                data_remaining -= chunk;
                memset(out_frame->data.header, 0, 9);
                curr = NULL;
            }
        } else {
            /* Weird large control frame, get its own record */
            curr = a_tls_record_create(sock->h2_conn->mc, config);
            if (!curr)
                goto err_out;
            aura_sliding_buffer_append(&curr->plaintext, out_frame->encoded.data, out_frame->encoded.len);

            a_tls_encrypt_record(sock->tls_ctx, curr);
            a_list_add_tail(&batch->record_list, &curr->t_list);

            batch->total_plaintext += out_frame->encoded.len;
            batch->total_ciphertext += curr->ciphertext.end;
            curr = NULL;
        }
    }

    A_BUG_ON_2(curr != NULL, true);

    /* count records */
    a_list_for_each(curr, &batch->record_list, t_list) {
        batch->cnt++;
    }

    /* Prepare for vectorized IO */
    a_prepare_batch_for_vector_io(sock->h2_conn->mc, batch);
    return batch;

err_out:
    a_destroy_tls_record_batch(batch);
    return NULL;
}

/* Prepare for vectorized send */
void a_prepare_batch_for_vector_io(struct aura_memory_ctx *mc, struct aura_tls_record_batch *batch) {
    struct aura_tls_record *record;
    struct iovec _iov, *iov;
    size_t iov_idx;

    if (a_list_is_empty(&batch->record_list))
        return;

    iov = aura_alloc(mc, sizeof(*iov) * batch->cnt);
    if (!iov)
        return;

    iov_idx = 0;
    a_list_for_each(record, &batch->record_list, t_list) {
        _iov = aura_sliding_buffer_get_read_iovec(&record->plaintext, SIZE_MAX);
        batch->iovecs[iov_idx].iov_base = _iov.iov_base;
        batch->iovecs[iov_idx].iov_len = _iov.iov_len;
        iov_idx++;
    }
    batch->iovec_cnt = iov_idx;
    batch->iov_ready = true;
}

/**
 * Send vectorized records using writev
 */
ssize_t aura_tls_send_vectorized(int sock_fd, struct aura_tls_record_batch *batch) {
    ssize_t bytes_written;

    if (batch->iovec_cnt == 0)
        return 0;

    do {
        bytes_written = writev(sock_fd, batch->iovecs, batch->iovec_cnt);
    } while (bytes_written == -1 && (errno == EWOULDBLOCK || errno == EAGAIN));

    return bytes_written;
}

struct msghdr *a_prepare_batch_for_sendmsg(struct aura_memory_ctx *mc, struct aura_tls_record_batch *batch) {
    struct msghdr *msghdr;
    struct aura_tls_record *record;
    size_t msg_cnt;

    if (!batch->iov_ready) {
        a_prepare_batch_for_vector_io(mc, batch);
        if (!batch->iov_ready)
            return NULL;
    }

    msghdr = aura_alloc(mc, sizeof(*msghdr));
    if (!msghdr)
        return NULL;
    msghdr->msg_iov = batch->iovecs;
    msghdr->msg_iovlen = batch->iovec_cnt;

    return msghdr;
}

/**
 * Send vectorized records using sendmsg
 */
ssize_t aura_tls_send_msg(int sock_fd, struct aura_memory_ctx *mc, struct aura_tls_record_batch *batch) {
    struct msghdr *msghdr;
    int bytes_sent;
    int cork;

    if (batch->cnt == 0)
        return 0;

    cork = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

    msghdr = a_prepare_batch_for_sendmsg(mc, batch);
    if (!msghdr)
        return 0;

    do {
        bytes_sent = sendmsg(sock_fd, msghdr, 0);
    } while (bytes_sent == -1 && (errno == EWOULDBLOCK || errno == EAGAIN));

    cork = 0;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

    aura_free(msghdr);
    return bytes_sent;
}

bool aura_adapt_tls_record_size(struct aura_h2_conn *conn, struct aura_tls_record_config *config) {
#if defined(__linux__) && defined(TCP_INFO)
    struct tcp_info tcpi;
    socklen_t tcp_info_sz;
    int res;

    tcp_info_sz = sizeof(tcpi);
    res = getsockopt(conn->sock->sock_fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tcp_info_sz);
    if (res != 0)
        return false;

    config->rtt_us = tcpi.tcpi_rtt;
    config->tcp_mss = tcpi.tcpi_snd_mss;

    if (tcpi.tcpi_retrans > 0) {
        config->loss_rate = (config->loss_rate * 0.9) + (tcpi.tcpi_retrans * 0.1);
    } else {
        /* decay */
        config->loss_rate *= 0.95;
    }

    /* Detect mobile network, high jitter and high latency */
    if (tcpi.tcpi_rttvar > 10000 || tcpi.tcpi_rtt > 200000) {
        config->is_mobile = true;
    }

    aura_calculate_optimal_record_size(config);

    if (config->optimal_plaintext != conn->last_record_size) {
        app_debug(true, 0, "TLS record size adapted: %u -> %u, (RTT: %uus, loss_rate: %.2f%%)",
                  conn->last_record_size, config->optimal_plaintext, config->rtt_us, config->loss_rate * 100);
        conn->last_record_size = config->optimal_plaintext;
    }
    return true;
#else
    return false;
#endif
}