#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "socket_srv.h"
#include "bug_lib.h"
#include "error_lib.h"
#include "evt_loop_srv.h"
#include "h2/h2_srv.h"
#include "h2/scheduler.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <netinet/tcp.h>

#define USE_ACCEPT_4 1

static void a_free_tls(struct aura_sock_tls_ctx *tls);

const struct aura_iovec aura_h2_alpn_protocols[] = {A_H2_APLN_PROTOCOLS};

static inline int a_set_no_tcp_delay_opt(int fd) {
    int on = 1;
    return setsockopt(fd, IPPROTO_IP, TCP_NODELAY, &on, sizeof(on));
}

/**
 * Retrieve sock cache and allocate a slot
 */
static inline struct aura_srv_sock *a_sock_alloc(struct aura_memory_ctx *mc) {
    struct aura_slab_cache *sc;
    struct aura_srv_sock *sock;

    sc = NULL;
    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_ID_SOCK);

    A_BUG_ON_2(!sc, true);
    sock = aura_slab_alloc(sc);
    return sock;
}

struct aura_srv_sock *aura_socket_create(struct aura_memory_ctx *mc, int fd, struct sockaddr *addr, socklen_t addr_len, int flags) {
    struct aura_srv_sock *sock;

    sock = a_sock_alloc(mc);
    if (!sock)
        return NULL;

    sock->tls_ctx = aura_alloc(mc, sizeof(*(sock->tls_ctx)));
    if (!sock->tls_ctx)
        goto exception_sock;
    memset(sock->tls_ctx, 0, sizeof(*sock->tls_ctx));

    memcpy(&sock->addr, addr, sizeof(*addr));
    sock->sock_fd = fd;
    sock->sock_len = addr_len;
    sock->flags = flags;
    sock->tls_ctx->ptls = NULL;
    sock->in_active = false;
    // sock->is_idle = false;
    sock->in_reap = false;

    bool res_pr = aura_sliding_buffer_create(mc, &sock->plain_read_buf, 0);
    bool res_pw = aura_sliding_buffer_create(mc, &sock->plain_write_buf, 0);
    if (!res_pr || !res_pw)
        goto exception_tls;

    bool res_er = aura_sliding_buffer_create(mc, &sock->tls_ctx->encrypted_read_buf, 4096);
    bool res_ew = aura_sliding_buffer_create(mc, &sock->tls_ctx->encrypted_write_buf, 0);
    if (!res_er || !res_ew)
        goto exception_buf;

    a_list_head_init(&sock->s_list);
    aura_set_fd_flag(sock->sock_fd, O_NONBLOCK | SOCK_NONBLOCK);

    return sock;

exception_buf:
    aura_sliding_buffer_destroy(&sock->tls_ctx->encrypted_read_buf);
    aura_sliding_buffer_destroy(&sock->tls_ctx->encrypted_write_buf);
exception_tls:
    aura_sliding_buffer_destroy(&sock->plain_read_buf);
    aura_sliding_buffer_destroy(&sock->plain_write_buf);
    aura_free(sock->tls_ctx);
exception_sock:
    aura_slab_free(sock);
    return NULL;
}

/**
 *
 */
static inline void a_dispose_sock_plain_buf(struct aura_srv_sock *sock) {
    aura_sliding_buffer_destroy(&sock->plain_read_buf);
    aura_sliding_buffer_destroy(&sock->plain_write_buf);
}

static inline void a_dispose_tls_out_buf(struct aura_sock_tls_ctx *tls_ctx) {
    aura_sliding_buffer_destroy(&tls_ctx->encrypted_read_buf);
    aura_sliding_buffer_destroy(&tls_ctx->encrypted_write_buf);
}

/** */
static void a_free_tls(struct aura_sock_tls_ctx *tls_ctx) {
    assert(!tls_ctx->async.in_flight);
    assert(tls_ctx->async.w_buf.base == NULL);

    ptls_free(tls_ctx->ptls);
    a_dispose_tls_out_buf(tls_ctx);

    aura_free(tls_ctx);
}

/** */
static inline void aura_socket_destroy(struct aura_srv_sock *sock) {
    app_debug(true, 0, "aura_socket_destroy <<<");
    if (sock->tls_ctx)
        a_free_tls(sock->tls_ctx);
    a_dispose_sock_plain_buf(sock);

    if (sock->h2_conn)
        aura_h2_connection_destroy(sock->h2_conn);
    close(sock->sock_fd);
    aura_slab_free(sock);
}

struct aura_srv_sock *aura_socket_accept(struct aura_memory_ctx *mc, int sock_fd, int flags) {
    int cli_fd, res;
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    struct aura_srv_sock *sock;

#ifdef USE_ACCEPT_4
    cli_fd = accept4(sock_fd, (struct sockaddr *)&cli_addr, &cli_len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (cli_fd < 0)
        return NULL;
#else
    if ((cli_fd = accept(server->sock_fd, (struct sockaddr *)&cli_addr, &cli_len)) < 0)
        return NULL;
    aura_set_fd_flag(cli_fd, O_NONBLOCK);
    aura_set_fd_flag(cli_fd, FD_CLOEXEC);
#endif
    sock = aura_socket_create(mc, cli_fd, (struct sockaddr *)&cli_addr, cli_len, flags);
    if (!sock)
        return NULL;
    res = a_set_no_tcp_delay_opt(sock->sock_fd);
    if (res != 0) {
        sys_debug(true, errno, "aura_socket_accept: aura_socket_create fd=%d:", cli_fd);
        return NULL;
    }

    if (sock->tls_ctx) {
        sock->state = A_SOCK_STATE_HANDSHAKE;
    } else {
        sock->state = A_SOCK_STATE_ESTABLISHED;
    }
    /* initialize connection state */
    ptls_log_init_conn_state(a_get_conn_log_state(sock), ptls_openssl_random_bytes);

    return sock;
}

static inline bool a_wave_can_continue(struct aura_srv_wave_ctx *wc) {
    uint64_t now_us = aura_now_us(CLOCK_MONOTONIC);

    if (now_us - wc->tick_start >= wc->max_epoch_usec) {
        wc->time_expired = true;
        return false;
    }

    // if (wc->all_processed >= wc->max_processed)
    //     return false;

    // if (has_critical_work())
    //     return true;

    if (wc->latency_processed > 10)
        return true;

    return false;
}

static inline void a_srv_wave_ctx_init(struct aura_srv_wave_ctx *wc, struct aura_srv_ctx *srv_ctx) {
    memset(wc, 0, sizeof(*wc));
    wc->srv_ctx = srv_ctx;
}

static inline void a_srv_wave_ctx_reset(struct aura_srv_wave_ctx *wc) {
    wc->wave_cnt = 0;
    wc->max_wave = 4;
    wc->max_critical = 64;
    wc->max_latency = 128;
    wc->max_epoch_usec = 2000; // 2ms
    wc->max_tp_bytes_per_wave = 65336;
    wc->all_processed = 0;
    wc->critical_processed = 0;
    wc->latency_processed = 0;
    wc->tick_start = aura_now_us(CLOCK_MONOTONIC);
    wc->no_new_critical = true;
    wc->critical_empty = true;
}

// void aura_process_active_queue(st_aura_evt_loop *evt_loop) {
void aura_process_active_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_srv_sock *sock;
    int res;

    while (!a_list_is_empty(&srv_ctx->queues.active)) {
        a_list_dequeue(sock, &srv_ctx->queues.active, s_list);

        switch (sock->state) {
        case A_SOCK_STATE_HANDSHAKE:
            res = aura_handle_handshake(sock, srv_ctx);
            if (res != A_PROGRESS_DONE)
                break;
        case A_SOCK_STATE_ESTABLISHED:
            res = aura_h2_proceed(sock, srv_ctx);
            break;
        default:
            break;
        }

        if (res == A_PROGRESS_BLOCKED)
            sock->is_idle = true;
        else {
            srv_ctx->evt_loop->ops->remove(srv_ctx->evt_loop, sock->sock_fd);
            a_list_add_tail(&srv_ctx->queues.reap, &sock->s_list);
            sock->state = A_SOCK_STATE_CLOSED;
            sock->in_reap = true;
            sock->in_active = false;
        }
    }
}

void aura_process_reap_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_srv_sock *sock;
    int res;

    while (!a_list_is_empty(&srv_ctx->queues.reap)) {
        app_debug(true, 0, "Reaping socket with fd: %d", sock->sock_fd);
        /* @todo: remove from timer */
        a_list_dequeue(sock, &srv_ctx->queues.reap, s_list);

        aura_socket_destroy(sock);
    }
}

/** */
void aura_process_in_ready_queue(st_aura_evt_loop *evt_loop) {
    struct aura_srv_wave_ctx wc;

    a_srv_wave_ctx_reset(&wc);
    do {
        wc.wave_cnt++;

        // a_process_critical_queue(&wc);
        // a_process_latency_queue(evt_loop->srv_ctx);
        // a_process_throughput_queue(evt_loop->srv_ctx);
        // a_process_maintenance_queue(evt_loop->srv_ctx); // maintenance only when idle
    } while (a_wave_can_continue(&wc));
}

/**/
// static void a_process_critical_queue(struct aura_srv_wave_ctx *wc) {
//     struct aura_srv_sock *sock;
//     struct aura_list_head *head;

//     head = &wc->srv_ctx->queues.critical;
//     while (!a_list_is_empty(head)) {
//         a_list_dequeue(sock, head, s_list);

//         if (sock->flags & A_SOCK_CLOSED) {
//             a_list_add_tail(&wc->srv_ctx->queues.maintenance, &sock->s_list);
//             // if (sock->h2_conn)
//             //     aura_h2_conn_destroy(sock->h2_conn);

//             // aura_socket_destroy(sock);
//             continue;
//         }

//         aura_h2_proceed(sock, wc->srv_ctx);
//     }
// }

/**/
// static void a_process_latency_queue(struct aura_srv_wave_ctx *wc) {
//     struct aura_srv_sock *sock;
//     struct aura_list_head *head;

//     head = &wc->srv_ctx->queues.latency;
//     while (!a_list_is_empty(head)) {
//         a_list_dequeue(sock, head, s_list);
//         if (sock->flags & A_SOCK_HANDSHAKE) {
//             aura_handle_handshake(sock, wc->srv_ctx);
//             continue;
//         }

//         aura_h2_proceed(sock, wc->srv_ctx);
//     }
// }

/**
 *
 */
ssize_t aura_read(int fd, void *buf, size_t len) {
    ssize_t n_read;

    do {
        n_read = recv(fd, buf, len, 0);
    } while (n_read == -1 && errno == EINTR);

    if (n_read == -1) {
        if (errno == EWOULDBLOCK) {
            return 0;
        } else {
            return -1;
        }
    }

    if (n_read == 0) {
        sys_debug(true, errno, "Client closed conn : %d", errno);
        return -1;
    }

    return n_read;
}

/**
 *
 */
ssize_t aura_write(int fd, void *buf, size_t len) {
    ssize_t n_written;

    do {
        n_written = send(fd, buf, len, 0);
    } while (n_written == -1 && errno == EINTR);

    if (n_written == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }

        sys_debug(true, errno, "aura write error");
        return -1;
    }

    if (n_written == 0) {
        sys_debug(true, errno, "write side closed");
        return -1;
    }

    return n_written;
}

/**
 *
 */
static inline int calculate_tls_payload_size(struct aura_srv_sock *sock, int suggested_tls_record_size) {
    uint16_t ps = suggested_tls_record_size;
    if (sock->tls_ctx != NULL && sock->tls_ctx->record_overhead < ps)
        ps -= sock->tls_ctx->record_overhead;
    return ps;
}

/**
 *
 */
static inline size_t calculate_tls_write_size(struct aura_srv_sock *sock, size_t buf_size) {
    size_t rec_size;

    /** @todo: are there any other optimizations around tls record size */
    rec_size = calculate_tls_payload_size(sock, 1400);
    return a_min(rec_size, buf_size);
}

static size_t a_generate_tls_records_from_one_frame(struct aura_srv_sock *sock, const void *input, size_t in_len) {
    static const size_t MAX_RECORD_PAYLOAD_SIZE = 16 * 1024;
    static const size_t LARGE_RECORD_OVERHEAD = 5 + 32;
    size_t tls_write_size, avail_write, rec_capacity;
    uint8_t *write_ptr;
    ptls_buffer_t write_buf;
    int res;

    tls_write_size = calculate_tls_write_size(sock, in_len);
    avail_write = aura_sliding_buffer_available_write(&sock->tls_ctx->encrypted_write_buf);
    write_ptr = aura_sliding_buffer_write_pointer(&sock->tls_ctx->encrypted_write_buf);
    if (write_ptr == NULL) {
        res = aura_sliding_buffer_ensure_capacity(&sock->tls_ctx->encrypted_write_buf, a_max(tls_write_size, MAX_RECORD_PAYLOAD_SIZE + LARGE_RECORD_OVERHEAD)); /** @todo: check how to optimize this size */
        if (!res)
            return 0;
        write_ptr = aura_sliding_buffer_write_pointer(&sock->tls_ctx->encrypted_write_buf);
        avail_write = aura_sliding_buffer_available_write(&sock->tls_ctx->encrypted_write_buf);
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
    res = ptls_send(sock->tls_ctx->ptls, &write_buf, input, tls_write_size);
    if (res != 0)
        app_exit(true, 0, "Failed to encrypt tls record with error: %s", res);
    if (write_buf.is_allocated) {
        app_debug(true, 0, ">>>> Allocated ptls buffer for ptls_send");
    }
    aura_sliding_buffer_commit_write(&sock->tls_ctx->encrypted_write_buf, write_buf.off);

    return tls_write_size;
}

/* Check if there is still tls data not sent */
static inline bool a_has_pending_tls_bytes(struct aura_srv_sock *sock) {
    size_t avail_read;

    if (!sock->tls_ctx)
        return false;

    return aura_sliding_buffer_available_read(&sock->tls_ctx->encrypted_write_buf);
}

/* Encrypts plain data into tls records for transmission over the wire */
static size_t a_generate_tls_records(struct aura_srv_sock *sock) {
    size_t bytes_newly_written, total_written;
    struct aura_h2_out_frame *out_frame;
    uint8_t read_ptr;

    /* Ensure tls buffer is cleared before next generation */
    A_BUG_ON_2(a_has_pending_tls_bytes(sock), true);

    while (true) {
        out_frame = aura_schedule_next_frame(&sock->h2_conn->sender);
        if (!out_frame)
            break;

        total_written = bytes_newly_written = 0;
        while (true) {
            // if (out_frame->frame.type == DATA) // construct iov with header and payload
            if (!out_frame->buf->valid) {
                /* stream likely reset */
                break;
            }
            bytes_newly_written = a_generate_tls_records_from_one_frame(sock, out_frame->encoded.data + total_written, out_frame->encoded.len - total_written);
            total_written += bytes_newly_written;
            if (total_written == out_frame->encoded.len || bytes_newly_written == 0)
                break;
        }
        aura_sliding_buffer_consume(out_frame->buf, total_written);
    }

    return total_written;
}

/**
 *
 */
static void a_flatten_vec_bytes() {}

ssize_t aura_sock_write_tls(struct aura_srv_sock *sock) {
    ssize_t tls_bytes_written, encrypted_written;
    uint8_t *read_ptr;
    size_t read_len;
    ptls_buffer_t *w_buf;

    tls_bytes_written = a_generate_tls_records(sock);

    if (!a_has_pending_tls_bytes(sock)) {
        /* nothing to write */
        return 0;
    }

    read_ptr = aura_sliding_buffer_read_pointer(&sock->tls_ctx->encrypted_write_buf);
    read_len = aura_sliding_buffer_available_read(&sock->tls_ctx->encrypted_write_buf);
    encrypted_written = aura_write(sock->sock_fd, read_ptr, read_len);
    if (encrypted_written == -1) {
        a_dispose_tls_out_buf(sock->tls_ctx);
        return -1;
    }

    aura_sliding_buffer_consume(&sock->tls_ctx->encrypted_write_buf, encrypted_written);

    /** @todo: check if all written, repeat write until all written */

    return encrypted_written;
}

static inline void aura_tls_shutdown(struct aura_srv_sock *sock) {
    ptls_buffer_t write_buf;
    uint8_t write_buf_small[32];
    int res;

    ptls_buffer_init(&write_buf, write_buf_small, sizeof(write_buf_small));
    res = ptls_send_alert(sock->tls_ctx->ptls, &write_buf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY);
    if (res != 0)
        return; /* @todo: return error */
    ptls_buffer_dispose(&write_buf);
}

/**
 *
 */
static inline void aura_handshake_complete(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx) {
    app_debug(true, 0, ">>>>aura_handshake_complete:");
    int res;
    size_t len;

    assert(!sock->tls_ctx->async.in_flight);
    assert(sock->tls_ctx->ptls);

    if (sock->tls_ctx->async.sock_closed) {
        // aura_tls_shutdown(sock);
        sock->state = A_SOCK_STATE_CLOSED;
        return;
    }

    sock->state = A_SOCK_STATE_ESTABLISHED;
    sock->tls_ctx->record_overhead = ptls_get_record_overhead(sock->tls_ctx->ptls);
}

/**
 *
 */
void aura_conn_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx) {
    app_debug(true, 0, "aura_conn_proceed:");
    const struct aura_iovec *prot;
    const char *chosen_prot;

    /* update handshake stats */
    /* redundant for now, but helpful for planning */
    chosen_prot = ptls_get_negotiated_protocol(sock->tls_ctx->ptls);
    for (prot = aura_h2_alpn_protocols; prot->base != NULL; ++prot) {
        if (memcmp(prot->base, chosen_prot, prot->len) == 0) {
            aura_h2_proceed(sock, srv_ctx);
        } else {
            /**/
        }
    }
}

/**
 *
 */
static inline void aura_handshake_failed(struct aura_srv_sock *sock) {
    app_debug(true, 0, ">>>> Handshake Failed");
}

/**
 *
 */
void a_on_async_job_complete(void *sock) {
    struct aura_srv_sock *a_sock = sock;
    // assert in flight

    // aura_handle_handshake(a_sock);
}

/**
 *
 */
static void a_handle_handshake_async(struct aura_srv_sock *sock, ptls_buffer_t *w_buf) {
    ptls_async_job_t *job;
    // assert not currently in flight
    // set socket in fllight

    /* keep buffer and wait for next */
    if (sock->tls_ctx->ptls != NULL) {
        sock->tls_ctx->async.w_buf = *w_buf;
        *w_buf = (ptls_buffer_t){NULL};

        job = ptls_get_async_job(sock->tls_ctx->ptls);
        if (job->set_completion_callback != NULL) /* this should always pass */
            job->set_completion_callback(job, a_on_async_job_complete, sock);
    }
}

/**
 *
 */
int aura_handle_handshake(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx) {
    app_debug(true, 0, ">>>> aura_handle_handshake:");
    ptls_buffer_t w_buf;
    void *send_buf, *read_ptr;
    size_t consumed;
    int res, n_read;
    int ret_val;

    n_read = aura_sliding_buffer_append_from_fd(&sock->tls_ctx->encrypted_read_buf, sock->sock_fd, 4096);
    if (n_read == -1) {
        sock->state = A_SOCK_STATE_CLOSED;
        return A_PROGRESS_ERROR;
    }

    if (n_read == 0 && aura_sliding_buffer_is_empty(&sock->tls_ctx->encrypted_read_buf))
        /* add back for polling */
        return A_PROGRESS_BLOCKED;

    if (sock->tls_ctx->async.w_buf.base != NULL) {
        w_buf = sock->tls_ctx->async.w_buf;
        sock->tls_ctx->async.w_buf = (ptls_buffer_t){NULL};
    } else
        ptls_buffer_init(&w_buf, "", 0);

    read_ptr = aura_sliding_buffer_read_pointer(&sock->tls_ctx->encrypted_read_buf);
    consumed = aura_sliding_buffer_available_read(&sock->tls_ctx->encrypted_read_buf);
    res = ptls_handshake(sock->tls_ctx->ptls, &w_buf, read_ptr, &consumed, NULL);
    aura_sliding_buffer_consume(&sock->tls_ctx->encrypted_read_buf, consumed);

    if (res == PTLS_ERROR_ASYNC_OPERATION) {
        // proceed async
        return A_PROGRESS_BLOCKED;
    }

    /* send stuff if available */
    if (w_buf.off != 0) {
        aura_write(sock->sock_fd, w_buf.base, w_buf.off);
    }
    ptls_buffer_dispose(&w_buf);

    if (res == 0) {
        aura_handshake_complete(sock, srv_ctx);
        ret_val = A_PROGRESS_DONE;
    } else if (res == PTLS_ERROR_IN_PROGRESS) {
        /* add back so we can rearm sock fd and try again */
        ret_val = A_PROGRESS_BLOCKED;
    } else {
        sock->state = A_SOCK_STATE_CLOSED;
        aura_handshake_failed(sock);
        ret_val = A_PROGRESS_ERROR;
    }

    return ret_val;
}
