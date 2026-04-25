#include "connection.h"
#include "h2/client.h"
#include "h2/h2_srv.h"
#include "header_srv.h"
#include "picotls.h"
#include "server_srv.h"
#include "socket_srv.h"
#include "url_lib.h"
#include <netdb.h>
#include <netinet/in.h>

extern struct aura_srv_global_conf *glob_conf;

int aura_h2_client_preface_setup(struct aura_h2_ctx *h2_ctx) {
    uint8_t *write_ptr, *output_data;
    struct aura_h2_sched_evt *evt;
    size_t len;

    app_debug(true, 0, "aura_h2_client_preface_setup <<<");
    if (aura_sliding_buffer_append(h2_ctx->scheduler.write_buf, aura_h2_connection_preface.base, aura_h2_connection_preface.len) < 0)
        return -1;
    output_data = aura_sliding_buffer_read_pointer(h2_ctx->scheduler.write_buf);
    evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, aura_h2_connection_preface.len, false);
    if (!evt) {
        return -1;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &evt->e_list);

    /* setup settings and initial window update */
    /* @todo: send headers as well */
    if (aura_setup_preface_settings(h2_ctx) != 0)
        return -1;

    aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_FRAMES);
    aura_h2_conn_transition_state_handler(h2_ctx, NULL);
    return 0;
}

int aura_client_init(struct aura_srv_sock *sock, const char *host, int type) {
    struct addrinfo *aip, *addr, hint;
    int fd;
    int reuse = 1;
    int err = 0;

    app_debug(true, 0, "aura_client_init <<<<");
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;

    if ((err = getaddrinfo(host, "9443", &hint, &addr)) < 0) {
        sys_debug(true, 0, "failed to resolve address %s", gai_strerror(err));
        return -1;
    }

    aip = addr;
    do {
        fd = socket(aip->ai_addr->sa_family, SOCK_STREAM, aip->ai_protocol);
        if (fd < 0) {
            continue;
        }

        if (connect(fd, aip->ai_addr, aip->ai_addrlen) == 0)
            break;
        close(fd);
    } while ((aip = aip->ai_next));

    /* No connect attempt worked */
    if (aip == NULL)
        return -1;

    if (aura_sock_init(sock, fd, aip->ai_addr, aip->ai_addrlen, 0) < 0)
        return -1;

    return 0;
}

int aura_client_handshake_init(struct aura_conn *conn) {
    ptls_buffer_t send_buf;
    int res, rv;
    size_t in_len;
    uint8_t cbuf_small[16384];
    ptls_iovec_t alpn_list[1];
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ptls_iovec_init(NULL, 0)}}};

    app_debug(true, 0, "aura_client_handshake_init <<<<");
    ptls_buffer_init(&send_buf, cbuf_small, sizeof(cbuf_small));
    in_len = 0;
    static const ptls_iovec_t protocols[] = {{(uint8_t *)"h2", 2}};
    client_hs_prop.client.negotiated_protocols.list = protocols;
    client_hs_prop.client.negotiated_protocols.count = PTLS_ELEMENTSOF(protocols);
    /** @todo: Set this */

    ptls_set_server_name(conn->tls_ctx->ptls, "localhost", 0);
    res = ptls_handshake(conn->tls_ctx->ptls, &send_buf, NULL, &in_len, &client_hs_prop);
    app_debug(true, 0, "------------> SENDING TO PEER: %lu", send_buf.off);
    if (send_buf.off > 0) {
        if (aura_write(conn->sock.sock_fd, send_buf.base, send_buf.off) < 0) {
            return -1;
        }
    }

    app_debug(true, 0, "aura_client_handshake_init <<<< : %x", res);

    if (res == PTLS_ERROR_ASYNC_OPERATION || res == PTLS_ERROR_IN_PROGRESS) {
        return 0;
    }

    return -1;
}

/** */
struct aura_h2_ctx *aura_h2_client_conn_create(struct aura_memory_ctx *mc) {
    struct aura_h2_ctx *h2_ctx;

    app_debug(true, 0, "aura_h2_client_conn_create <<<<");
    h2_ctx = aura_h2_ctx_init(mc, false);
    if (!h2_ctx)
        return NULL;

    aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_PREFACE);
    aura_h2_conn_transition_state_handler(h2_ctx, aura_h2_client_preface_setup);

    return h2_ctx;
}

/**
 * Create client requests
 */
int aura_client_request_create(const char *url, size_t url_len, void *user_data) {
    struct aura_conn *conn;
    struct aura_h2_ctx *h2_ctx;
    struct aura_h2_stream *stream;
    struct aura_url parsed_url;
    struct aura_memory_ctx *mc;
    int res;

    app_debug(true, 0, "aura_client_request_create <<<<");
    mc = &glob_conf->mem_ctx;
    if (aura_url_parse(mc, url, url_len, &parsed_url) < 0) {
        return -1;
    }
    /* @todo: Attempt to find connection in pool */
    conn = NULL;

    /* Create new connection  */
    if (!conn) {
        conn = aura_conn_create(&glob_conf->mem_ctx, false, true, false);
        if (!conn)
            return -1;

        if (aura_client_init(&conn->sock, parsed_url.authority.host.base, SOCK_STREAM) < 0)
            return -1;

        if (aura_client_handshake_init(conn) < 0) {
            aura_conn_destroy(conn);
            return -1;
        }

        /* Add to conn pool */

        /* Create underlying protocol ctx */
        if (conn->protocol_callbacks.on_create(conn) < 0) {
            aura_conn_destroy(conn);
            return -1;
        }
        h2_ctx = conn->protocol_ctx.ctx;

        /* Attach request to be created once handshake completes */
        struct aura_client_pending_req *pending_req;
        pending_req = aura_alloc(mc, sizeof(*pending_req));
        if (!pending_req) {
            aura_conn_destroy(conn);
            return -1;
        }

        a_list_add_tail(&h2_ctx->pending_reqs, &pending_req->head);

        /* Store peer socket in sock map */
        conn->srv_ctx->glob_conf->conn_map[conn->sock.sock_fd] = conn;

        /* add to event loop */
        if (conn->srv_ctx->evt_loop->ops->add(conn->srv_ctx->evt_loop, conn->sock.sock_fd, AURA_EVENT_READ) < 0) {
            aura_conn_destroy(conn);
            return -1;
        }

        return 0;
    }

    /* Open stream */
    struct aura_slab_cache *sc;

    sc = aura_slab_cache_find_by_id(h2_ctx->conn->mc, A_SLAB_CACHE_ID_STREAM);
    stream = aura_slab_alloc(sc);
    if (!stream)
        return -1;

    if (aura_h2_stream_init(stream, h2_ctx->conn->mc, h2_ctx->next_stream_id, A_H2_STREAM_STATE_IDLE, 0, user_data) < 0) {
        return -1;
    }

    return 0;
}

int aura_h2_client_submit_request(struct aura_iovec *method, struct aura_iovec *scheme, struct aura_header_field *hdrs, size_t num_hdrs, const uint8_t *body, size_t body_len) {
    size_t hdr_size;

    hdr_size = aura_get_headers_size(hdrs, num_hdrs);
}