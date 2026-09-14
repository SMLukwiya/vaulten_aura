#include "probe.h"

static int a_h2_probe_ctx_init(struct aura_h2_probe_ctx *p_ctx, const char *hostname,
                               const char *trusted_cert_fname, int fd) {
    ERR_clear_error();
    p_ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    assert(p_ctx->ssl_ctx);

    if (trusted_cert_fname)
        assert(SSL_CTX_load_verify_locations(p_ctx->ssl_ctx, trusted_cert_fname, NULL) == 1);
    else
        assert(SSL_CTX_set_default_verify_paths(p_ctx->ssl_ctx) == 1);

    SSL_CTX_set_verify(p_ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    p_ctx->ssl = SSL_new(p_ctx->ssl_ctx);
    assert(p_ctx->ssl);
    /* set SNI */
    SSL_set_tlsext_host_name(p_ctx->ssl, hostname);
    /* set fd */
    assert(SSL_set_fd(p_ctx->ssl, fd) == 1);
    /* set ALPN */
    const unsigned char alpn[] = {2, 'h', '2'};
    assert(SSL_set_alpn_protos(p_ctx->ssl, alpn, sizeof(alpn)) == 0);
    SSL_set1_host(p_ctx->ssl, hostname);

    /* Enable async handshakes */
    SSL_set_mode(p_ctx->ssl, SSL_MODE_ASYNC);
    SSL_set_connect_state(p_ctx->ssl);
    return 0;
}

int aura_h2_probe_connect(struct aura_h2_probe_ctx *p_ctx, const char *host, const char *port) {
    int sock_fd = aura_server_tool_connect(host, port);
    assert(sock_fd > 0);
    a_h2_probe_ctx_init(p_ctx, host, NULL, sock_fd);
    return 0;
}

int aura_h2_probe_tls_handshake(struct aura_h2_probe_ctx *p_ctx) {
    int ret = SSL_do_handshake(p_ctx->ssl);
    int err = SSL_get_error(p_ctx->ssl, ret);
    int sock_fd;
    uint64_t nr_fds;
    OSSL_ASYNC_FD *fds;
    fd_set _fds;

    if (err == SSL_ERROR_WANT_ASYNC) {
        app_debug(false, 0, "Handshake Async ret=%d, err=%d", ret, err);
        FD_ZERO(&_fds);

        SSL_get_all_async_fds(p_ctx->ssl, NULL, &nr_fds);
        fds = malloc(sizeof(OSSL_ASYNC_FD) * nr_fds);
        assert(fds);
        SSL_get_all_async_fds(p_ctx->ssl, fds, &nr_fds);

        for (uint64_t i = 0; i < nr_fds; ++i) {
            sock_fd = fds[i];
            FD_SET(sock_fd, &_fds);
        }

        struct timeval tv = {.tv_sec = 2, .tv_usec = 0}; /* 5 seconds timeout */

        while (true) {
            int rv = select(sock_fd + 1, &_fds, NULL, NULL, &tv);
            if (rv == 0 || rv < 0) {
                /* timed out */
                free(fds);
                return -1;
            }

            ret = SSL_do_handshake(p_ctx->ssl);
            err = SSL_get_error(p_ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_ASYNC)
                continue;
            break;
        }
        free(fds);
    }

    if (err != SSL_ERROR_NONE)
        return -1;
    return 0;
}

void aura_h2_probe_close(struct aura_h2_probe_ctx *p_ctx) {
    int sock_fd = SSL_get_fd(p_ctx->ssl);
    close(sock_fd);

    SSL_shutdown(p_ctx->ssl);
    SSL_free(p_ctx->ssl);
    SSL_CTX_free(p_ctx->ssl_ctx);
}

int aura_h2_probe_send_preface(struct aura_h2_probe_ctx *p_ctx) {
    int64_t len = sizeof(conn_preface_valid);
    if (SSL_write(p_ctx->ssl, conn_preface_valid, len) != len)
        return -1;
    return 0;
}

int aura_h2_probe_send_preface_settings(struct aura_h2_probe_ctx *p_ctx) {
    int64_t len = sizeof(preface_settings_frame);
    if (SSL_write(p_ctx->ssl, preface_settings_frame, len) != len)
        return -1;
    return 0;
}

int aura_h2_probe_send(struct aura_h2_probe_ctx *p_ctx, const uint8_t *buf, uint64_t len, uint64_t start, uint64_t end) {
    uint64_t _len = start - end;
    len = len > _len ? _len : len;
    if (SSL_write(p_ctx->ssl, buf, len) != (int64_t)len)
        return -1;
    return 0;
}

int aura_h2_probe_recv(struct aura_h2_probe_ctx *p_ctx, uint8_t *buf, uint64_t len) {
    return SSL_read(p_ctx->ssl, buf, len);
}

int aura_h2_probe_expect_goaway(const uint8_t *src_in, uint64_t len, int err) {
    struct aura_h2_frame frame;
    struct aura_h2_goaway_payload goaway;

    assert(aura_h2_probe_parse_frame_header(&frame, src_in, len) == 0);
    assert(frame.type == A_H2_FRAME_TYPE_GOAWAY);
    assert(frame.stream_id == 0);

    aura_h2_decode_goaway_payload(&frame, &goaway);
    assert(goaway.error_code == err);
    return 0;
}

int aura_h2_probe_expect_settings(const uint8_t *src_in, uint64_t len) {
    struct aura_h2_frame frame;
    struct aura_h2_settings_payload settings;

    assert(aura_h2_probe_parse_frame_header(&frame, src_in, len) == 0);
    assert(frame.type == A_H2_FRAME_TYPE_SETTINGS);
    assert(frame.stream_id == 0);
}
