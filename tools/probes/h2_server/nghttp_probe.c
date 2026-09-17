#include "utils.h"
#include "utils_lib.h"
#include <assert.h>
#include <sys/select.h>

static ssize_t a_send_cb(nghttp2_session *session, const uint8_t *data,
                         size_t len, int flags, void *user_data) {
    SSL *ssl = (SSL *)user_data;
    int rv = SSL_write(ssl, data, len);
    if (rv <= 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return rv;
}

static int a_on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    app_debug(false, 0, "ON FRAME RECEIVED");
    app_debug(false, 0, "------------------------");
    app_debug(false, 0, "FRAME TYPE=%d", frame->hd.type);
    return 0;
}

static int a_on_invalid_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code, void *user_data) {
    app_debug(false, 0, "ON INVALID FRAME");
    app_debug(false, 0, "------------------------");
    app_debug(false, 0, "FRAME TYPE=%d", frame->hd.type);
    return 0;
}

static int a_on_header_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name,
                               nghttp2_rcbuf *value, uint8_t flags, void *user_data) {
    nghttp2_vec hdr_name, hdr_value;

    app_debug(false, 0, "ON HEADER RECEIVED");
    app_debug(false, 0, "------------------------");
    hdr_name = nghttp2_rcbuf_get_buf(name);
    hdr_value = nghttp2_rcbuf_get_buf(value);

    app_debug(false, 0, "key='%s', value='%s'", hdr_name.base, hdr_value.base);
    return 0;
}

static int a_on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    app_debug(false, 0, "ON DATA CHUNK RECEIVED");
    app_debug(false, 0, "------------------------");
    app_info(false, 0, "Response body: %.*s", (int)len, data);
    return 0;
}

static int a_on_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    app_debug(false, 0, "ON STREAM CLOSED");
    app_debug(false, 0, "------------------------");
    app_debug(false, 0, "Stream id=%u, Error code=%d", stream_id, error_code);
    return 0;
}

int aura_server_tool_h2_probe(const char *host, const char *service, const char *trusted_cert_fname) {
    SSL_CTX *ctx;
    BIO *ssl_bio = NULL;
    SSL *ssl;
    int sock_fd = -1, err, rv;

    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);

    if (trusted_cert_fname)
        err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
    else
        err = SSL_CTX_set_default_verify_paths(ctx);
    if (err <= 0) {
        app_debug(false, 0, "Could not load trusted certificates");
        err = -1;
        goto cleanup;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    ssl_bio = BIO_new_ssl_connect(ctx);
    assert(ssl_bio);

    BIO_set_conn_hostname(ssl_bio, host);
    BIO_set_conn_port(ssl_bio, service);

    err = BIO_get_ssl(ssl_bio, &ssl);
    assert(err == 1);
    assert(ssl);

    /* set SNI */
    err = SSL_set_tlsext_host_name(ssl, host);
    assert(err == 1);

    /* set ALPN */
    const unsigned char alpn[] = {2, 'h', '2'};
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    /* Set hostname for certificate hostname verification. */
    err = SSL_set1_host(ssl, host);
    assert(err == 1);

    nghttp2_session *session;
    nghttp2_session_callbacks *callbacks;
    nghttp2_ssize ng_rv;

    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback2(callbacks, a_send_cb);
    nghttp2_session_callbacks_set_on_header_callback2(callbacks, a_on_header_recv_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, a_on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, a_on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, a_on_invalid_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, a_on_stream_close_cb);

    nghttp2_session_client_new3(&session, callbacks, ssl, NULL, NULL);

    nghttp2_settings_entry settings[] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65536}};

    const nghttp2_nv headers[] = {
      A_MAKE_NV(":method", "GET"),
      A_MAKE_NV(":path", "/api/v1/func1"),
      A_MAKE_NV(":scheme", "https"),
      A_MAKE_NV(":authority", host),
      A_MAKE_NV("priority", "u=5, i"),
      A_MAKE_NV("accept", "*/*"),
      A_MAKE_NV("user-agent", "nghttp2-probe/1.0.0"),
    };

    app_info(false, 0, "===== H2 Request Probe =====");

    /* TCP connect and TLS handshake. */
    err = BIO_do_connect(ssl_bio);
    if (err <= 0) {
        app_debug(false, 0, "Could not connect to server %s on port %s\n", host, service);
        err = -1;
        goto cleanup;
    }

    err = BIO_get_fd(ssl_bio, &sock_fd);
    assert(err > -1);

    nghttp2_submit_settings(session, 0, settings, ARR_CNT(settings));
    nghttp2_submit_request2(session, NULL, headers, ARR_CNT(headers), NULL, NULL);
    nghttp2_session_send(session);

    app_info(false, 0, "===== Connected to host:%s, port:%s =====", host, service);

    fd_set fds;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0}; /* 5 seconds timeout */

    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock_fd, &fds);
        int rv = select(sock_fd + 1, &fds, NULL, NULL, &tv);
        if (rv == 0) {
            app_debug(false, 0, "probe timed out");
            break;
        }

        uint8_t buf[8192];
        app_debug(false, 0, "BIO read");
        rv = BIO_read(ssl_bio, buf, sizeof(buf));
        app_debug(false, 0, "BIO read received=%d", rv);
        if (rv < 0) {
            app_debug(false, 0, "SSL_read error");
            break;
        }

        if (rv == 0) {
            break;
        }

        ng_rv = nghttp2_session_mem_recv2(session, buf, rv);
        app_debug(false, 0, "nghttp2_session_mem_recv2 rv=%ld", ng_rv);
        nghttp2_session_send(session);
    }

    nghttp2_session_del(session);
    app_info(false, 0, "===== SHUTTING DOWN =====");
    BIO_ssl_shutdown(ssl_bio);

cleanup:
    if (ssl_bio)
        BIO_free_all(ssl_bio);

    SSL_CTX_free(ctx);

    if (ERR_peek_error()) {
        err = -1;
        app_debug(false, 0, "Errors from the OpenSSL error queue:\n");
        ERR_print_errors_fp(stderr);
    }
    ERR_clear_error();

    return err;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        app_info(false, 0, "Usage: %s <host> <port>");
        return -1;
    }

    return aura_server_tool_h2_probe(argv[1], argv[2], NULL);
}