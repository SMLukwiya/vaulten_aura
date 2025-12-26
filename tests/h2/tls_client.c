#include <arpa/inet.h>
#include <assert.h>
#include <nghttp2/nghttp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

static ssize_t send_cb(nghttp2_session *session, const u_int8_t *data, long unsigned len, int flags, void *user_data) {
    SSL *ssl = user_data;
    return SSL_write(ssl, data, (int)len);
}

static ssize_t recv_cb(nghttp2_session *session, uint8_t *buf, long unsigned len, int flags, void *user_data) {
    SSL *ssl = user_data;
    return SSL_read(ssl, buf, (int)len);
}

int a_run_tls_client(const char *hostname, const char *port, const char *trusted_cert_fname, FILE *err_stream) {
    SSL_CTX *ctx = NULL;
    BIO *ssl_bio = NULL;
    SSL *ssl = NULL;
    int exit_code = 0, err = 1, request_len;
    size_t buf_size;
    char *in_buf, *out_buf;

    buf_size = 16 * 1024;
    in_buf = malloc(buf_size);
    assert(in_buf);
    out_buf = malloc(buf_size);
    assert(out_buf);

    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);

    if (trusted_cert_fname)
        err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
    else
        err = SSL_CTX_set_default_verify_paths(ctx);

    if (err <= 0) {
        if (err_stream)
            fprintf(err_stream, "Failed to load trusted certificates\n");
        goto failure;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    const unsigned char alpn[] = "\x2h2";
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1);

    ssl_bio = BIO_new_ssl_connect(ctx);
    assert(ssl_bio);
    BIO_set_conn_hostname(ssl_bio, hostname);
    BIO_set_conn_port(ssl_bio, port);

    err = BIO_get_ssl(ssl_bio, &ssl);
    assert(err == 1);
    assert(ssl);

    err = SSL_set_tlsext_host_name(ssl, hostname);
    assert(err == 1);
    err = SSL_set1_host(ssl, hostname);
    assert(err == 1);

    err = BIO_do_connect(ssl_bio);
    if (err <= 0) {
        if (err_stream)
            fprintf(err_stream, "Could not connect to server %s on port %s\n", hostname, port);
        goto failure;
    }

    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback2(callbacks, send_cb);
    nghttp2_session_callbacks_set_recv_callback2(callbacks, recv_cb);

    nghttp2_session *session;
    nghttp2_session_client_new2(&session, callbacks, ssl, NULL);

    /* connection preface */
    SSL_write(ssl, NGHTTP2_CLIENT_MAGIC, NGHTTP2_CLIENT_MAGIC_LEN);

    /* Settings frame */
    nghttp2_settings_entry entry = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &entry, 1);

    /* Streams */
    const nghttp2_nv hdrs[] = {
      {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_FLAG_NONE},
      {(uint8_t *)":scheme", (uint8_t *)"http2", 7, 5, NGHTTP2_FLAG_NONE},
      {(uint8_t *)":authority", (uint8_t *)hostname, 11, strlen(hostname), NGHTTP2_FLAG_NONE},
    };

    nghttp2_submit_request2(session, NULL, hdrs, 4, NULL, NULL);
    nghttp2_session_send(session);

    printf("-------- receiving from aura_server");
    while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN) {
        int n_read = BIO_read(ssl_bio, in_buf, buf_size);
        if (n_read <= 0) {
            int ssl_err = SSL_get_error(ssl, n_read);
            if (ssl_err == SSL_ERROR_ZERO_RETURN)
                break;

            if (err_stream)
                fprintf(err_stream, "Error %i while reading from aura_server\n", ssl_err);
            goto failure;
        }
        nghttp2_session_mem_recv2(session, in_buf, n_read);
    }
    printf("-------- Done receiving\n");

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);

    BIO_ssl_shutdown(ssl_bio);
    goto cleanup;

failure:
    exit_code = 1;

cleanup:
    if (ssl_bio)
        BIO_free_all(ssl_bio);
    if (ctx)
        SSL_CTX_free(ctx);
    free(out_buf);
    free(in_buf);

    if (ERR_peek_error()) {
        exit_code = 1;
        if (err_stream) {
            fprintf(err_stream, "OpenSSL error queue\n");
        }
        ERR_clear_error();
    }

    return exit_code;
}

int main(int argc, char **argv) {
    int err;
    const char *hostname = "vaultenaura.local";
    const char *port = "8080";
    const char *trusted_cert_fname = NULL;

    err = a_run_tls_client(hostname, port, trusted_cert_fname, stderr);
    if (err) {
        fprintf(stderr, "AURA TLS error\n");
        return 1;
    }

    fprintf(stderr, "AURA TLS success\n");
    return 0;
}