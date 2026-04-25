#include <netinet/in.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int a_select_alpn_cb(SSL *ssl,
                     const unsigned char **out,
                     unsigned char *outlen,
                     const unsigned char *in,
                     unsigned int inlen,
                     void *arg) {
    *out = (uint8_t *)"h2";
    *outlen = 2;
    printf("a_select_alpn_cb\n");
    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *a_create_ssl_ctx(const char *cert_file, const char *keypair_file) {
    SSL_CTX *ctx;
    int err;
    FILE *error_stream;

    error_stream = stderr;
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(error_stream, "Failed to create server ssl ctx!\n");
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, keypair_file, SSL_FILETYPE_PEM) <= 0) {
        if (error_stream) {
            fprintf(error_stream, "Failed to load server keypair from file: %s\n", keypair_file);
            return NULL;
        }
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
        if (error_stream) {
            fprintf(error_stream, "Could not load server certificate:%s\n", cert_file);
            return NULL;
        }
    }

    if (SSL_CTX_check_private_key(ctx) <= 0) {
        if (error_stream) {
            fprintf(error_stream, "Server keypair doesnot match server certificate\n");
            return NULL;
        }
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    const unsigned char alpn[] = {2, 'h', '2'};
    SSL_CTX_set_alpn_select_cb(ctx, a_select_alpn_cb, NULL);
    return ctx;
}

ssize_t a_send_cb(nghttp2_session *session, const uint8_t *data, size_t len, int flags, void *user_data) {
    SSL *ssl = (SSL *)user_data;

    /* Partial write (adversarial) */
    size_t write_len = len / 2 + 1;
    int written = SSL_write(ssl, data, write_len);
    return written;
}

ssize_t a_data_prod_read_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                            uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    const char *msg = "Hello from vaultenaura nghttp2 adversarial server!";
    size_t len = strlen(msg);
    ssize_t chunk = len / 2;
    memcpy(buf, msg, chunk);
    static int sent = 0;
    if (sent) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    sent = 1;
    return chunk;
}

void submit_response(nghttp2_session *session, int32_t stream_id) {
    nghttp2_nv headers[] = {
      {(uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
      {(uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE},
    };

    nghttp2_data_provider2 data_prd;

    data_prd.read_callback = a_data_prod_read_cb;
    nghttp2_submit_response2(session, stream_id, headers, 2, &data_prd);
}

int a_on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        int32_t stream_id = frame->hd.stream_id;
        printf("Received request on stream %d\n", stream_id);

        /* submit response */
        submit_response(session, stream_id);
    }
    return 0;
}

int main(int argc, char **argv) {
    int err;
    if (argc < 3) {
        fprintf(stderr, "Usage: cmd <cert_file_name> <keypair_file_name>\n");
        return -1;
    }
    /** @todo: get cert and file names */
    SSL_CTX *ctx = a_create_ssl_ctx(argv[1], argv[2]);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(9443),
      .sin_addr.s_addr = INADDR_ANY,
    };

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 1);
    printf("Listening on port 9443...\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            printf("client connect failed\n");
            return -1;
        }
        SSL *ssl = SSL_new(ctx);
        if (SSL_set_fd(ssl, client_fd) <= 0) {
            printf("ssl_set_fd error...\n");
            return -1;
        }

        err = SSL_accept(ssl);
        printf("Listening on port 9443...err_B: %d\n", err);

        if ((err) <= 0) {
            int rv = SSL_get_error(ssl, err);
            char buf[1024];
            switch (rv) {
            case SSL_ERROR_SSL:
                uint64_t e = ERR_get_error();
                ERR_error_string_n(e, buf, sizeof(buf));
                printf("ssl_accept failed...: rv: %s\n", buf);
                break;
            default:
                printf("ssl_accept failed...: rv: %d\n", rv);
            }
            return -1;
        }
        printf("TLS established...\n");

        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback2(callbacks, a_send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, a_on_frame_recv);

        nghttp2_session *session;
        nghttp2_session_server_new2(&session, callbacks, ssl, NULL);

        /* initial settings */
        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, NULL, 0);
        nghttp2_session_send(session);

        /* Read loop */
        uint8_t buf[4096];
        while (1) {
            int r = SSL_read(ssl, buf, sizeof(buf));
            if (r <= 0)
                break;

            nghttp2_session_mem_recv2(session, buf, r);
            nghttp2_session_send(session);
        }

        close(client_fd);
        SSL_clear(ssl);
    }
    return 0;
}