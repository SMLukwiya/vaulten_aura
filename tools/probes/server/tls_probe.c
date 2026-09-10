#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "utils.h"

int aura_server_tools_tls_probe(const char *host, const char *service, const char *trusted_cert_fname) {
    SSL_CTX *ctx;
    BIO *ssl_bio = NULL;
    SSL *ssl;
    X509 *cert;
    int sock_fd, err;

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

    /* Only TLS 1.3 */
    // SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
    // SSL_set_max_proto_version(ssl, TLS1_3_VERSION);

    /* set SNI */
    err = SSL_set_tlsext_host_name(ssl, host);
    assert(err == 1);

    /* set ALPN */
    const unsigned char alpn[] = {2, 'h', '2'};
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    /* Set hostname for certificate hostname verification. */
    err = SSL_set1_host(ssl, host);
    assert(err == 1);

    app_info(false, 0, "===== TLS HANDSHAKE Probe =====");

    /* TCP connect and TLS handshake. */
    err = BIO_do_connect(ssl_bio);
    if (err <= 0) {
        app_debug(false, 0, "Could not connect to server %s on port %s\n", host, service);
        err = -1;
        goto cleanup;
    }

    app_info(false, 0, "Connected to %s:%s", host, service);
    app_info(false, 0, "TLS Handshake successful!");
    app_info(false, 0, "Negotiated version: %s", SSL_get_version(ssl));
    app_info(false, 0, "Negotiated cipher: %s", SSL_get_cipher(ssl));

    /* Display certificate */
    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char subject[196] = {0};
        char issuer[128] = {0};

        /* Not sure if SSL adds a terminating character */
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject) - 1);
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer) - 1);
        app_info(false, 0, "SUBJECT: %s", subject);
        app_info(false, 0, "ISSUER: %s", issuer);
        X509_free(cert);
    }

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
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        app_info(false, 0, "Usage: %s <host> <port>", argv[0]);
        return -1;
    }

    return aura_server_tools_tls_probe(argv[1], argv[2], NULL);
}