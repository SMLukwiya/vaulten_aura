#if defined(SOLARIS) /* Solaris 10 */
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 700
#endif

#include "blobber_lib.h"
#include "error_lib.h"
#include "evt_loop_srv.h"
#include "function_lib.h"
#include "memory_lib.h"
#include "openssl/err.h"
#include "openssl/ocsp.h"
#include "openssl/pem.h"
#include "openssl/safestack.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "picotls.h"
#include "picotls/certificate_compression.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"
#include "picotls/pembase64.h"
#include "privilege_lib.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "socket_srv.h"
#include "types_lib.h"
#include "unix_socket_lib.h"

#include <alloca.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <sys/timerfd.h>
#include <time.h>

#define AURA_DEBUG 1

/* global server configs */
struct aura_srv_global_conf *glob_conf;

/**/
int aura_ocsp_timer_fd = -1;

/**
 * We update ocsp via the same epoll setup for the general server
 * call after daemonize as timer is not inherited
 */
static void a_create_ocsp_timer_fd(int64_t interval_sec) {
    struct itimerspec t;
    struct timespec now;

    aura_ocsp_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (aura_ocsp_timer_fd < 0)
        goto err_out;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        goto err_out;

    memset(&t, 0, sizeof(struct itimerspec));
    t.it_interval.tv_sec = now.tv_sec + 30; /* run the updater on startup */
    t.it_value.tv_sec = interval_sec;

    if (timerfd_settime(aura_ocsp_timer_fd, 0, &t, NULL) < 0)
        goto err_out;

    return;
err_out:
    sys_alert(true, errno, "create_ocsp_timer failed");
    return;
}

/**
 *
 */
static X509 *a_load_cert(const char *filename) {
    X509 *cert;
    FILE *fp = fopen(filename, "r");
    if (ferror(fp)) {
        sys_alert(true, errno, "Failed to load cert file %s");
        return NULL;
    }

    ERR_clear_error();
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        if (ERR_peek_error())
            app_alert(true, 0, "Failed to load cert file %s", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    fclose(fp);
    return cert;
}

/**/
static EVP_PKEY *a_load_key(const char *keyfile) {
    EVP_PKEY *private_key;
    FILE *fp = fopen(keyfile, "r");
    if (ferror(fp)) {
        sys_alert(true, errno, "Failed to load key file %s");
        return NULL;
    }

    ERR_clear_error();
    private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!private_key) {
        fclose(fp);
        if (ERR_peek_error())
            app_alert(true, 0, "Failed to load key file %s", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    fclose(fp);
    return private_key;
}

/**/
static STACK_OF(X509) * a_load_cert_chain(const char *filename) {
    STACK_OF(X509) * cert_chain;
    X509 *cert;
    size_t file_len;

    FILE *fp = fopen(filename, "r");
    if (ferror(fp)) {
        sys_alert(true, errno, "Failed to load cert chain %s");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    ERR_clear_error();
    cert_chain = sk_X509_new_null();
    while (ftell(fp) < file_len) {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert) {
            fclose(fp);
            if (ERR_peek_error())
                app_alert(true, 0, "Failed to load cert chain %s", ERR_error_string(ERR_get_error(), NULL));
            return NULL;
        }
        sk_X509_push(cert_chain, cert);
    }
    fclose(fp);
    return cert_chain;
}

/**
 *
 */
static void a_trigger_ocsp_update(struct aura_ocsp_updater *updater) {
    // I should load the cert chain in while parsing the yaml config using a dummy ssl context
    // STACK_OF(OPENSSL_STRING) *ocsp_urls = X509_get1_ocsp()
}

/**
 *
 */
static void a_handle_ocsp_timer_event(int timer_fd, struct aura_ocsp_updater *updater) {
    uint64_t expiration;
    ssize_t s;

    if (timer_fd != aura_ocsp_timer_fd) {
        /* something shady going on */
        app_alert(true, 0, "ocsp update error, passed timer fd %d mismatch with actual fd %d", timer_fd, aura_ocsp_timer_fd);
        return;
    }

    s = read(timer_fd, &expiration, sizeof(expiration));
    if (s == sizeof(expiration))
        a_trigger_ocsp_update(updater);
}

/**
 *
 */
struct aura_srv_host_conf *a_resolve_sni(struct aura_srv_listener_conf *lc, const char *server_name, uint32_t *off) {
    aura_rax_node_t *host_node;
    int host_conf_off;

    host_node = aura_rax_lookup(lc->sni, server_name, sizeof(server_name) - 1);
    if (!host_node)
        return NULL;

    if (host_node->data.type != A_RAX_DATA_INT) {
        app_debug(true, 0, "Incorrect data format, something fishy going on: FIX NOW!");
        return NULL;
    }
    host_conf_off = host_node->data.int_val;
    *off = host_conf_off;

    return &glob_conf->host_pool.hosts[host_conf_off];
}

static struct addrinfo *a_resolve_address(const char *hostname, const char *serv_name, int protocol, int sock_type) {
    int err;
    struct addrinfo hint, *res;

    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_socktype = sock_type;
    hint.ai_protocol = protocol;
    hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG;

    if ((err = getaddrinfo(hostname, serv_name, &hint, &res)) < 0) {
        sys_debug(true, 0, "failed to resolve address %s", gai_strerror(err));
        return NULL;
    }

    return res;
}

/**
 * We use a super structure passed to the callback
 * to encapsulate the chosen listener as well as the
 * actual 'ptls_on_client_hello_t' (self)
 */
struct a_super_on_client_hello_ptls {
    ptls_on_client_hello_t super;
    struct aura_srv_listener_conf *listener;
};

/**
 * Client hello callback
 */
static int a_on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls_conn, ptls_on_client_hello_parameters_t *hello_params) {
    struct aura_srv_host_conf *host_config;
    struct aura_srv_tls_iden *chosen_tls_identity, *tls_identity;
    struct aura_srv_listener_conf *lc;
    struct a_super_on_client_hello_ptls *super_st;
    bool prefer_raw_public_key;
    struct aura_srv_sock *conn_data;
    int res;

    if (hello_params->incompatible_version)
        return 0;

    super_st = (struct a_super_on_client_hello_ptls *)self;
    lc = super_st->listener;
    conn_data = (*ptls_get_data_ptr(tls_conn)); /* struct aura_srv_sock * */

    if (hello_params->server_name.base != NULL) {
        host_config = a_resolve_sni(lc, hello_params->server_name.base, &conn_data->host_conf_off);
        assert(host_config != NULL);
        ptls_set_server_name(tls_conn, (const char *)hello_params->server_name.base, hello_params->server_name.len);
        ptls_log_recalc_conn_state(a_get_conn_log_state(conn_data));
    } else {
        host_config = super_st->listener->fb_host_conf;
        assert(host_config != NULL);
    }

    prefer_raw_public_key = hello_params->server_certificate_types.count > 0 && memchr(hello_params->server_certificate_types.list, PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY, hello_params->server_certificate_types.count) != NULL;
    chosen_tls_identity = &lc->tls_pool.idens[host_config->def_tls_off];
    if (chosen_tls_identity->contexts.tls1_3.ctx->use_raw_public_keys != prefer_raw_public_key) {
        for (size_t i = 0; i < host_config->other_tls_cnt; ++i) {
            if (lc->tls_pool.idens[host_config->other_tls_off[i]].contexts.tls1_3.ctx->use_raw_public_keys == prefer_raw_public_key) {
                tls_identity = &lc->tls_pool.idens[host_config->other_tls_off[i]];
                if (hello_params->signature_algorithms.count == 0) {
                    chosen_tls_identity = tls_identity;
                    goto identity_found;
                }

                for (size_t j = 0; tls_identity->contexts.tls1_3.sig_scheme[i].scheme_id != UINT16_MAX; ++j) {
                    for (size_t k = 0; k < hello_params->signature_algorithms.count; ++k)
                        if (tls_identity->contexts.tls1_3.sig_scheme[j].scheme_id == hello_params->signature_algorithms.list[k]) {
                            chosen_tls_identity = tls_identity;
                            goto identity_found;
                        }
                }
            }
        }
    }
identity_found:
    ptls_set_context(tls_conn, chosen_tls_identity->contexts.tls1_3.ctx);
    app_debug(true, 0, "Identity found: Negotiated protocols %d", hello_params->negotiated_protocols.count);

    /* ALNP */
    if (hello_params->negotiated_protocols.count != 0) {
        for (size_t i = 0; i < hello_params->negotiated_protocols.count; ++i) {
            return ptls_set_negotiated_protocol(tls_conn, "h2", sizeof("h2") - 1);
        }
    }
    return PTLS_ALERT_PROTOCOL_VERSION; /* not h2 */
}

/**
 * We use a super structure passed to the callback
 * to encapsulate the chosen listener as well as the
 * actual 'ptls_on_client_hello_t' (self)
 */
struct aura_super_on_emit_certificate_ptls {
    ptls_emit_certificate_t super;
    struct aura_srv_tls_iden *tls_identity;
};

/**
 * Emit certificate callback
 */
static int a_on_emit_certificate(ptls_emit_certificate_t *self, ptls_t *tls, ptls_message_emitter_t *emitter,
                                 ptls_key_schedule_t *key_sched, ptls_iovec_t context, int push_status_request,
                                 const uint16_t *compress_algos, size_t num_compress_algos) {

    struct aura_super_on_emit_certificate_ptls *super_st;
    ptls_emit_certificate_t *emit_comp;
    ptls_context_t *tlsctx;
    void *ocsp_response;
    int ret;

    /* cast back to super to access listener */
    super_st = (struct aura_super_on_emit_certificate_ptls *)self;

    if (super_st->tls_identity->compressed_cert.emit_ptls != NULL) {
        emit_comp = &super_st->tls_identity->compressed_cert.emit_ptls->super;
        ret = emit_comp->cb(emit_comp, tls, emitter, key_sched, context, push_status_request, compress_algos, num_compress_algos);
        if (ret != PTLS_ERROR_DELEGATE)
            goto Exit;
    }

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
        ptls_context_t *tlsctx = ptls_get_context(tls);
        void *ocsp_response = push_status_request ? super_st->tls_identity->ocsp.ocsp_stapling.ocsp_response : NULL;
        size_t ocsp_response_len = super_st->tls_identity->ocsp.ocsp_stapling.ocsp_response_len;
        ret = ptls_build_certificate_message(
          emitter->buf,
          ptls_iovec_init(NULL, 0),
          tlsctx->certificates.list,
          tlsctx->certificates.count,
          ocsp_response != NULL ? ptls_iovec_init(ocsp_response, ocsp_response_len) : ptls_iovec_init(NULL, 0));
        if (ret != 0)
            goto Exit;
    });
    ret = 0;

Exit:
    return ret;
}

/**
 * build_compressed_certificate_ptls: returns ptls_emit_compressed_certificate_ *
 * call ptls_init_compressed_certificate(dest, ctx->certificates.list, ctx->certificates.count, ocsp_status)
 * call ptls_dispose_compressed_certificate when done
 */

/**
 * Encrypted Cleint Hello stuff
 */
struct aura_ech_opener {
    ptls_ech_create_opener_t super;
    struct aura_ech_opener_conf {
        uint8_t config_id;
        ptls_hpke_kem_t *kem;
        ptls_hpke_cipher_suite_t **cipher_suites; /* NULL terminated */
        ptls_iovec_t parsed_ech_config;
        uint8_t max_name_length;
        ptls_key_exchange_context_t *key_ex;
        bool advertise;
    } ech_configs[1];
};

/**
 *
 */
static ptls_aead_context_t *a_ech_create_opener(struct st_ptls_ech_create_opener_t *self, ptls_hpke_kem_t **kem,
                                                ptls_hpke_cipher_suite_t **cipher, ptls_t *ptls, uint8_t config_id,
                                                ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc,
                                                ptls_iovec_t info_prefix) {
    struct aura_ech_opener *super_st;
    struct aura_ech_opener_conf *config = NULL;
    ptls_aead_context_t *aead = NULL;
    ptls_buffer_t info_buf;
    size_t i;
    int ret;

    *cipher = NULL;
    *kem = NULL;
    super_st = (struct aura_ech_opener *)self;

    /* find matching config, bail out if none */
    for (config = super_st->ech_configs; config->key_ex != NULL; ++config)
        if (config->config_id == config_id)
            break;
    if (config->key_ex == NULL)
        goto Exit;

    /* find matching cipher-suite, or bail out if none */
    for (i = 0; super_st->ech_configs->cipher_suites[i] != NULL; ++i) {
        if (super_st->ech_configs->cipher_suites[i]->id.kdf == cipher_id.kdf && super_st->ech_configs->cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = super_st->ech_configs->cipher_suites[i];
            break;
        }
    }
    if (*cipher == NULL)
        goto Exit;

    ptls_buffer_init(&info_buf, "", 0);
    ptls_buffer_pushv(&info_buf, info_prefix.base, info_prefix.len);
    ptls_buffer_pushv(&info_buf, config->parsed_ech_config.base, config->parsed_ech_config.len);

    *kem = config->kem;
    ret = ptls_hpke_setup_base_r(*kem, *cipher, config->key_ex, &aead, enc, ptls_iovec_init(info_buf.base, info_buf.off));
    if (ret != 0)
        goto Exit;

Exit:
    ptls_buffer_dispose(&info_buf);
    return aead;
}

/**
 * Parse a single encrypted client hello config
 */
static int a_parse_one_ech_config(const aura_blob_param_st *blob, const st_aura_blob_node *ech_entry_node,
                                  struct aura_ech_opener_conf *ech_conf) {
    const st_aura_blob_kv_pair *kv;
    const st_aura_blob_node *val, *ciphers_node, *cipher_entry_node;
    ptls_hpke_cipher_suite_t **cand;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx, i, j;
    const char *key, *public_name;
    int res;

    kv_cnt = ech_entry_node->map.kv_cnt;
    kv_idx = ech_entry_node->map.kv_idx;
    *ech_conf = (struct aura_ech_opener_conf){.cipher_suites = ptls_openssl_hpke_cipher_suites, .max_name_length = 64, .advertise = true};

    for (i = 0; i < kv_cnt; ++i) {
        kv = &blob->kv_pairs[kv_idx + i];
        key = blob->strtab + kv->key_offset;
        val = &blob->nodes[kv->node_idx];

        if (strcmp(key, "config_id") == 0) {
            const char *config_id = blob->strtab + val->str_offset;
            aura_scan_str(config_id, SCNu8, &ech_conf->config_id);
            continue;
        }

        if (strcmp(key, "key_file") == 0) {
            EVP_PKEY *pkey;
            const char *key_file = blob->strtab + val->str_offset;
            pkey = a_load_key(key_file);
            if (key == NULL) {
                /* although this shouldn't happen since validate would have failed if there was an error */
                app_debug(true, 0, "Failed to load ech key file");
                return 1;
            }

            res = ptls_openssl_create_key_exchange(&ech_conf->key_ex, pkey);
            if (res != 0) {
                app_debug(true, 0, "Failed to load hpke ech config");
                return 1;
            }

            EVP_PKEY_free(pkey);
            for (j = 0; ptls_openssl_hpke_kems[j] != NULL; ++j) {
                if (ptls_openssl_hpke_kems[i]->keyex == ech_conf->key_ex->algo) {
                    ech_conf->kem = ptls_openssl_hpke_kems[i];
                    break;
                }
            }

            if (ech_conf->kem == NULL) {
                /* should also not happen */
                app_debug(true, 0, "private key %s is not supported for ech", ech_conf->key_ex->algo->name);
                return 1;
            }
            continue;
        }

        if (strcmp(key, "public_name") == 0) {
            public_name = blob->strtab + val->str_offset;
            continue;
        }

        if (strcmp(key, "advertise") == 0) {
            // true or false
            continue;
        }

        if (strcmp(key, "max_name_length") == 0) {
            const char *max_name_len = blob->strtab + val->str_offset;
            aura_scan_str(max_name_len, SCNu8, &ech_conf->max_name_length);
            continue;
        }

        if (strcmp(key, "cipher_suites") == 0) {
            ciphers_node = &blob->nodes[kv->node_idx];
            arr_cnt = ciphers_node->arr.arr_cnt;
            arr_idx = ciphers_node->arr.arr_idx;

            ech_conf->cipher_suites = malloc(sizeof(*ech_conf->cipher_suites) * (arr_cnt + 1)); /* NULL terminated */
            memset(ech_conf->cipher_suites, 0, sizeof(*ech_conf->cipher_suites) * (arr_cnt + 1));

            for (j = 0; j < arr_cnt; ++j) {
                for (cand = ptls_openssl_hpke_cipher_suites; *cand != NULL; ++cand) {
                    cipher_entry_node = &blob->nodes[blob->arrs[arr_idx + i].node_idx];
                    const char *cipher = blob->strtab + cipher_entry_node->str_offset;
                    if (strcasecmp(cipher, (*cand)->name) == 0)
                        break;
                }
                if (*cand == NULL) {
                    /* should not happen */
                    return 1;
                }
                ech_conf->cipher_suites[i] = *cand;
            }
            ech_conf->cipher_suites[i] = NULL;

            continue;
        }
    }

    /* build ech config */
    ptls_buffer_t ptls_buf;
    ptls_buffer_init(&ptls_buf, "", 0);
    res = ptls_ech_encode_config(&ptls_buf, ech_conf->config_id, ech_conf->kem, ech_conf->key_ex->pubkey, ech_conf->cipher_suites, ech_conf->max_name_length, public_name);
    if (res != 0)
        app_exit(true, 0, "Failed to build ECHConfig: %d", res);
    ech_conf->parsed_ech_config = ptls_iovec_init(ptls_buf.base, ptls_buf.off);

    return 0;
}

/**
 * Parse encrypted client hello config
 */
static int a_parse_ech_config(const aura_blob_param_st *blob, const st_aura_blob_node *ech_node,
                              ptls_ech_create_opener_t **ech_opener, ptls_iovec_t *retry_config) {
    const st_aura_blob_node *ech_entry_node;
    struct aura_ech_opener *ech;
    uint32_t arr_cnt, arr_idx, i;
    int res;

    ech = malloc(sizeof(*ech) + sizeof(ech->ech_configs[0]) * (arr_cnt + 1)); /* NULL terminated */
    if (ech == NULL)
        sys_exit(true, errno, "a_parse_ech_config(): Out of memory");

    *ech = (struct aura_ech_opener){{a_ech_create_opener}};

    *retry_config = ptls_iovec_init(NULL, 0);

    arr_cnt = ech_node->arr.arr_cnt;
    arr_idx = ech_node->arr.arr_idx;

    for (i = 0; i < arr_cnt; ++i) {
        ech_entry_node = &blob->nodes[blob->arrs[arr_idx + i].node_idx];

        res = a_parse_one_ech_config(blob, ech_entry_node, &ech->ech_configs[i]);
        if (res != 0) {
            return 1;
        }

        // setup retry config
    }

    ech->ech_configs[arr_cnt] = (struct aura_ech_opener_conf){0};

    return 0;
}

/**
 *
 */
struct aura_ptls_super_ctx {
    ptls_context_t ctx;
    struct a_super_on_client_hello_ptls ch;
    struct aura_super_on_emit_certificate_ptls ec;
    struct {
        ptls_openssl_sign_certificate_t ossl;
    } sc;
    ptls_openssl_verify_certificate_t vc;
};

/**
 *
 */
static int a_setup_tls(struct aura_srv_listener_conf *lc, ptls_key_exchange_algorithm_t **key_ex,
                       ptls_cipher_suite_t **cipher_suites, ptls_ech_create_opener_t *ech_create_opener,
                       ptls_iovec_t ech_retry_configs, unsigned int server_cipher_preference,
                       ptls_iovec_t raw_public_key, struct aura_srv_tls_iden *iden,
                       bool client_verify) {
    struct aura_ptls_super_ctx *ptls_super_ctx;
    X509 *cert;
    EVP_PKEY *key;
    X509_STORE *ca_store;
    STACK_OF(X509) * cert_chain;
    int res;

    ptls_super_ctx = malloc(sizeof(*ptls_super_ctx));
    if (!ptls_super_ctx)
        app_exit(true, errno, "Out of memory");
    memset(ptls_super_ctx, 0, sizeof(*ptls_super_ctx));

    *ptls_super_ctx = (struct aura_ptls_super_ctx){
      .ctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = key_ex,
        .cipher_suites = cipher_suites,
        .tls12_cipher_suites = ptls_openssl_tls12_cipher_suites,
        .certificates = {NULL},
        .ech.server = {ech_create_opener, ech_retry_configs},
        .on_client_hello = &ptls_super_ctx->ch.super,
        .emit_certificate = &ptls_super_ctx->ec.super,
        .sign_certificate = NULL,
        .verify_certificate = NULL,
        .ticket_lifetime = 0,     /* not yet supported */
        .max_early_data_size = 0, /* not yet supported */
        .hkdf_label_prefix__obsolete = NULL,
        .require_dhe_on_psk = 0, /* not yet supported */
        .use_exporter = 0,
        .send_change_cipher_spec = 0,
        .require_client_authentication = 0,
        .omit_end_of_early_data = 0,
        .server_cipher_preference = server_cipher_preference,
        .ticket_requests.server.max_count = 0, /* not yet supported */
        .encrypt_ticket = NULL,                /* not yet supported */
        .save_ticket = NULL,                   /* not yet supported */
        .log_event = NULL,
        .update_open_count = NULL,
        .update_traffic_key = NULL,
        .decompress_certificate = NULL,
        .on_extension = NULL,
      },
      .ch = {
        .listener = lc,
        .super = {.cb = a_on_client_hello},
      },
      .ec = {
        .tls_identity = iden,
        .super = {.cb = a_on_emit_certificate},
      },
    };

    cert = a_load_cert(iden->cert.cert_file);
    if (cert == NULL)
        app_exit(true, 0, "a_load_cert() failed");

    key = a_load_key(iden->key.key_file);
    if (!key)
        sys_exit(true, 0, "a_load_key() failed");

    // if (client_verify) {
    //     ctx.require_client_authentication = 1;
    //     ca_store = SSL_CTX_get_cert_store(iden->contexts.tls1_2);
    //     assert(ca_store);
    //     if (ptls_openssl_init_verify_certificate(&vc, ca_store) != 0) {
    //         sys_exit(true, 0, "ptls openssl init verify certificate failed");
    //     }
    //     super_ptls->ctx.verify_certificate = &vc.super;
    // }

    if (ptls_openssl_init_sign_certificate(&ptls_super_ctx->sc.ossl, key) != 0) {
        sys_exit(true, 0, "ptls openssl init sign certificate failed");
    }
    ptls_super_ctx->ctx.sign_certificate = &ptls_super_ctx->sc.ossl.super;

    if (raw_public_key.base == NULL) {
        res = ptls_load_certificates(&ptls_super_ctx->ctx, iden->cert.cert_file);
        assert(res == 0);
    } else {
        ptls_super_ctx->ctx.certificates.list = malloc(sizeof(ptls_super_ctx->ctx.certificates.list[0]));
        ptls_super_ctx->ctx.certificates.list[0] = raw_public_key;
        ptls_super_ctx->ctx.certificates.count = 1;
        ptls_super_ctx->ctx.use_raw_public_keys = 1;
        ptls_super_ctx->ctx.emit_certificate = NULL;
    }

    iden->contexts.tls1_3.ctx = &ptls_super_ctx->ctx;
    return res;
}

/**
 *
 */
static void load_tls_identity(const aura_blob_param_st *blob, const st_aura_blob_node cert_file_node,
                              ptls_iovec_t *raw_pubkey, ptls_iovec_t *certs) {
    size_t raw_pubkey_count, cert_cnt;
    const char *cert_file;
    int res;

    cert_file = blob->strtab + cert_file_node.str_offset;
    res = ptls_load_pem_objects(cert_file, "PUBLIC KEY", raw_pubkey, 1, &raw_pubkey_count);
    if (res != 0) {
        //
    }

    // load private key with ssl

    /** @todo: client verification */
}

/**
 * Setup socket for accepting connections.
 */
static struct aura_srv_sock *a_server_init(int type, struct sockaddr *serv_addr, socklen_t addr_len) {
    struct aura_srv_sock *sock;
    int fd;
    int reuse = 1;
    int err = 0;

    fd = socket(serv_addr->sa_family, type, 0);
    if (fd < 0) {
        sys_debug(true, errno, "Failed to initialize server");
        return NULL;
    }

    if (serv_addr->sa_family == AF_INET && type == SOCK_STREAM) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            goto exception;
    } else {
        app_exit(true, 0, "Unsuported domain: %d of type: %d", serv_addr->sa_family, type);
    }

    if (bind(fd, serv_addr, addr_len) < 0)
        goto exception;

    if (listen(fd, AURA_QLEN) < 0)
        goto exception;

    aura_set_fd_flag(fd, O_NONBLOCK);

    sock = aura_socket_create(&glob_conf->mem_ctx, fd, serv_addr, addr_len, A_SOCK_LISTENER);
    if (!sock)
        goto exception;

    return sock;
exception:
    err = errno;
    close(fd);
    errno = err;
    return NULL;
}

/**
 *
 */
void a_server_shutdown(int signo) {
    app_info(true, 0, "Shutdown signal(->server)!");
    // unlink and cleanup
}

/**
 * NOTE:
 * Server config table indexes,
 * This must match the one defined in
 * the daemon. When updating one, update
 * the other as well
 */
enum srv_node_idx {
    A_IDX_NONE,
    A_IDX_SERVER_NAME,
    A_IDX_SERVER_PORT,
    A_IDX_SERVER_ADDR,
    A_IDX_SERVER_TO_READ,
    A_IDX_SERVER_TO_WRITE,
    A_IDX_TLS_IDEN,
    A_IDX_TLS_CIPHERS,
    A_IDX_HOSTS
};

/**
 * Build h2 origin frames returning an array of {len, char} pairs
 */
static struct aura_iovec *a_build_h2_origin_frame(const aura_blob_param_st *blob, const st_aura_blob_node *h2_node) {
    const st_aura_blob_node *h2_origin_entry_node;
    struct aura_iovec *h2_origin;
    uint32_t h2_cnt, h2_idx, i;
    const char *h2_frame;

    h2_cnt = h2_node->arr.arr_cnt;
    h2_idx = h2_node->arr.arr_idx;

    h2_origin = malloc(sizeof(*h2_origin) * (h2_cnt + 1)); /* NULL terminated */
    if (h2_origin == NULL)
        goto err;
    memset(h2_origin, 0, sizeof(*h2_origin) * (h2_cnt + 1));

    for (i = 0; i < h2_cnt; ++i) {
        h2_origin_entry_node = &blob->nodes[blob->arrs[h2_idx + i].node_idx];
        h2_frame = blob->strtab + h2_origin_entry_node->str_offset;
        h2_origin[i].len = htons((uint16_t)strlen(h2_frame));
        h2_origin[i].base = strdup(h2_frame);
        if (h2_origin[i].base == NULL)
            goto err;
    }
    h2_origin[h2_cnt] = (struct aura_iovec){NULL};
    return h2_origin;
err:
    return NULL;
}

/**
 *
 */
static ptls_cipher_suite_t **a_parse_ciphers_suites(const aura_blob_param_st *blob, const st_aura_blob_node *cipher_node) {
    ptls_cipher_suite_t *c;
    ptls_cipher_suite_t **cs;
    const st_aura_blob_node *tls_cipher_entry_node;
    int cipher_length = 0;
    const char *cipher;
    uint32_t arr_cnt, arr_idx, i, j;

    arr_cnt = cipher_node->arr.arr_cnt;
    arr_idx = cipher_node->arr.arr_idx;

    /**
     * All ciphers that pass through should ideally be correct
     */
    cs = malloc(sizeof(*cs) * (arr_cnt + 1));
    if (cs == NULL)
        sys_exit(true, errno, "a_parse_cipher_suites(): Out of memory");

    for (i = 0; i < arr_cnt; ++i) {
        tls_cipher_entry_node = &blob->nodes[blob->arrs[arr_idx + i].node_idx];
        cipher = blob->strtab + tls_cipher_entry_node->str_offset;

        for (j = 0; (c = ptls_openssl_cipher_suites_all[j]) != NULL; ++j) {
            if (strcmp(cipher, c->name) == 0) {
                cs[i] = c;
                break;
            }
        }
    }
    cs[arr_cnt] = NULL;

    return cs;
}

/**
 * Test if the listener config provided can
 * allow creating a new listener
 */
static bool a_listener_is_new(struct sockaddr *addr, socklen_t addr_len) {
    int i;
    struct sockaddr *a;
    struct sockaddr_in *ip4_a, *ip4_b;

    for (i = 0; i < glob_conf->host_pool.cnt; ++i) {
        a = &glob_conf->host_pool.hosts[i].addr;

        if (glob_conf->host_pool.hosts[i].addr_len != addr_len)
            break;

        if (a->sa_family == AF_INET) {
            ip4_a = (struct sockaddr_in *)a;
            ip4_b = (struct sockaddr_in *)addr;
            if (ntohl(ip4_a->sin_addr.s_addr) == ntohl(ip4_b->sin_addr.s_addr))
                return false;

            if (ntohs(ip4_a->sin_port) == ntohs(ip4_b->sin_port))
                return false;

        } else {
            app_debug(true, 0, "Unsupported address protocol: %s", a->sa_family);
        }
    }

    return true;
}

/**
 * Test if provided tls identity pair (cert and key)
 * are new
 */
static bool a_tls_is_new(struct aura_srv_listener_conf *lc, const char *cert_file, const char *key_file) {
    if (lc->tls_pool.idens == NULL)
        return true;

    for (int i = 0; i < lc->tls_pool.cnt; ++i) {
        if (strcmp(cert_file, lc->tls_pool.idens[i].cert.cert_file))
            return true;

        if (strcmp(key_file, lc->tls_pool.idens[i].key.key_file))
            return true;
    }

    return false;
}

/**
 * Add tls identity to the global tls pool
 */
static int a_tls_add_iden(const aura_blob_param_st *blob, const st_aura_blob_node *tls_ident_entry_node,
                          ptls_key_exchange_algorithm_t **key_ex, ptls_cipher_suite_t **cs,
                          ptls_ech_create_opener_t *create_opener, ptls_iovec_t retry_configs,
                          struct aura_srv_listener_conf *lc) {

    struct aura_srv_tls_iden *iden, *dest;
    const st_aura_blob_node *entry_node;
    const st_aura_blob_kv_pair *kv;
    ptls_iovec_t raw_pubkey = {NULL};
    uint32_t kv_cnt, kv_idx, i;
    const char *key, *cert_file = NULL, *key_file = NULL, *tag = NULL;
    int res;

    kv_cnt = tls_ident_entry_node->map.kv_cnt;
    kv_idx = tls_ident_entry_node->map.kv_idx;

    /* extract value from kv entries */
    for (i = 0; i < kv_cnt; ++i) {
        kv = &blob->kv_pairs[kv_idx + i];
        key = blob->strtab + kv->key_offset;
        entry_node = &blob->nodes[kv->node_idx];

        if (strcmp(key, "cert_file") == 0) {
            cert_file = blob->strtab + entry_node->str_offset;
            continue;
        }

        if (strcmp(key, "key_file") == 0) {
            key_file = blob->strtab + entry_node->str_offset;
            continue;
        }

        if (strcmp(key, "tag") == 0) {
            tag = blob->strtab + entry_node->str_offset;
            continue;
        }
    }

    if (!a_tls_is_new(lc, cert_file, key_file))
        return 0;

    iden = malloc(sizeof(*iden));
    if (iden == NULL)
        goto err;

    if (lc->tls_pool.cnt >= lc->tls_pool.cap) {
        lc->tls_pool.cap = lc->tls_pool.cap == 0 ? 5 : lc->tls_pool.cap * 2;
        lc->tls_pool.idens = realloc(lc->tls_pool.idens, sizeof(*iden) * lc->tls_pool.cap);
        if (!lc->tls_pool.idens)
            goto err;
    }

    dest = &lc->tls_pool.idens[lc->tls_pool.cnt];
    memcpy(dest, iden, sizeof(*iden));
    dest->cert.cert_file = strdup(cert_file);
    dest->key.key_file = strdup(key_file);
    dest->tag = tag ? strdup(tag) : NULL;

    res = a_setup_tls(lc, key_ex, cs, create_opener, retry_configs, 0, raw_pubkey, dest, false);
    lc->tls_pool.cnt++;
    return 0;
err:
    return -1;
}

/**
 * Add host configuration to the global config list
 * and return the offset of the newly added conf
 */
static inline int a_add_host_conf(struct aura_srv_host_conf *hc) {
    struct aura_srv_host_conf *conf;
    size_t host_cap = glob_conf->host_pool.cap;
    size_t host_cnt = glob_conf->host_pool.cnt;
    int res = -1;

    if (host_cnt >= host_cap) {
        host_cap = host_cap == 0 ? 5 : host_cap * 2;
        glob_conf->host_pool.cap = host_cap;
        glob_conf->host_pool.hosts = realloc(glob_conf->host_pool.hosts, sizeof(*conf) * host_cap);
        if (!glob_conf->host_pool.hosts)
            return res;
    }

    conf = &glob_conf->host_pool.hosts[glob_conf->host_pool.cnt];
    memcpy(conf, hc, sizeof(*hc));
    res = glob_conf->host_pool.cnt;
    glob_conf->host_pool.cnt++;
    return res;
}

/**
 * Create host conf for this hostname, insert into global
 * host conf table and return the offset of the added conf
 */
static int a_create_host_conf(struct aura_srv_listener_conf *lc, int fd,
                              struct sockaddr *addr, socklen_t addr_len, const char *hostname,
                              const char *port, uint32_t default_tls_idx, struct aura_iovec *h2_frames) {
    struct aura_srv_host_conf conf;
    uint16_t port_num;
    int host_off;
    bool res;

    memcpy(&conf.addr, addr, sizeof(*addr));
    conf.addr_len = addr_len;
    conf.authority.hostname.base = strdup(hostname);
    conf.authority.hostname.len = strlen(hostname);
    aura_scan_str(port, "%" SCNu16, &conf.authority.port);
    conf.def_tls_off = default_tls_idx;
    res = aura_router_init(&conf.router);
    if (!res)
        return -1;

    if (h2_frames != NULL)
        conf.h2_origin_frame = h2_frames;

    if (lc->fd_pool.cnt >= lc->fd_pool.cap) {
        lc->fd_pool.cap = lc->fd_pool.cap == 0 ? 5 : lc->fd_pool.cap * 2;
        lc->fd_pool.fds = realloc(lc->fd_pool.fds, sizeof(int) * lc->fd_pool.cap);
        if (!lc->fd_pool.fds)
            return -1;
    }
    lc->fd_pool.fds[lc->fd_pool.cnt++] = fd;

    host_off = a_add_host_conf(&conf);

    /* add host + conf to listener sni map */
    if (host_off != -1)
        aura_rax_insert(lc->sni, hostname, sizeof(hostname) - 1, A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_int(host_off));

    return host_off;
}

/* Add a new sock to global socket table */
// @todo: perhaps the function name should be better
static inline void add_sock_to_fdmap(struct aura_srv_sock *sock) {
    glob_conf->fdmap[sock->sock_fd] = sock;
}

/**
 * Parse configs received from daemon
 */
static void a_setup_configs(void *config, struct aura_srv_listener_conf *lc) {
    const st_aura_blob_node *nodes, *server_name_node, *server_port_node, *cert_file_node, *key_file_node;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const st_aura_blob_arr_entry *arrs;
    const char *strtab;
    const int *srv_tab;
    uint32_t arr_cnt, arr_idx, kv_cnt, kv_idx, i, j;
    ptls_cipher_suite_t **cipher_suites;
    ptls_iovec_t retry_configs;
    ptls_key_exchange_algorithm_t **key_exchanges = ptls_openssl_key_exchanges_all;
    const char *port;
    int res;

    struct {
        ptls_ech_create_opener_t *create_opener;
        ptls_iovec_t retry_configs;
    } ech = {NULL};

    nodes = aura_blob_get_nodes(config);
    kv_pairs = aura_blob_get_kvs(config);
    arrs = aura_blob_get_arrs(config);
    strtab = aura_blob_get_strtab(config);
    srv_tab = aura_blob_get_tab(config);

    aura_blob_param_st blob_arg = {
      .nodes = nodes,
      .kv_pairs = kv_pairs,
      .arrs = arrs,
      .strtab = strtab,
    };

    /* parse server */
    if (srv_tab[A_IDX_SERVER_NAME] != 0) {
        server_name_node = &nodes[srv_tab[A_IDX_SERVER_NAME]];
    }

    if (srv_tab[A_IDX_SERVER_PORT] != 0) {
        server_port_node = &nodes[srv_tab[A_IDX_SERVER_PORT]];
        port = strtab + server_port_node->str_offset;
    }

    /* parse ciphers */
    if (srv_tab[A_IDX_TLS_CIPHERS] != 0) {
        cipher_suites = a_parse_ciphers_suites(&blob_arg, &nodes[srv_tab[A_IDX_TLS_CIPHERS]]);
    }

    // A_IDX_ECH_NODE
    if (lc->tls_pool.cnt > 0 && lc->tls_pool.idens[0].contexts.tls1_3.ctx != NULL) {
        ptls_context_t *ptls_ctx = lc->tls_pool.idens[0].contexts.tls1_3.ctx;
        ech.create_opener = ptls_ctx->ech.server.create_opener;
        ech.retry_configs = ptls_ctx->ech.server.retry_configs;
    }

    /* parse tls */
    if (srv_tab[A_IDX_TLS_IDEN] != 0) {
        const st_aura_blob_node *tls_ident_node, *tls_ident_entry_node;
        /* get tls sequence node */
        tls_ident_node = &nodes[srv_tab[A_IDX_TLS_IDEN]];
        uint32_t arr_cnt = tls_ident_node->arr.arr_cnt;
        uint32_t arr_idx = tls_ident_node->arr.arr_idx;

        for (i = 0; i < arr_cnt; ++i) {
            /* for each map entry inside tls sequence */
            tls_ident_entry_node = &nodes[arrs[arr_idx + i].node_idx];
            res = a_tls_add_iden(&blob_arg, tls_ident_entry_node, key_exchanges, cipher_suites, ech.create_opener, ech.retry_configs, lc);
            if (res) {
                sys_exit(true, errno, "Failed to add tls identity");
            }
        }
    }
    app_debug(true, 0, "----tls added suc");

    /* parse hosts */
    if (srv_tab[A_IDX_HOSTS] != 0) {
        const st_aura_blob_node *host_node, *entry_node;
        struct addrinfo *ailist, *aip;
        struct aura_iovec *h2_origin_frames = NULL;
        struct aura_srv_sock *sock;
        const char *key, *hostname = NULL, *tls = NULL;
        int fd, tls_idx = -1;

        /* hosts sequence node */
        host_node = &nodes[srv_tab[A_IDX_HOSTS]];
        arr_cnt = host_node->arr.arr_cnt;
        arr_idx = host_node->arr.arr_idx;

        for (i = 0; i < arr_cnt; ++i) {
            host_node = &nodes[arrs[arr_idx + i].node_idx];
            kv_cnt = host_node->map.kv_cnt;
            kv_idx = host_node->map.kv_idx;

            for (j = 0; j < kv_cnt; ++j) {
                kv = &kv_pairs[kv_idx + j];
                key = strtab + kv->key_offset;
                entry_node = &nodes[kv->node_idx];

                if (strcmp(key, "name") == 0) {
                    hostname = strtab + entry_node->str_offset;
                    ailist = a_resolve_address(hostname, port, IPPROTO_TCP, SOCK_STREAM);
                    if (ailist == NULL)
                        app_exit(true, 0, "Failed to resolve address");

                    for (aip = ailist; aip != NULL; aip = aip->ai_next) {
                        res = a_listener_is_new(aip->ai_addr, aip->ai_addrlen);
                        if (!res)
                            continue;

                        sock = a_server_init(SOCK_STREAM, aip->ai_addr, aip->ai_addrlen);
                        if (sock == NULL) {
                            sys_debug(true, errno, "Failed to initialize server for %s", hostname);
                            continue;
                        }
                        break;
                    }

                    if (sock == NULL)
                        // freeaddrinfo(ailist);
                        app_exit(true, errno, "Failed to setup listener_conf");
                    continue;
                }
                add_sock_to_fdmap(sock);

                if (strcmp(key, "tls") == 0) {
                    tls = strtab + entry_node->str_offset;

                    for (int i = 0; i < lc->tls_pool.cnt; ++i) {
                        if (strcmp(tls, lc->tls_pool.idens[i].tag) == 0) {
                            tls_idx = i;
                            break;
                        }
                    }
                    continue;
                }

                if (strcmp(key, "http2_origin_frame") == 0) {
                    h2_origin_frames = a_build_h2_origin_frame(&blob_arg, entry_node);
                    if (!h2_origin_frames)
                        sys_exit(true, errno, "Failed to build h2 origin frames for %s", hostname);
                }
                app_debug(true, 0, "Built origin frames for %s", hostname);
            }

            /* add host */
            res = a_create_host_conf(lc, sock->sock_fd, aip->ai_addr, aip->ai_addrlen, hostname, port, tls_idx, h2_origin_frames);
            if (res == -1)
                sys_exit(true, errno, "Failed to create host config for %s", hostname);

            app_debug(true, 0, "Built host config for %s", hostname);
            /* ocsp */
            struct aura_ocsp_updater ocsp_updater; // attached to host
        }
    }

    aura_install_signal_handler(SIGINT, SIG_IGN);
    aura_install_signal_handler(SIGQUIT, SIG_IGN);
    aura_install_signal_handler(SIGTERM, a_server_shutdown);
    /** @todo: how about SIGPIPE */

    if (glob_conf->user.base != NULL) {
        int err;
        err = aura_drop_privileges(glob_conf->user.base);
        if (err == 1)
            app_exit(true, errno, "Failed to drop privileges");
        else if (err == 2)
            app_exit(true, 0, "Refusing to run as root, failed to drop to 'nobody', set user in the server config");
        glob_conf->user.len = strlen(glob_conf->user.base);
    } else {
        if (getuid() == 0)
            app_exit(true, 0, "Refusing to run as root, failed to drop to 'nobody', set user in the server config");
    }

    // set_capabilities();
    // get capability from config or set normally on linux
    // drop_capabilities();

    // register file configs
    // get throttle response
    // get header commands
    // get redirect options
    // get/register config status handlers
    // get/register debug handler
    // get/register timing config
    // get/register trace (self trace)
    // get/register logging
    app_debug(true, 0, ">>>> Done setting up configurations");
}

/**
 * Setup global server context
 */
struct aura_srv_ctx *a_server_ctx_init(st_aura_evt_loop *loop, struct aura_srv_listener_conf *lc) {
    app_debug(true, 0, "a_server_ctx_init <<<<");
    struct aura_srv_ctx *ctx;

    ctx = malloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));

    ctx->glob_conf = glob_conf;
    ctx->evt_loop = loop;
    ctx->listener_conf = lc;
    loop->srv_ctx = ctx;
    //
    a_list_head_init(&ctx->batches.queues.handshake_queue);
    a_list_head_init(&ctx->batches.queues.fast_lane_queue);
    a_list_head_init(&ctx->batches.queues.standard_queue);
    a_list_head_init(&ctx->batches.queues.background_queue);
    a_list_head_init(&ctx->batches.queues.timeout_queue);
    a_list_head_init(&ctx->batches.queues.write_queue);
    //

    return ctx;
}

static inline int num_of_conn(struct aura_srv_ctx *ctx) {
    return ctx->metrics.connections;
}

/**
 *
 */
static inline void a_close_idle_connections(struct aura_srv_ctx *ctx) {
    if (num_of_conn(ctx) - ctx->glob_conf->conn.soft_limit) {
        // aura_close_idle_connections();
    }
}

/**
 * Parse a function config blob and add it
 * to the function list of a route
 */
int a_parse_function_config(struct iovec data) {
    const st_aura_blob_node *nodes;
    const st_aura_blob_arr_entry *arrs;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const char *strtab;
    const int *fn_tab;
    const st_aura_blob_node *fn_name_node, *fn_desc_node, *hostname_node;
    const st_aura_blob_node *http_trigger_node, *fn_triggers_node, *kv_val_node;
    const st_aura_blob_node *concurrency_node;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx;
    struct aura_fn fn;
    uint64_t fn_code_len;
    const void *config, *fn_code;
    struct aura_srv_host_conf *host;
    const char *kv_key, *kv_val;
    struct aura_iovec iov;
    struct aura_route *new_route;
    int i;
    bool res;

    config = data.iov_base;
    nodes = aura_blob_get_nodes(config);
    kv_pairs = aura_blob_get_kvs(config);
    arrs = aura_blob_get_arrs(config);
    strtab = aura_blob_get_strtab(config);
    fn_tab = aura_blob_get_tab(config);
    fn_code_len = aura_blob_get_opaque_data_len(config);

    memset(&fn, 0, sizeof(fn));

    /* Fn name */
    if (fn_tab[A_IDX_FN_NAME] != 0) {
        fn_name_node = &nodes[fn_tab[A_IDX_FN_NAME]];
        fn.name = strdup(strtab + fn_name_node->str_offset);
    }

    /**
     * Check host early, so we don't do any work
     * if the function does not belong to any host
     */
    host = NULL;
    if (fn_tab[A_IDX_FN_HOST] != 0) {
        const char *hostname;

        hostname_node = &nodes[fn_tab[A_IDX_FN_HOST]];
        hostname = strtab + hostname_node->str_offset;
        for (int i = 0; i < glob_conf->host_pool.cnt; ++i) {
            if (strcmp(glob_conf->host_pool.hosts[i].authority.hostname.base, hostname) == 0) {
                host = &glob_conf->host_pool.hosts[i];
                break;
            }
        }
    } else {
        app_debug(true, 0, "Function: %s does not define a valid host name", fn.name);
        return -1;
    }

    if (!host) {
        app_debug(true, 0, "Function: %s does not define a valid host name", fn.name);
        return -1;
    }

    /* Fn description */
    if (fn_tab[A_IDX_FN_DESCRIPTION] != 0) {
        fn_desc_node = &nodes[fn_tab[A_IDX_FN_DESCRIPTION]];
        fn.description = strdup(strtab + fn_desc_node->str_offset);
    }

    /* FN triggers */
    if (fn_tab[A_IDX_FN_TRIGGERS] != 0) {
        fn_triggers_node = &nodes[fn_tab[A_IDX_FN_TRIGGERS]];
        /* http */
        if (fn_tab[A_IDX_FN_HTTP_TRIGGER] != 0) {
            http_trigger_node = &nodes[fn_tab[A_IDX_FN_HTTP_TRIGGER]];
            kv_idx = http_trigger_node->map.kv_idx;
            kv_cnt = http_trigger_node->map.kv_cnt;

            for (i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "path") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    fn.http_trigger.path.base = strdup(kv_val);
                    fn.http_trigger.path.len = strlen(kv_val);
                }

                if (strcmp(kv_key, "method") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    if (strcmp(kv_val, "GET"))
                        fn.http_trigger.http_method = GET;
                    else if (strcmp(kv_val, "POST") == 0)
                        fn.http_trigger.http_method = POST;
                    else {
                        // add others
                    }
                }

                if (strcmp(kv_key, "auth")) {
                    // handle auth
                }
            }
        }

        /* others */
    }

    /* Concurrency */
    const char *instances;
    if (fn_tab[A_IDX_FN_MIN_INSTANCES] != 0) {
        concurrency_node = &nodes[fn_tab[A_IDX_FN_MIN_INSTANCES]];
        instances = strtab + concurrency_node->str_offset;
        aura_scan_str(instances, "%d" SCNu32, &fn.fn_concurrency.min_instances);
    }

    if (fn_tab[A_IDX_FN_MAX_INSTANCES] != 0) {
        concurrency_node = &nodes[fn_tab[A_IDX_FN_MAX_INSTANCES]];
        instances = strtab + concurrency_node->str_offset;
        aura_scan_str(instances, "%d" SCNu32, &fn.fn_concurrency.max_instances);
    }

    /* Fn code */
    fn_code = aura_blob_get_opaque_data(config);
    fn.fn_code = malloc(fn_code_len);
    memcpy(fn.fn_code, fn_code, fn_code_len);
    fn.fn_code_len = fn_code_len;

    /* add a route for this function */
    res = aura_route_add(&host->router, 1, &fn);
    if (!res) {
        /* free fn allocated stuff */
        sys_debug(true, errno, "Failed to add route to host: %s", host->authority.hostname);
        return -1;
    }

    return 0;
}

/**
 *  Handle internal requests
 */
static inline void a_handle_internal_request(st_aura_evt_loop *loop) {
    struct aura_msg msg;
    struct aura_msg_hdr hdr, res_hdr;
    int res;

    res = aura_recv_msg(loop->dmn_fd, &msg);
    aura_dump_msg(&msg, true);
    if (res < 0) {
        sys_debug(true, errno, "aura_recv_msg failed: res: %d", res);
        loop->srv_ctx->batches.internal = false;
        aura_evt_loop_stop(loop);
        return;
    } else if (res == 0) {
        /* daemon stopped */
        app_debug(true, 0, "DAEMON STOPPED");
        loop->srv_ctx->batches.internal = false;
        aura_evt_loop_stop(loop);
        return;
    }
    hdr = msg.hdr;

    switch (hdr.type) {
    case A_MSG_PING:
        a_init_msg_hdr(res_hdr, 0, A_MSG_PING, 0);
        aura_msg_send(loop->dmn_fd, &res_hdr, NULL, 0, -1);
        break;

    case A_MSG_CMD_EXECUTE:
        switch (hdr.cmd_type) {
        case A_CMD_SERVER_STOP:
            /* initiate close */
            aura_evt_loop_stop(loop);
            break;
        case A_CMD_FN_DEPLOY:
            a_parse_function_config(msg.data);
            // handle error internally by reading and parsing from the file if neccessary
            break;
        default:
            app_debug(true, 0, "Unknown cmd type %d", hdr.cmd_type);
            break;
        }
        break;
    default:
        app_debug(true, 0, "Unknown msg type %d", hdr.type);
    }
    /* add back to evt loop */
    loop->ops->add(loop, loop->dmn_fd, AURA_EVENT_READ);
    // aura_evt_loop_add(loop, loop->dmn_fd, AURA_EVENT_READ);
    loop->srv_ctx->batches.internal = false;
}

/**
 * Setup global memory context
 */
bool a_setup_memory() {
    struct aura_slab_cache *sc;
    bool res;

    aura_memory_ctx_init(&glob_conf->mem_ctx);

    res = aura_create_dynamic_slab_alloc_caches(&glob_conf->mem_ctx);
    if (!res)
        goto exception;

    /* socket slab cache */
    sc = aura_slab_cache_create(&glob_conf->mem_ctx, A_SLAB_CACHE_ID_SOCK, "socket", sizeof(struct aura_srv_sock), NULL, 0);
    if (!sc)
        goto exception;

    /* h2 connection slab cache */
    sc = aura_slab_cache_create(&glob_conf->mem_ctx, A_SLAB_CACHE_ID_CONNECTION, "h2 connection", sizeof(struct aura_h2_conn), NULL, 0);
    if (!sc)
        goto exception;

    /* stream slab cache */
    sc = aura_slab_cache_create(&glob_conf->mem_ctx, A_SLAB_CACHE_ID_STREAM, "stream", sizeof(struct aura_h2_stream), NULL, 0);
    if (!sc)
        goto exception;

    // aura_slab_cache_dump(sc);
    // struct aura_srv_sock *sock;
    // sock = a_sock_alloc(&glob_conf->mem_ctx);
    // app_debug(true, 0, "<><><><><> Alloc");
    // aura_slab_cache_dump(sc);
    // aura_slab_free(sock);
    // app_debug(true, 0, "<><><><><> Free");
    // aura_slab_cache_dump(sc);
    return true;

exception:
    aura_memory_ctx_destroy(&glob_conf->mem_ctx);
    return false;
}

/**
 * Main server loop, the engine that runs
 * our desperate dream
 */
int a_run_loop(struct aura_srv_ctx *ctx) {
    st_aura_evt_loop *loop;
    struct aura_srv_sock *s, *s1;
    struct aura_msg msg;
    int max_accept = 500;
    int timeout_ms = 1000;
    int num_of_events, res, fd;

    loop = ctx->evt_loop;
    aura_evt_loop_start(loop);
    while (loop->running) {
        a_close_idle_connections(ctx);
        loop->ops->poll(loop, timeout_ms, max_accept);
        // aura_evt_loop_poll(loop, timeout_ms, max_accept);

        if (loop->srv_ctx->batches.internal == true) {
            a_handle_internal_request(loop);
        }

        /* process handshakes */
        a_list_for_each(s, &loop->srv_ctx->batches.queues.handshake_queue, s_list) {
            loop->ops->remove(loop, s->sock_fd);
            // aura_evt_loop_remove(loop, s->sock_fd);
            aura_handle_handshake(s, ctx);
        }

        /* Move completed handshakes and also close some folks! */
        a_list_for_each_safe_to_delete(s, s1, &loop->srv_ctx->batches.queues.handshake_queue, s_list) {
            if ((s->flags & A_SOCK_HANDSHAKE) == 0) {
                a_list_delete(&s->s_list);
                a_list_add(&loop->srv_ctx->batches.queues.fast_lane_queue, &s->s_list);
            } else if ((s->flags & A_SOCK_CLOSED) != 0) {
                aura_socket_destroy(s);
                a_list_delete(&s->s_list);
                app_debug(true, 0, "Should close this socket");
            }
        }

        /* process folks who are ready! */
        a_list_for_each(s, &loop->srv_ctx->batches.queues.fast_lane_queue, s_list) {
            loop->ops->remove(loop, s->sock_fd);
            // aura_evt_loop_remove(loop, s->sock_fd);
            aura_conn_proceed(s, ctx);
        }

        /* write to folks to are wise */
        a_list_for_each(s, &loop->srv_ctx->batches.queues.write_queue, s_list) {
            /**/
        }

        /* close folks who need closing! */
        a_list_for_each_safe_to_delete(s, s1, &loop->srv_ctx->batches.queues.fast_lane_queue, s_list) {
            if ((s->flags & A_SOCK_CLOSED) != 0) {
                a_list_delete(&s->s_list);
                app_debug(true, 0, "Should close this socket");
            }
        }

        /* rearm hopeful clients! */
        a_list_for_each(s, &loop->srv_ctx->batches.queues.handshake_queue, s_list) {
            loop->ops->add(loop, s->sock_fd, AURA_EVENT_READ);
            // aura_evt_loop_add(loop, s->sock_fd, AURA_EVENT_READ);
        }

        /* rearm clients who mean business! */
        a_list_for_each(s, &loop->srv_ctx->batches.queues.fast_lane_queue, s_list) {
            loop->ops->add(loop, s->sock_fd, AURA_EVENT_READ);
            // aura_evt_loop_add(loop, s->sock_fd, AURA_EVENT_READ);
        }

        /* handle others */
    }

    /* perform cleanup */
    return 0;
}

/**
 * Setup default global configuration
 * substituted when config is parsed
 */
static inline int a_glob_conf_init() {
    memset(glob_conf, 0, sizeof(struct aura_srv_global_conf));
    glob_conf->boot_time = aura_now_ms();

    return 0;
}

/**
 * Setup listener config
 */
static inline int a_listener_conf_init(struct aura_srv_listener_conf *lc) {
    memset(lc, 0, sizeof(*lc));
    lc->sni = aura_rax_new();
    if (!lc->sni)
        return 1;
    lc->fd_pool.fds = NULL;
    lc->tls_pool.idens = NULL;
    lc->ptls = NULL;
    lc->bpf_program = NULL;
    return 0;
}

/**
 * Load busy functions
 */
static void a_load_functions() {
    // DIR
}

/**
 * Let us Begin
 */
int main(int argc, char *argv[]) {
    int res;
    int sock_fd;
    struct aura_msg msg;
    struct aura_msg_hdr hdr;
    void *config;
    struct aura_srv_listener_conf *listener_conf;
    struct aura_srv_ctx *ctx;
    st_aura_evt_loop *loop;
    pthread_t sb_man_thread;
    struct aura_sb_man_params *sb_man_params;

    aura_scan_str(argv[1], "%" SCNu32, &sock_fd);
    /** @todo: check against OPENMAX */

    aura_recv_msg(sock_fd, &msg);
    config = msg.data.iov_base;

    glob_conf = alloca(sizeof(*glob_conf));
    if (!glob_conf) {
        sys_debug(true, errno, "Failed to create global config");
        goto exception;
    }

    res = a_glob_conf_init();
    if (res) {
        sys_debug(true, errno, "Failed to initialize global configs");
        goto exception;
    }

    res = a_setup_memory();
    if (!res) {
        sys_debug(true, errno, "Failed to create memory context!");
        goto exception;
    }

    listener_conf = alloca(sizeof(*listener_conf));
    if (!listener_conf)
        goto exception;

    res = a_listener_conf_init(listener_conf);
    if (res) {
        sys_debug(true, 0, "Failed to init listener conf");
        goto exception;
    }

    a_setup_configs(config, listener_conf);
    free(config);

    loop = aura_evt_loop_create(sock_fd, 100);
    if (!loop) {
        sys_debug(false, errno, "Failed to create event loop");
        goto exception;
    }

    ctx = a_server_ctx_init(loop, listener_conf);
    if (!ctx) {
        sys_debug(true, errno, "Failed to create server context");
        goto exception;
    }

    /* alert daemon we may have succeeded */
    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);
    res = aura_msg_send(sock_fd, &hdr, NULL, 0, -1);

    /* register fds to poll */
    loop->ops->add(loop, sock_fd, AURA_EVENT_READ);
    for (int i = 0; i < listener_conf->fd_pool.cnt; ++i) {
        loop->ops->add(loop, listener_conf->fd_pool.fds[i], AURA_EVENT_READ);
    }

    a_run_loop(ctx);

    exit(0);
exception:
    sys_info(true, errno, "Server exiting");
    exit(1);
}
