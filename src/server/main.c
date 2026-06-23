#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <alloca.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#include "blobber/lib.h"
#include "connection.h"
#include "db/broker.h"
#include "db/db.h"
#include "error_lib.h"
#include "evt_loop_srv.h"
#include "fn/lib.h"
#include "h2/server.h"
#include "heap/lib.h"
#include "host.h"
#include "mem.h"
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
#include "server_srv.h"
#include "slab.h"
#include "socket_srv.h"
#include "string_lib.h"
#include "types_lib.h"
#include "unix/sock.h"
#include "user/user.h"

#define A_MAX_PRELOAD_FN_CNT 5

/* Max nr of open FD */
static long AURA_OPEN_MAX = 0;

/**/
static int aura_ocsp_timer_fd = -1;

/**
 * We update ocsp via the same epoll setup for the general server
 * call after aura_daemonize as timer is not inherited
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

static int a_conn_pool_init(struct aura_srv_conn_pool *pool, struct aura_mem_ctx *mc) {
    struct aura_rh_map_key key;

    memset(pool, 0, sizeof(*pool));

    pthread_mutex_init(&pool->mutex, NULL);

    if (aura_rh_map_init(&pool->pool, mc, 16, A_RH_KEY_STR, true) < 0)
        return -1;

    return 0;
}

static void a_conn_pool_destroy(struct aura_srv_conn_pool *pool) {
    if (!pool)
        return;

    pthread_mutex_destroy(&pool->mutex);
    aura_rh_map_destroy(&pool->pool);
}

/**
 * check for host configuration that handles the request
 * and return a pointer to it
 */
struct aura_srv_host_conf *a_resolve_sni(struct aura_srv_listeners_conf *lc, const char *server_name) {
    aura_rax_node_t *host_node;

    app_debug(true, 0, "A_RESOLVE_SNI servername=%s, len=%u", server_name, strlen(server_name));
    host_node = aura_rax_lookup(lc->sni, server_name, strlen(server_name));
    if (!host_node)
        return NULL;

    if (host_node->data.type != A_RAX_DATA_PTR) {
        app_debug(true, 0, "a_resolve_sni: Incorrect data format!: %d", host_node->data.type);
        return NULL;
    }

    return host_node->data.ptr_val;
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
 * Store on_client_hello in a wrapper context
 * as hello function requires more context
 * that provided directly by 'ptls_on_client_hello_t'
 */
struct aura_on_client_hello_ptls {
    ptls_on_client_hello_t super;
    struct aura_srv_listeners_conf *listener;
};

/**
 * Client hello callback
 */
static int a_on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls_conn, ptls_on_client_hello_parameters_t *hello_params) {
    struct aura_srv_host_conf *host_config;
    struct aura_srv_tls_iden *chosen_tls_identity, *tls_identity;
    struct aura_srv_listeners_conf *lc;
    struct aura_on_client_hello_ptls *super_self_st;
    bool prefer_raw_public_key;
    struct aura_conn *conn_data;
    int res;

    if (hello_params->incompatible_version)
        return 0;

    super_self_st = (struct aura_on_client_hello_ptls *)self;
    lc = super_self_st->listener;
    /* struct aura_conn */
    conn_data = (*ptls_get_data_ptr(tls_conn));

    if (hello_params->server_name.base != NULL) {
        host_config = a_resolve_sni(lc, hello_params->server_name.base);
        A_BUG_ON_2(!host_config, true);
        conn_data->host = host_config;
        ptls_set_server_name(tls_conn, (const char *)hello_params->server_name.base, hello_params->server_name.len);
        ptls_log_recalc_conn_state(a_get_conn_log_state(conn_data));
    } else {
        /* Use fallback host config */
        host_config = super_self_st->listener->fb_host_conf;
        A_BUG_ON_2(!host_config, true);
    }

    prefer_raw_public_key = hello_params->server_certificate_types.count > 0 && memchr(hello_params->server_certificate_types.list, PTLS_CERTIFICATE_TYPE_RAW_PUBLIC_KEY, hello_params->server_certificate_types.count) != NULL;
    chosen_tls_identity = &lc->tls_pool.entries[host_config->def_tls_off];
    if (chosen_tls_identity->contexts.ptls.ctx->use_raw_public_keys != prefer_raw_public_key) {
        for (size_t i = 0; i < host_config->other_tls_cnt; ++i) {
            if (lc->tls_pool.entries[host_config->other_tls_off[i]].contexts.ptls.ctx->use_raw_public_keys == prefer_raw_public_key) {
                tls_identity = &lc->tls_pool.entries[host_config->other_tls_off[i]];
                if (hello_params->signature_algorithms.count == 0) {
                    chosen_tls_identity = tls_identity;
                    goto identity_found;
                }

                for (size_t j = 0; tls_identity->contexts.ptls.sig_schemes[i].scheme_id != UINT16_MAX; ++j) {
                    for (size_t k = 0; k < hello_params->signature_algorithms.count; ++k)
                        if (tls_identity->contexts.ptls.sig_schemes[j].scheme_id == hello_params->signature_algorithms.list[k]) {
                            chosen_tls_identity = tls_identity;
                            goto identity_found;
                        }
                }
            }
        }
    }
identity_found:
    ptls_set_context(tls_conn, chosen_tls_identity->contexts.ptls.ctx);

    /* ALNP */
    if (hello_params->negotiated_protocols.count != 0) {
        for (size_t i = 0; i < hello_params->negotiated_protocols.count; ++i) {
            return ptls_set_negotiated_protocol(tls_conn, "h2", sizeof("h2") - 1);
        }
    }
    return PTLS_ALERT_PROTOCOL_VERSION; /* not h2 */
}

/**
 * Store ptls emit cert in a wrapper context
 * as the emit function requires more context
 * than provided by the 'ptls_emit_certificate_t'
 */
struct aura_on_emit_certificate_ptls {
    ptls_emit_certificate_t super;
    struct aura_srv_tls_iden *tls_identity;
};

/**
 * Emit certificate callback
 */
static int a_on_emit_certificate(ptls_emit_certificate_t *self, ptls_t *tls, ptls_message_emitter_t *emitter,
                                 ptls_key_schedule_t *key_sched, ptls_iovec_t context, int push_status_request,
                                 const uint16_t *compress_algos, size_t num_compress_algos) {

    struct aura_on_emit_certificate_ptls *super_st;
    ptls_emit_certificate_t *emit_comp;
    ptls_context_t *tlsctx;
    void *ocsp_response;
    int ret;

    /* get wrapper context */
    super_st = (struct aura_on_emit_certificate_ptls *)self;

    if (super_st->tls_identity->compressed_cert.emit_ptls != NULL) {
        emit_comp = &super_st->tls_identity->compressed_cert.emit_ptls->super;
        ret = emit_comp->cb(emit_comp, tls, emitter, key_sched, context, push_status_request, compress_algos, num_compress_algos);
        if (ret != PTLS_ERROR_DELEGATE)
            goto Exit;
    }

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
        ptls_context_t *tls_ctx = ptls_get_context(tls);
        void *ocsp_response = push_status_request ? super_st->tls_identity->ocsp.ocsp_stapling.ocsp_response : NULL;
        size_t ocsp_response_len = super_st->tls_identity->ocsp.ocsp_stapling.ocsp_response_len;
        ret = ptls_build_certificate_message(
          emitter->buf,
          ptls_iovec_init(NULL, 0),
          tls_ctx->certificates.list,
          tls_ctx->certificates.count,
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
    ptls_context_t ctx;        /* server context */
    ptls_context_t client_ctx; /* client context */
    struct aura_on_client_hello_ptls ch;
    struct aura_on_emit_certificate_ptls ec;
    struct {
        ptls_openssl_sign_certificate_t ossl;

    } sc;
    ptls_openssl_verify_certificate_t vc;
};

/**
 *
 */
static int a_setup_tls(struct aura_srv_listeners_conf *lc, ptls_key_exchange_algorithm_t **key_ex,
                       ptls_cipher_suite_t **cipher_suites, ptls_ech_create_opener_t *ech_create_opener,
                       ptls_iovec_t ech_retry_configs, unsigned int server_cipher_preference,
                       ptls_iovec_t raw_public_key, struct aura_srv_tls_iden *iden,
                       bool client_verify) {
    struct aura_ptls_super_ctx *ptls_super_ctx;
    EVP_PKEY *key;
    int res;

    ptls_super_ctx = calloc(1, sizeof(*ptls_super_ctx));
    if (!ptls_super_ctx)
        app_exit(true, errno, "Out of memory");

    *ptls_super_ctx = (struct aura_ptls_super_ctx){
      /* server ctx */
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
      /* client ctx */
      .client_ctx = {
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
        .verify_certificate = NULL, /* set below */
        .ticket_lifetime = 0,       /* not yet supported */
        .max_early_data_size = 0,   /* not yet supported */
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

    key = a_load_key(iden->key.key_file);
    if (!key)
        sys_exit(true, 0, "a_load_key() failed");

    /* use default */
    iden->contexts.store = X509_STORE_new();
    X509_STORE_set_default_paths(iden->contexts.store);
    /** @todo: remove after testing */
    X509_STORE_load_locations(iden->contexts.store, "/home/lukwiya/studies/C/vaulten_aura/tests/scripts/ca_cert.pem", NULL);

    if (ptls_openssl_init_verify_certificate(&ptls_super_ctx->vc, iden->contexts.store) != 0) {
        sys_exit(true, 0, "ptls openssl init verify certificate failed");
    }
    ptls_super_ctx->client_ctx.verify_certificate = &ptls_super_ctx->vc.super;

    if (client_verify) {
        ptls_super_ctx->ctx.require_client_authentication = 1;
        ptls_super_ctx->ctx.verify_certificate = &ptls_super_ctx->vc.super;
    }

    if (ptls_openssl_init_sign_certificate(&ptls_super_ctx->sc.ossl, key) != 0) {
        sys_exit(true, 0, "ptls openssl init sign certificate failed");
    }
    ptls_super_ctx->ctx.sign_certificate = &ptls_super_ctx->sc.ossl.super;

    if (raw_public_key.base == NULL) {
        res = ptls_load_certificates(&ptls_super_ctx->ctx, iden->cert.cert_file);
        A_BUG_ON_2(res != 0, true);
    } else {
        ptls_super_ctx->ctx.certificates.list = malloc(sizeof(ptls_super_ctx->ctx.certificates.list[0]));
        ptls_super_ctx->ctx.certificates.list[0] = raw_public_key;
        ptls_super_ctx->ctx.certificates.count = 1;
        ptls_super_ctx->ctx.use_raw_public_keys = 1;
        ptls_super_ctx->ctx.emit_certificate = NULL;
    }

    iden->contexts.ptls.ctx = &ptls_super_ctx->ctx;
    iden->contexts.ptls.client_ctx = &ptls_super_ctx->client_ctx;
    iden->contexts.ptls.sig_schemes = ptls_super_ctx->sc.ossl.schemes;
    return 0;
}

/**
 * Test if the listener config provided can
 * allow creating a new listener
 */
static bool a_listener_is_new(struct aura_srv_listeners_conf *lc,
                              struct sockaddr *addr, socklen_t addr_len) {
    int i;
    struct sockaddr *a;
    struct sockaddr_in *ip4_a, *ip4_b;

    for (i = 0; i < lc->listeners_pool.cnt; ++i) {
        a = &lc->listeners_pool.entries[i].addr;

        if (lc->listeners_pool.entries[i].addr_len != addr_len)
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
 * Setup socket for accepting connections.
 */
static int a_server_init(int type, struct sockaddr *serv_addr, socklen_t addr_len) {
    int fd;
    int reuse = 1;
    int err;

    fd = socket(serv_addr->sa_family, type, 0);
    if (fd < 0) {
        sys_debug(true, errno, "Failed to initialize server");
        return -1;
    }

    if (serv_addr->sa_family == AF_INET && type == SOCK_STREAM) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            goto exception;
    } else {
        app_exit(true, 0, "Unsuported domain: %d of type: %d", serv_addr->sa_family, type);
    }

    if (bind(fd, serv_addr, addr_len) < 0)
        goto exception;

    if (type == SOCK_STREAM)
        if (listen(fd, AURA_QLEN) < 0)
            goto exception;

    aura_set_fd_flag(fd, O_NONBLOCK);

    return fd;
exception:
    err = errno;
    close(fd);
    errno = err;
    return -1;
}

int a_listener_init(struct aura_srv_listener *listener, struct aura_srv_listeners_conf *lc) {
    struct addrinfo *ailist, *aiptr;
    int type, protocol;
    int reuse = 1;

    type = listener->protocol == A_PROTOCOL_TCP ? SOCK_STREAM : SOCK_DGRAM;
    protocol = listener->protocol == A_PROTOCOL_TCP ? IPPROTO_TCP : IPPROTO_UDP;

    ailist = a_resolve_address(listener->address, listener->port, protocol, type);
    if (!ailist)
        return -1;

    for (aiptr = ailist; aiptr != NULL; aiptr = aiptr->ai_next) {
        if (!a_listener_is_new(lc, aiptr->ai_addr, aiptr->ai_addrlen))
            continue;

        if ((listener->fd = a_server_init(type, aiptr->ai_addr, aiptr->ai_addrlen)) < 0)
            continue;
        break;
    }

    if (listener->fd < 0) {
        freeaddrinfo(ailist);
        return -1;
    }

    switch (listener->protocol) {
    case A_PROTOCOL_TCP:
        // if (listener->tls)
        listener->on_event = aura_conn_tcp_listener_event_handler;
        // else
        //     listener->on_event = aura_conn_listener_event_handler;
        break;

    case A_PROTOCOL_UDP:
    default:
        break;
    }

    listener->addr_len = aiptr->ai_addrlen;
    // memcpy(&listener->addr, aiptr->ai_addr, sizeof(*aiptr->ai_addr));
    memcpy(&listener->addr, aiptr->ai_addr, sizeof(struct sockaddr));

    return 0;
}

/**
 *
 */
void a_server_shutdown(int signo) {
    app_info(true, 0, "Shutdown signal(->server)!");
    exit(0);
}

/**
 * NOTE:
 * Server config table indexes,
 * This must match the one defined in
 * the daemon. When updating one, update
 * the other as well
 */
enum srv_node_idx {
    A_IDX_SERVER_NONE,
    A_IDX_SERVER_NAME,
    A_IDX_SERVER_READ_TO,     // read timeout
    A_IDX_SERVER_WRITE_TO,    // write timeout
    A_IDX_SERVER_LISTENERS,   // socket listeners
    A_IDX_SERVER_TLS_IDEN,    // tls identities
    A_IDX_SERVER_TLS_CIPHERS, // tls ciphers
    A_IDX_SERVER_HOSTS        // hosts
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
    if (!cs)
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
 * Test if provided tls identity pair (cert and key)
 * are new
 */
static bool a_tls_is_new(struct aura_srv_listeners_conf *lc, const char *cert_file, const char *key_file) {
    if (lc->tls_pool.entries == NULL)
        return true;

    for (int i = 0; i < lc->tls_pool.cnt; ++i) {
        if (strcmp(cert_file, lc->tls_pool.entries[i].cert.cert_file))
            return true;

        if (strcmp(key_file, lc->tls_pool.entries[i].key.key_file))
            return true;
    }

    return false;
}

static struct aura_srv_tls_iden *a_get_tls_iden_slot(struct aura_srv_listeners_conf *lc) {
    if (lc->tls_pool.cnt >= lc->tls_pool.cap) {
        lc->tls_pool.cap = lc->tls_pool.cap == 0 ? 5 : lc->tls_pool.cap * 2;
        lc->tls_pool.entries = realloc(lc->tls_pool.entries, sizeof(struct aura_srv_tls_iden) * lc->tls_pool.cap);
        if (!lc->tls_pool.entries)
            return NULL;
    }

    return &lc->tls_pool.entries[lc->tls_pool.cnt++];
}

/**
 * Add tls identity to the global tls pool
 */
static int a_tls_add_iden(const aura_blob_param_st *blob, const st_aura_blob_node *tls_ident_entry_node,
                          ptls_key_exchange_algorithm_t **key_ex, ptls_cipher_suite_t **cs,
                          ptls_ech_create_opener_t *create_opener, ptls_iovec_t retry_configs,
                          struct aura_srv_listeners_conf *lc) {

    struct aura_srv_tls_iden *iden;
    const st_aura_blob_node *entry_node;
    const st_aura_blob_kv_pair *kv;
    ptls_iovec_t raw_pubkey = {NULL};
    uint32_t kv_cnt, kv_idx, i;
    const char *key, *cert_chain_file = NULL, *key_file = NULL, *tag = NULL;
    int res;

    kv_cnt = tls_ident_entry_node->map.kv_cnt;
    kv_idx = tls_ident_entry_node->map.kv_idx;

    /* extract value from kv entries */
    for (i = 0; i < kv_cnt; ++i) {
        kv = &blob->kv_pairs[kv_idx + i];
        key = blob->strtab + kv->key_offset;
        entry_node = &blob->nodes[kv->node_idx];

        /* What is loaded is the chain cert file */
        if (strcmp(key, "cert_file") == 0) {
            cert_chain_file = blob->strtab + entry_node->str_offset;
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

    if (!a_tls_is_new(lc, cert_chain_file, key_file))
        return 0;

    iden = a_get_tls_iden_slot(lc);
    if (!iden)
        return -1;

    iden->cert.cert_file = strdup(cert_chain_file);
    iden->key.key_file = strdup(key_file);
    iden->tag = tag ? strdup(tag) : NULL;

    res = a_setup_tls(lc, key_ex, cs, create_opener, retry_configs, 0, raw_pubkey, iden, false);
    return res;
err:
    return -1;
}

/**
 * Parse configs received from daemon
 */
static int a_setup_configs(struct aura_srv_global_ctx *gc, void *config) {
    const st_aura_blob_node *nodes, *server_name_node, *server_port_node, *cert_file_node, *key_file_node;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const st_aura_blob_arr_entry *arrs;
    const char *strtab;
    const int *srv_tab;
    uint32_t arr_cnt, arr_idx, kv_cnt, kv_idx, i, j;
    ptls_cipher_suite_t **cipher_suites;
    ptls_iovec_t retry_configs;
    ptls_key_exchange_algorithm_t **key_exchanges = ptls_openssl_key_exchanges_all;
    int res;

    struct {
        ptls_ech_create_opener_t *create_opener;
        ptls_iovec_t retry_configs;
    } ech = {NULL};

    struct aura_srv_listeners_conf *lc = &gc->listeners;

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

    /* parse ciphers */
    if (srv_tab[A_IDX_SERVER_TLS_CIPHERS] != 0) {
        cipher_suites = a_parse_ciphers_suites(&blob_arg, &nodes[srv_tab[A_IDX_SERVER_TLS_CIPHERS]]);
    }

    /* ech */
    if (lc->tls_pool.cnt > 0 && lc->tls_pool.entries[0].contexts.ptls.ctx != NULL) {
        ptls_context_t *ptls_ctx = lc->tls_pool.entries[0].contexts.ptls.ctx;
        ech.create_opener = ptls_ctx->ech.server.create_opener;
        ech.retry_configs = ptls_ctx->ech.server.retry_configs;
    }

    /* parse tls */
    if (srv_tab[A_IDX_SERVER_TLS_IDEN] != 0) {
        const st_aura_blob_node *tls_ident_node, *tls_ident_entry_node;
        /* get tls sequence node */
        tls_ident_node = &nodes[srv_tab[A_IDX_SERVER_TLS_IDEN]];
        uint32_t arr_cnt = tls_ident_node->arr.arr_cnt;
        uint32_t arr_idx = tls_ident_node->arr.arr_idx;

        for (i = 0; i < arr_cnt; ++i) {
            /* for each map entry inside tls sequence */
            tls_ident_entry_node = &nodes[arrs[arr_idx + i].node_idx];

            res = a_tls_add_iden(&blob_arg, tls_ident_entry_node, key_exchanges, cipher_suites, ech.create_opener, ech.retry_configs, lc);
            if (res < 0) {
                sys_debug(true, errno, "a_setup_configs: tls iden slot err");
                return -1;
            }
        }
    }

    /* setup listeners */
    if (srv_tab[A_IDX_SERVER_LISTENERS] != 0) {
        const st_aura_blob_node *listener_node, *entry_node;
        struct aura_srv_listener *listener;
        const char *key, *listener_name;

        listener_node = &nodes[srv_tab[A_IDX_SERVER_LISTENERS]];
        arr_cnt = listener_node->arr.arr_cnt;
        arr_idx = listener_node->arr.arr_idx;

        for (i = 0; i < arr_cnt; ++i) {
            listener_node = &nodes[arrs[arr_idx + i].node_idx];
            kv_cnt = listener_node->map.kv_cnt;
            kv_idx = listener_node->map.kv_idx;

            listener = aura_listener_conf_create(&lc->listeners_pool);
            if (!listener) {
                sys_debug(true, 0, "a_setup_configs: listener conf creation err:");
                return -1;
            }

            for (j = 0; j < kv_cnt; ++j) {
                kv = &kv_pairs[kv_idx + j];
                key = strtab + kv->key_offset;
                entry_node = &nodes[kv->node_idx];

                if (strcmp(key, "name") == 0) {
                    listener_name = strtab + entry_node->str_offset;
                    listener->name = strdup(listener_name);
                    continue;
                }

                if (strcmp(key, "address") == 0) {
                    const char *address;
                    address = strtab + entry_node->str_offset;
                    listener->address = strdup(address);
                    continue;
                }

                if (strcmp(key, "port") == 0) {
                    const char *port;
                    port = strtab + entry_node->str_offset;
                    listener->port = strdup(port);
                    continue;
                }

                if (strcmp(key, "protocol") == 0) {
                    const char *protocol;
                    protocol = strtab + entry_node->str_offset;
                    if (aura_scan_str(protocol, "%" SCNu8, &listener->protocol) != 1) {
                        sys_debug(true, errno, "a_setup_config: config protocol err:");
                        return -1;
                    }
                    continue;
                }

                if (strcmp(key, "tls") == 0) {
                    const char *tls;
                    tls = strtab + entry_node->str_offset;
                    if (aura_scan_str(tls, "%" SCNu8, &listener->tls) != 1) {
                        sys_debug(true, errno, "a_setup_config: tls boolean value invalid:");
                        return -1;
                    }
                    continue;
                }

                if (strcmp(key, "quic") == 0) {
                    const char *quic;
                    quic = strtab + entry_node->str_offset;
                    if (aura_scan_str(quic, "%" SCNu8, &listener->quic) != 1) {
                        sys_debug(true, errno, "a_setup_config: quic boolean value invalid:");
                        return -1;
                    }
                    continue;
                }
            }

            if (a_listener_init(listener, lc) < 0) {
                sys_debug(true, errno, "a_setup_configs: listener init err:");
                return -1;
            }
        }
    }

    /* parse hosts */
    if (srv_tab[A_IDX_SERVER_HOSTS] != 0) {
        const st_aura_blob_node *host_node, *entry_node;
        struct addrinfo *ailist, *aip;
        struct aura_iovec *h2_origin_frames = NULL;
        const char *key, *hostname = NULL, *tls = NULL;
        int fd, tls_idx = -1;

        /* hosts sequence node */
        host_node = &nodes[srv_tab[A_IDX_SERVER_HOSTS]];
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
                    if (!hostname) {
                        /* should not happen */
                    }
                }

                if (strcmp(key, "tls") == 0) {
                    tls = strtab + entry_node->str_offset;

                    for (int i = 0; i < lc->tls_pool.cnt; ++i) {
                        if (strcmp(tls, lc->tls_pool.entries[i].tag) == 0) {
                            tls_idx = i;
                            break;
                        }
                    }
                    continue;
                }

                if (strcmp(key, "http2_origin_frame") == 0) {
                    h2_origin_frames = a_build_h2_origin_frame(&blob_arg, entry_node);
                    if (!h2_origin_frames) {
                        sys_debug(true, errno, "a_setup_configs: building origin frame for %s err", hostname);
                        return -1;
                    }
                }
            }

            /* add host */
            struct aura_srv_host_conf *host_conf;
            host_conf = aura_host_config_create(&gc->host_pool, hostname, tls_idx, h2_origin_frames);
            if (!host_conf < 0) {
                sys_debug(true, errno, "a_setup_configs: host config create err: %s", hostname);
                return -1;
            }
            /* set server context */
            host_conf->router.srv_ctx = gc->srv_ctx;

            /* add host + conf to listener sni map */
            if (!aura_rax_insert(lc->sni, hostname, strlen(hostname), A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_ptr(host_conf))) {
                sys_debug(true, errno, "a_setup_configs: sni insert for hostname: %s err", hostname);
                return -1;
            }

            /* ocsp */
            struct aura_ocsp_updater ocsp_updater; // attached to hoste, strlen(hostname), host_conf);
        }
    }

    aura_install_signal_handler(SIGINT, SIG_IGN);
    aura_install_signal_handler(SIGQUIT, SIG_IGN);
    aura_install_signal_handler(SIGTERM, a_server_shutdown);
}

/**
 * Setup global server context
 */
static int a_server_ctx_init(struct aura_srv_global_ctx *gc, struct aura_srv_ctx *ctx, int dmn_fd) {
    struct aura_mem_ctx *mc = &gc->mem_ctx;

    memset(ctx, 0, sizeof(*ctx));
    ctx->glob_conf = gc;
    ctx->next_task_id = 1;
    gc->srv_ctx = ctx;

    if (aura_hpack_load_static_table(mc) < 0) {
        sys_debug(true, errno, "a_server_ctx_init: load static table err");
        return -1;
    }

    if (aura_completion_queue_init(&ctx->completions) < 0) {
        sys_debug(true, errno, "a_server_ctx_init: completion queue err");
        return -1;
    }

    /* Create event loop */
    ctx->evt_loop = aura_evt_loop_create(ctx, AURA_OPEN_MAX);
    if (!ctx->evt_loop) {
        sys_debug(true, errno, "a_server_ctx_init: evt_loop err");
        return -1;
    }

    ctx->conn_tab = aura_dyn_dense_pool_create(A_CONN_TAB_DEFAULT_SZ, sizeof(struct aura_conn_tab_ent));
    if (!ctx->conn_tab) {
        sys_debug(true, errno, "a_server_ctx_init: conn table err");
        return -1;
    }

    if (aura_rh_map_init(&ctx->conn_pool.pool, mc, 32, A_RH_KEY_STR, true) < 0) {
        sys_debug(true, errno, "a_server_ctx_init: conn pool err");
        return -1;
    }

    aura_pending_req_coordinator_init(&ctx->req_coord);

    ctx->dmn_peer = aura_ipc_peer_create(dmn_fd);
    if (!ctx->dmn_peer) {
        sys_debug(true, errno, "a_server_ctx_init: dmn_peer err");
        return -1;
    }

    /* Add to epoll */
    if (aura_evt_loop_add(ctx->evt_loop, dmn_fd, ctx->dmn_peer, AURA_EVENT_READ) < 0) {
        sys_debug(true, errno, "a_server_ctx_init: evt loop add dmn fd err");
        return -1;
    }

    aura_timer_wheel_init(&ctx->timer_wheel);

    aura_list_head_init(&ctx->queues.handshake);
    aura_list_head_init(&ctx->queues.active);
    aura_list_head_init(&ctx->queues.reap);

    return 0;
}

/* Find host by hostname */
static inline struct aura_srv_host_conf *a_find_host(struct aura_srv_global_ctx *gc, const char *hostname) {
    for (int i = 0; i < gc->host_pool.cnt; ++i) {
        if (strcasecmp(hostname, gc->host_pool.hosts[i].hostname.base) == 0) {
            return &gc->host_pool.hosts[i];
        }
    }

    return NULL;
}

void a_load_fn_destructor(const void *stat) {
    struct aura_fn_stat_wrapper *_stat;

    if (!stat)
        return;
    _stat = (struct aura_fn_stat_wrapper *)stat;
    aura_free((void *)_stat->fn_stat);
    aura_free((void *)_stat->fn_name);
    aura_free(_stat);
}

/**
 * Load top k busy functions
 */
static void a_preload_functions(struct aura_srv_global_ctx *gc, int dmn_sock_fd) {
    struct aura_mem_ctx *mc = &gc->mem_ctx;
    struct aura_heap *hp;
    struct aura_functions *fns, fns_copy;
    struct aura_fn_stat *fn_stat;
    struct aura_heap_ent *hp_ent;
    struct aura_fn_stat_wrapper *aux_stat, *_aux_stat;
    struct aura_fn *fn;
    struct aura_srv_host_conf *host;
    int rv, error;
    int i, j;

    hp = aura_alloc(&gc->mem_ctx, sizeof(*hp));
    if (!hp)
        sys_exit(true, errno, "a_preload_functions error : heap alloc");

    if (aura_heap_init(hp, &gc->mem_ctx, A_MAX_PRELOAD_FN_CNT, aura_fn_stat_compare, A_HP_TYPE_MAX_HEAP) < 0)
        sys_exit(true, errno, "a_preload_functions error : aura_heap_init");

    fns = aura_fn_list_fetch_broker(mc, dmn_sock_fd, &error);
    /* No functions deployed yet! */
    if (!fns) {
        /* Fatal error */
        if (error < 0)
            sys_exit(true, errno, "a_preload_functions: aura_fn_list_fetch error:");
        return;
    }

    /**
     * Remove older versions of a function
     * Just create a copy and copy over for now
     * @todo: somehow the db entries are listed earliest first, check to see
     * if latest can be listed first
     */
    if (fns->func_cnt > 0) {
        fns_copy.funcs = calloc(1, sizeof(struct aura_fn_petite) * fns->func_cnt);
        fns_copy.funcs[0] = fns->funcs[fns->func_cnt - 1];
        fns_copy.func_cnt = 1;
        for (int i = fns->func_cnt - 2; i >= 0; --i) {
            int j = 0, k = fns_copy.func_cnt;
            while (j < k) {
                /* add to copy list */
                if (strcmp(fns_copy.funcs[j].fn_name, fns->funcs[i].fn_name) != 0) {
                    fns_copy.funcs[fns_copy.func_cnt++] = fns->funcs[i];
                }
                j++;
            }
        }
    }

    /**
     * Load the top k functions using their stats
     */
    for (int i = 0; i < fns_copy.func_cnt; ++i) {
        fn_stat = aura_fn_stat_fetch_broker(mc, fns_copy.funcs[i].fn_name, fns_copy.funcs[i].fn_version, dmn_sock_fd);
        if (!fn_stat)
            continue;

        aux_stat = aura_alloc(mc, sizeof(*aux_stat));
        if (!aux_stat)
            sys_exit(true, errno, "a_preload_functions: aura_alloc aux_stat error:");

        aux_stat->fn_stat = fn_stat;
        aux_stat->fn_name = aura_strdup(mc, fns_copy.funcs[i].fn_name);
        aux_stat->fn_version = fns_copy.funcs[i].fn_version;

        if (!aura_heap_is_full(hp)) {
            aura_heap_push(hp, &aux_stat->hp_ent);
            continue;
        }

        /**
         * If the heap is full, check if the current stat is "higher" than the
         * min of the heap, if so, replace the min with the current stat.
         * @todo: this will not necessary load the best 5 functions
         * because we evict the best fn so far and not the worst
         */
        hp_ent = aura_heap_peek(hp);
        _aux_stat = aura_container_of(hp_ent, struct aura_fn_stat_wrapper, hp_ent); // aura_heap_peek(hp);
        if (aura_heap_is_full(hp) && aura_fn_stat_compare((void *)aux_stat, (void *)_aux_stat) > 0) {
            hp_ent = aura_heap_pop(hp);
            _aux_stat = aura_container_of(hp_ent, struct aura_fn_stat_wrapper, hp_ent);
            a_load_fn_destructor(_aux_stat);

            assert(aura_heap_push(hp, &aux_stat->hp_ent) == 0);
            continue;
        }

        /**
         * If the heap is full and the current stat does not
         * qualify to be added to the heap, simply get rid of it
         */
        a_load_fn_destructor(_aux_stat);
    }

    /**
     * Add the loaded functions to their respective routes
     */
    // aura_heap_for_each(hp, aux_stat) {
    aura_heap_for_each(hp, hp_ent) {
        aux_stat = aura_container_of(hp_ent, struct aura_fn_stat_wrapper, hp_ent);
        fn = aura_fn_load_broker(mc, aux_stat->fn_name, aux_stat->fn_version, dmn_sock_fd);
        if (!fn) {
            /* Technically should not be possible! */
        } else {
            host = a_find_host(gc, fn->meta.host);
            if (!host) {
                aura_fn_destroy(fn);
                continue;
            }
            if (aura_route_add(&host->router, fn) < 0) {
                aura_fn_destroy(fn);
            }
        }
    }

    aura_free(fns);
    free(fns_copy.funcs);

    /* Clean up heap */
    aura_heap_destroy(hp);
}

/**
 *  Handle internal requests
 */
static inline void a_handle_internal_request(st_aura_evt_loop *loop) {
    struct aura_msg msg;
    struct aura_msg_hdr hdr, res_hdr;
    int res;

    res = aura_msg_recv(loop->srv_ctx->dmn_peer->fd, &msg);
    if (res <= 0) {
        sys_debug(true, errno, "a_handle_internal_request: aura_msg_recv: res: %d", res);
        aura_set_internal_request_inactive(loop->srv_ctx);
        /** @todo: should this kill this server */
        // aura_evt_loop_stop(loop);
        return;
    }

    hdr = msg.hdr;

    switch (hdr.type) {
    case A_MSG_PING:
        a_init_msg_hdr(res_hdr, 0, A_MSG_PING, 0);
        aura_msg_send(loop->srv_ctx->dmn_peer->fd, &res_hdr, NULL, 0, -1);
        break;

    case A_MSG_CMD_EXECUTE:
        switch (hdr.cmd_type) {
        case A_CMD_SERVER_STOP:
            /* initiate close */
            aura_evt_loop_stop(loop);
            break;
        case A_CMD_FN_DEPLOY:
            // a_parse_function_config(msg.data);

            break;
        default:
            app_debug(true, 0, "Unknown cmd type %d", hdr.cmd_type);
            break;
        }
        break;
    default:
        app_debug(true, 0, "Unknown msg type %d", hdr.type);
    }

    aura_set_internal_request_inactive(loop->srv_ctx);
}

/**
 * Setup global memory context
 */
static int a_setup_memory_caches(struct aura_mem_ctx *mc) {
    struct aura_slab_cache *sc;

    if (aura_create_dynamic_slab_alloc_caches(mc) < 0)
        goto exception;

    /* socket slab cache */
    sc = aura_slab_cache_create(mc, A_SLAB_CACHE_GENERIC_CONN, "generic connection", sizeof(struct aura_conn), NULL, 0);
    if (!sc)
        goto exception;

    /* h2 client connection slab cache */
    sc = aura_slab_cache_create(mc, A_SLAB_CACHE_ID_H2_SERVER_CONN, "h2 server connection", sizeof(struct aura_h2_server_conn), NULL, 0);
    if (!sc)
        goto exception;

    /* h2 client connection slab cache */
    sc = aura_slab_cache_create(mc, A_SLAB_CACHE_ID_H2_CLIENT_CONN, "h2 client connection", sizeof(struct aura_h2_client_conn), NULL, 0);
    if (!sc)
        goto exception;

    /* stream slab cache */
    sc = aura_slab_cache_create(mc, A_SLAB_CACHE_ID_H2_STREAM, "stream", sizeof(struct aura_h2_stream), NULL, 0);
    if (!sc)
        goto exception;

    return 0;

exception:
    aura_mem_ctx_destroy(mc);
    return -1;
}

void aura_run_timer_wheel(struct aura_srv_ctx *srv_ctx) {
    struct aura_timer_wheel *tw;

    tw = &srv_ctx->timer_wheel;
    aura_timers_run(tw);
}

/**
 * Main server loop, the engine that runs
 * our desperate dream
 */
int a_run_loop(struct aura_srv_ctx *srv_ctx) {
    st_aura_evt_loop *loop;
    struct aura_msg msg;
    int max_accept;
    int64_t timeout;
    uint64_t t1, t2;
    int num_of_events, res, fd;

    loop = srv_ctx->evt_loop;
    aura_evt_loop_start(loop);

    while (loop->running) {
        aura_run_timer_wheel(srv_ctx);
        aura_conn_process_completions(srv_ctx);

        t1 = aura_evt_loop_get_timeout(&srv_ctx->timer_wheel);
        t2 = aura_srv_opt_get_candidate_epoll_timeout(&srv_ctx->optimizer);
        max_accept = aura_srv_opt_get_accept_budget(&srv_ctx->optimizer, srv_ctx->inflight);

        /* Get the min of the two timeouts */
        timeout = a_min(t1, t2);
        aura_evt_loop_poll(loop, timeout, max_accept);

        if (loop->srv_ctx->dmn_peer->active) {
            a_handle_internal_request(loop);
        }

        aura_conn_process_handshake_queue(srv_ctx);

        aura_conn_process_active_queue(srv_ctx);

        aura_conn_process_completions(srv_ctx);

        aura_conn_process_reap_queue(loop->srv_ctx);

        aura_run_timer_wheel(srv_ctx);
        aura_conn_process_completions(srv_ctx);

        /* handle others */
    }

    /* perform cleanup */
    return 0;
}

/**
 * Setup default global configuration
 * substituted when config is parsed
 */
static inline int a_glob_conf_init(struct aura_srv_global_ctx *gc) {
    struct aura_user_rec user;

    if (aura_usr_get_rec(&user) < 0)
        return -1;

#ifdef AURA_DEV_BUILD
    /**
     * Switch to nobody if running as root
     * in dev, in prod, we should already
     * use the default set user
     */
    if (user.user_id == 0) {
        struct aura_user_rec nobody;
        if (aura_usr_get_rec_by_name(&nobody, "nobody") < 0)
            return -1;

        if (aura_usr_drop_priv(nobody.user_id, nobody.group_id) < 0)
            return -1;

        gc->user.base = aura_strndup(&gc->mem_ctx, "nobody", sizeof("nobody") - 1);
        gc->user.len = sizeof("nobody") - 1;
    }
#endif

    memset(gc, 0, sizeof(*gc));
    aura_mem_ctx_init(&gc->mem_ctx);

    gc->boot_time = aura_now_ms(CLOCK_MONOTONIC);

    /* init app memory context */

    if (a_setup_memory_caches(&gc->mem_ctx) < 0) {
        sys_debug(true, errno, "main: a_setup_memory_caches error");
        return -1;
    }

    gc->listeners.sni = aura_rax_new();
    if (!gc->listeners.sni)
        return -1;

    aura_host_pool_init(&gc->host_pool);

    return 0;
}

/**
 * Let us Begin
 */
int main(int argc, char *argv[]) {
    struct aura_srv_global_ctx *gc;
    struct aura_srv_ctx *ctx;
    struct aura_msg_hdr hdr;
    struct aura_msg msg;
    struct rlimit rlimit;
    void *config;
    int dmn_fd, rv;

    if (getrlimit(RLIMIT_NOFILE, &rlimit) < 0)
        sys_exit(true, errno, "main: get resource limit err");

    AURA_OPEN_MAX = rlimit.rlim_max;
    if (AURA_OPEN_MAX == RLIM_INFINITY)
        /* arbitrary value from seeing around! */
        AURA_OPEN_MAX = 256;

    aura_scan_str(argv[1], "%" SCNu32, &dmn_fd);
    if (dmn_fd < 0 || dmn_fd > AURA_OPEN_MAX)
        app_exit(true, 0, "main: dmn fd invalid value");

    if (aura_msg_recv(dmn_fd, &msg) <= 0)
        sys_exit(true, 0, "main: aura msg recv from dmn err");

    gc = alloca(sizeof(*gc));
    if (!gc)
        sys_exit(true, errno, "main: global config err");

    if (a_glob_conf_init(gc) < 0)
        sys_exit(true, errno, "main: global config init err");

    ctx = alloca(sizeof(struct aura_srv_ctx));
    if (!ctx)
        sys_exit(true, errno, "main: server ctx err");

    if (a_server_ctx_init(gc, ctx, dmn_fd) < 0)
        sys_exit(true, errno, "main: server ctx init err");

    config = msg.data.iov_base;
    if (a_setup_configs(gc, config) < 0)
        sys_exit(true, 0, "main: config setup err");
    free(config);

    /* alert daemon we may have succeeded */
    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);
    if (aura_msg_send(dmn_fd, &hdr, NULL, 0, -1) < 0)
        sys_exit(true, errno, "main: server msg send to dmn err");

    /* register fds to poll */
    for (int i = 0; i < gc->listeners.listeners_pool.cnt; ++i) {
        aura_evt_loop_add(
          ctx->evt_loop,
          gc->listeners.listeners_pool.entries[i].fd,
          &gc->listeners.listeners_pool.entries[i],
          AURA_EVENT_READ);
    }

    a_preload_functions(gc, dmn_fd);

    rv = a_run_loop(ctx);
    sys_debug(true, errno, "AURA SERVER exiting: rv=%d", rv);
    exit(rv);
}
