#ifndef AURA_SERVER_H
#define AURA_SERVER_H

#include "db/db.h"
#include "defaults_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "metrics_srv.h"
#include "picotls.h"
#include "picotls/certificate_compression.h"
#include "picotls/openssl.h"
#include "picotls/pembase64.h"
#include "radix_lib.h"
#include "route_srv.h"
#include "socket_srv.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* for general null terminated string */
#define a_str_lit(str) (str), strlen(str)
/* WARNING: only use for static character, and character arrays, not character pointers */
#define a_str_lit_static(str) (str), sizeof(str) - 1

#define AURA_QLEN 4096
#define A_MAX_FDS 65536

#define A_H2_APLN_PROTOCOLS \
    {a_str_lit_static("h2")}, {a_str_lit_static("h2-14")}, {a_str_lit_static("h2-16")}, { NULL }

/* OCSP updater structure */
struct aura_ocsp_updater {
    int timer_fd;
    time_t interval;
    uint32_t max_failures;
};

/* OCSP info structure */
struct aura_tls_ocsp_info {
    char *ocsp_url;
    time_t last_update;
    time_t next_update;
    uint8_t *ocsp_response;
    size_t ocsp_response_len;
};

/* Security policy structure */
struct aura_srv_sec_policy {
    void *waf_config; /* web application firewall */
    void *ratelimiter_config;
    void *ip_acl;       /* ACLs */
    uint32_t policy_id; /* unique ID for logging */
};

/* A single identity structure */
struct aura_srv_tls_iden {
    const char *tag;
    struct {
        char *cert_file;
        void *mmapped_data; /* mem mapped for zero copy */
        size_t size;
    } cert;

    struct {
        char *key_file;
        void *mmapped_data;
        size_t size;
        int hsm_slot; /* Hardware security Module slot */
        uint8_t type;
    } key;

    struct {
        char *cert_chain_file;
        void *mmapped_data;
        size_t size;
    } cert_chain;

    struct {
        struct {
            ptls_context_t *ctx;
            ptls_openssl_signature_scheme_t *sig_scheme;
        } tls1_3;
    } contexts;

    struct {
        struct aura_tls_ocsp_info ocsp_stapling;
        struct aura_ocsp_updater ocsp_updater;
    } ocsp;

    struct {
        ptls_emit_compressed_certificate_t *emit_ptls;
    } compressed_cert;
};

/* Server host config structure */
struct aura_srv_host_conf {
    struct {
        struct aura_iovec hostname;
        uint16_t port;
    } authority;
    struct sockaddr addr;
    socklen_t addr_len;
    uint32_t def_tls_off; /* default tls identity offset */
    uint32_t *other_tls_off;
    uint32_t other_tls_cnt;
    struct aura_router router;
    struct aura_iovec *h2_origin_frame;
    struct aura_srv_sec_policy *def_security_policy; /* default security policy */
};

/* Server queues structure */
struct aura_srv_req_queue {
    struct aura_list_head fast_lane_queue;
    struct aura_list_head standard_queue;
    struct aura_list_head background_queue;
    struct aura_list_head handshake_queue;
    struct aura_list_head timeout_queue;
    struct aura_list_head write_queue;

    /*Adaptive scheduling stats */
    uint32_t avg_completion_time[A_TOTAL_ADMISSIONS_PRIORITY_LEVELS]; /* Per prio */
    uint32_t queue_depths[A_TOTAL_ADMISSIONS_PRIORITY_LEVELS];
};

/**
 * Listener config strucure: holds configs shared
 * by all listeners
 */
struct aura_srv_listener_conf {
    struct {
        int *fds;
        size_t cnt;
        size_t cap;
    } fd_pool;
    struct {
        struct aura_srv_tls_iden *idens;
        size_t cnt;
        size_t cap;
    } tls_pool;
    ptls_t *ptls;
    struct aura_srv_host_conf *fb_host_conf; /* fallback host, if SNI lookup fails */
    aura_rax_tree_t *sni;                    /* radix tree */
    uint32_t flag;                           /* config flags, only http2 enabled now */
    void *bpf_program;
};

/* Server general context structure */
struct aura_srv_ctx {
    struct aura_srv_global_conf *glob_conf;
    struct aura_evt_loop *evt_loop;
    struct aura_srv_listener_conf *listener_conf;

    struct {
        size_t idle_timeouts;          /* number of http idle timeouts */
        size_t read_closed;            /* premature close on read */
        size_t write_closed;           /* premature close on write */
        size_t aura_server_errors[10]; /** @todo: define AURA_SERVER_ERRORS */
    } h2;

    struct {
        struct aura_srv_req_queue queues;
        size_t handshake_cnt;
        size_t read_cnt;
        size_t write_cnt;
        size_t timeout_cnt;
        /* if we have an internal request, we store the sock fd */
        bool internal;
    } batches;

    struct aura_srv_metrics_bucket metrics;
};

/**
 * Global aura server configuration structure
 */
struct aura_srv_global_conf {
    struct aura_iovec server_name; /* Aura server name */
    size_t max_req_size;           /* max size of accepted request, e.g, POST */
    time_t boot_time;              /* server boot time */
    bool shutdown_requested;       /* if shutdown has been requested */

    struct aura_srv_sock *fdmap[A_MAX_FDS];
    struct {
        struct aura_srv_host_conf *hosts;
        size_t cnt;
        size_t cap;
    } host_pool;

    struct {
        uint32_t soft_limit;
        uint32_t hard_limit;
    } conn;

    struct aura_memory_ctx mem_ctx;
    struct aura_iovec user;

    struct aura_iovec aura_app_path;
    struct aura_iovec aura_db_path;
    AURA_DBHANDLE db_handle;
};

#endif