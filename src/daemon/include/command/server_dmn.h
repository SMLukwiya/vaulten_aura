#ifndef AURA_DMN_SERVER_H
#define AURA_DMN_SERVER_H

#include "blobber_lib.h"
#include "http_lib.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "picotls.h"
#include "protocol.h"
#include "radix_lib.h"
#include "types_lib.h"
#include "unix/sock.h"

#include <signal.h>
#include <stdbool.h>

#define A_ADDR_UNSET_IPV4 0xFFFFFFFF
#define A_ADDR_UNSET_IPv6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#define A_PORT_UNSET 0

/* yaml listeners container */
struct aura_yml_srv_listeners {
    struct {
        uint32_t address; /* @todo: support ipv6 with a union type */
        int port;
        a_transport_protocol protocol;
        bool tls;
        bool quic;
    } *entries;
    uint32_t cnt;
    uint32_t cap;
};

/* yaml tls tags container */
struct aura_yml_tls_tags {
    char **entries;
    uint32_t cnt;
    uint32_t cap;
};

/* yaml hosts container */
struct aura_yml_srv_hosts {
    struct {
        char *name;
        char *tls_tag;
    } *entries;
    uint32_t cnt;
    uint32_t cap;
};

/**
 * User data to validate mandatory fields and related yaml fields
 * like tls identites and hosts relationships...
 */
struct aura_yml_usr_data_ctx {
    bool seen_aura_version;                  /* yaml version */
    bool seen_svr_env;                       /* server environment set */
    bool seen_listeners;                     /* server listeners */
    struct aura_yml_srv_listeners listeners; /* store listeners */
    bool seen_tls_identities;                /* any defined tls identities*/
    bool seen_any_key_file;                  /* key file for a tls identity */
    bool expect_key;                         /* expect to parse a key as next token */
    bool seen_ciphers;                       /* tls ciphers */
    bool is_aes128gcmsha256_set;             /* RFC 8446 Mandatory cipher suite! */
    struct aura_yml_tls_tags tls_tags;       /* tls tags */
    bool seen_hosts;                         /* server hosts */
    struct aura_yml_srv_hosts hosts;
    bool extract; /* extract the parsed values for use later */
    aura_rax_tree_t *parse_tree;
    st_aura_b_builder builder;
    struct aura_yml_node *node_arr;
    uint32_t node_cap;
    uint32_t node_cnt;
    uint32_t node_len;
    SSL_CTX *ssl_ctx; /* fake SSL context to validate key and cert files */
};

/**
 * Server config table indexes,
 * This must match the one defined in
 * the server. When updating one, update
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

typedef void (*cmd_cb)(int fd, pid_t pid);

/**
 *
 */
struct srv_start_arg {
    cmd_cb cb;
};

/* Start server */
int aura_dmn_server_start(struct aura_msg *msg, int cli_fd, void *arg);

/* Stop server */
int aura_dmn_server_stop(struct aura_msg *msg, int cli_fd, void *arg);

/* Get server status */
int aura_dmn_server_status(int cli_fd, void *arg);

/* validate server config */
void aura_dmn_server_config_validate(int fd, int cli_fd);

#endif