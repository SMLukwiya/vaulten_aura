#ifndef AURA_DMN_SERVER_H
#define AURA_DMN_SERVER_H

#include "blobber/lib.h"
#include "http_lib.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "protocol.h"
#include "radix/tree.h"
#include "types_lib.h"
#include "unix/sock.h"

#include <signal.h>
#include <stdbool.h>

#define A_ADDR_UNSET_IPV4 0xFFFFFFFF
#define A_ADDR_UNSET_IPv6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#define A_PORT_UNSET 0

static char server_started[] = "\x1B[1;32mServer started\x1B[0m";
static char server_start_failed[] = "\x1B[1;31mFailed to start server\x1B[0m";
static char server_stopped[] = "\x1B[1;32mServer stopped\x1B[0m";
static char server_stopped_failed[] = "\x1B[1;32mServer stop failed\x1B[0m";
static char server_up[] = "\x1B[1;32mServer up\x1B[0m";
static char server_down[] = "\x1B[1;31mServer down\x1B[0m";

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
    struct aura_yml_srv_listeners listeners; /* store listeners */
    struct aura_yml_tls_tags tls_tags;       /* tls tags */
    struct aura_yml_srv_hosts hosts;
    aura_rax_tree_t parse_tree;
    st_aura_b_builder builder;
    struct {
        struct aura_yml_node *entries;
        uint32_t cap;
        uint32_t cnt;
    } node_vec;
    SSL_CTX *ssl_ctx;            /* fake SSL context to validate key and cert files */
    bool seen_aura_version;      /* yaml version */
    bool seen_svr_env;           /* server environment set */
    bool seen_listeners;         /* server listeners */
    bool seen_tls_identities;    /* any defined tls identities*/
    bool seen_any_key_file;      /* key file for a tls identity */
    bool expect_key;             /* expect to parse a key as next token */
    bool seen_ciphers;           /* tls ciphers */
    bool is_aes128gcmsha256_set; /* RFC 8446 Mandatory cipher suite! */
    bool seen_hosts;             /* server hosts */
    bool extract;                /* extract the parsed values for use later */
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

enum aura_srv_data_t {
    A_SERVER_CONF
};

typedef void (*cmd_cb)(int fd, pid_t pid);

/* Start server */
int aura_dmn_start_server(struct aura_msg *msg, int cli_fd, void *arg);

/* Stop server */
int aura_dmn_stop_server(struct aura_msg *msg, int cli_fd, void *arg);

/* Get server status */
int aura_dmn_get_server_status(int cli_fd, void *arg);

/* validate server config */
void aura_dmn_validate_server_conf(int config_fd, int cli_fd);

#endif