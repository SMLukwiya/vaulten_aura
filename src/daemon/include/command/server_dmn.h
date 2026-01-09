#ifndef AURA_DMN_SERVER_H
#define AURA_DMN_SERVER_H

#define _POSIX_C_SOURCE 200809L

#include "blobber_lib.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "picotls.h"
#include "radix_lib.h"
#include "types_lib.h"
#include "unix_socket_lib.h"

#include <signal.h>
#include <stdbool.h>

/**
 * User data to validate mandatory fields and related yaml fields
 * like tls identites and hosts relationships...
 */
struct aura_yml_usr_data_ctx {
    bool seen_aura_version;
    bool seen_svr_env;
    bool seen_srv_addr;
    bool seen_srv_port;
    bool seen_tls_identities;
    bool seen_any_key_file;
    bool expect_key;
    bool seen_hosts;
    bool seen_ciphers;
    bool is_aes128gcmsha256_set; /* RFC 8446 9.1 stuff! */
    bool extract;
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

typedef void (*cmd_cb)(int fd, pid_t pid);

/**
 *
 */
struct srv_start_arg {
    cmd_cb cb;
};

int aura_dmn_start_server(struct aura_msg *msg, int cli_fd, struct srv_start_arg *p);
int aura_dmn_stop_server(struct aura_msg *msg, int srv_fd, int cli_fd, pid_t srv_pid);
int aura_dmn_server_status(int srv_fd, int cli_fd);

#endif