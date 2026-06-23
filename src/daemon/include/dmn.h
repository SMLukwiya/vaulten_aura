#ifndef AURA_DMN_H
#define AURA_DMN_H

#include "db/db.h"
#include "dense_pool/static.h"
#include "error_lib.h"
#include "mem.h"
#include "time_lib.h"
#include "types_lib.h"
#include "user/user.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#define A_SOCK_FILE_FD_IDX 0
#define A_SOCK_PAIR_FD_IDX 1
#define A_DMN_POLLFD_POOL_SZ 64
#define A_DMN_DEFAULT_SERVER_FD -1

struct aura_dmn_conf {
    int log_lvl;
    bool require_peer_uid_match;
};

static struct aura_dmn_conf def_dmn_conf = {
  .log_lvl = 1,
  .require_peer_uid_match = true,
};

/* Define pollfd pool */
A_DEFINE_DENSE_POOL(pollfd, A_DMN_POLLFD_POOL_SZ, struct pollfd);

/* Daemon Global Config structure */
struct aura_dmn_glob_conf {
    struct aura_iovec db_file;
    AURA_DBHANDLE db_handle;
    struct aura_mem_ctx mc;
    struct timespec boot_time;
    struct aura_pollfd_dense_pool pollfd_pool;
    int unix_sock_fd;
    int server_pid;
    int server_fd; /* server socket fd from socket_pair */
    struct aura_user_rec user;
    struct aura_dmn_conf admin_conf;
};

/* Add fd for polling */
static inline int aura_add_pollfd_entry(struct aura_pollfd_dense_pool *pool, int fd) {
    uint32_t idx = aura_pollfd_dense_pool_lease(pool);
    if (idx == A_DENSE_POOL_INVALID_IDX)
        return -1;

    struct pollfd *slot = aura_pollfd_dense_pool_get_slot(pool, idx);
    slot->fd = fd;
    slot->events = POLLIN;
    slot->revents = 0;

    return 0;
}

static inline void aura_release_pollfd_entry(struct aura_pollfd_dense_pool *pool, uint32_t idx) {
    struct pollfd *pfd = aura_pollfd_dense_pool_get_slot(pool, idx);
    pfd->events = 0;
    pfd->fd = -1;

    aura_pollfd_dense_pool_release(pool, idx);
}

#endif