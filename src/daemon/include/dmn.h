#ifndef AURA_DMN_H
#define AURA_DMN_H

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "db/db.h"
#include "dense_pool/static.h"
#include "error_lib.h"
#include "event_ctx/context.h"
#include "fn/lib.h"
#include "memory/lru_cache.h"
#include "memory/mem.h"
#include "time_lib.h"
#include "types_lib.h"
#include "user/user.h"

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

enum {
    A_DMN_SERVER_SHUTDOWN_NORMAL
};

/* Daemon Global Config structure */
struct aura_dmn_glob_conf {
    struct aura_evt_src_registry evt_src_registry; /* Event sources */
    struct aura_fn_registry fn_registry;           /* Function registry */
    AURA_DBHANDLE db_handle;                       /* Database handle */
    struct aura_mem_ctx mc;                        /* memory context */
    struct timespec boot_time;                     /* Start time */
    struct aura_pollfd_dense_pool pollfd_pool;     /* Daemon polling structure */
    struct aura_user_rec user;                     /* Daemon user */
    struct aura_dmn_conf admin_conf;
    struct aura_lru_cache fn_cache; /* Function cache */
    int unix_sock_fd;
    int server_pid;               /* server process id */
    int server_fd;                /* server socket fd from socket_pair */
    int server_fd_idx;            /* server pollfd entry index */
    uint8_t server_shutdown_flag; /* shutdown flag*/
    bool server_running;          /* server running and added to pollfd */
};

/**
 * Add fd for polling
 * Returns -1 for error or the entry
 * index in the pool
 */
static inline int aura_add_pollfd_entry(struct aura_pollfd_dense_pool *pool, int fd) {
    uint32_t idx = aura_pollfd_dense_pool_lease(pool);
    if (idx == A_DENSE_POOL_INVALID_IDX)
        return -1;

    app_debug(true, 0, "ADDING FOR POLLING=%d at idx=%d", fd, idx);
    struct pollfd *slot = aura_pollfd_dense_pool_get_slot(pool, idx);
    slot->fd = fd;
    slot->events = POLLIN;
    slot->revents = 0;

    return idx;
}

static inline void aura_release_pollfd_entry(struct aura_pollfd_dense_pool *pool, uint32_t idx) {
    struct pollfd *pfd = aura_pollfd_dense_pool_get_slot(pool, idx);
    app_debug(true, 0, "RELEASING FD=%d", pfd->fd);
    close(pfd->fd);
    pfd->fd = -1;

    aura_pollfd_dense_pool_release(pool, idx);
}

#endif