#ifndef AURA_DMN_H
#define AURA_DMN_H

#include "db/db.h"
#include "error_lib.h"
#include "memory_lib.h"
#include "time_lib.h"
#include "types_lib.h"
#include "user/user.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#define A_SOCK_FILE_FD_IDX 0
#define A_SOCK_PAIR_FD_IDX 1

struct aura_dmn_conf {
    int log_lvl;
    bool require_peer_uid_match;
};

static struct aura_dmn_conf def_dmn_conf = {
  .log_lvl = 1,
  .require_peer_uid_match = true,
};

/* Daemon Global Config structure */
struct aura_dmn_glob_conf {
    struct aura_iovec db_file;
    AURA_DBHANDLE db_handle;
    struct aura_mem_ctx mc;
    struct timespec boot_time;
    struct pollfd *poll_fds;
    int server_pid;
    struct aura_user_rec user;
    struct aura_dmn_conf admin_conf;
};

int aura_daemon(void);

#endif