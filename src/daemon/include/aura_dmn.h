#ifndef AURA_DMN_H
#define AURA_DMN_H

#include "db/db.h"
#include "error_lib.h"
#include "memory_lib.h"
#include "types_lib.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#define A_SOCK_FILE_FD_IDX 0
#define A_SOCK_PAIR_FD_IDX 1

/* Daemon Global Config structure */
struct aura_dmn_glob_conf {
    struct aura_iovec aura_app_path;
    struct aura_iovec aura_db_path;
    AURA_DBHANDLE db_handle;
    struct aura_mem_ctx mc;
    int server_pid;
    uint64_t boot_time;
    struct pollfd *poll_fds;
};

int aura_daemon(void);

#endif