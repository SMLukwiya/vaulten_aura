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

#define LOCKFILE "/tmp/aurad.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define MAX_CONN 100
#define A_SOCKET_PAIR_FD_INDEX 1

/* Daemon Global Config structure */
struct aura_daemon_glob_conf {
    struct aura_iovec aura_app_path;
    struct aura_iovec aura_db_path;
    AURA_DBHANDLE db_handle;
    struct aura_memory_ctx mc;
    int server_pid;
    struct pollfd poll_fds[MAX_CONN];
};

int aura_daemon(void);

#endif