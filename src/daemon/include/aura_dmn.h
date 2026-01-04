#ifndef AURA_DMN_H
#define AURA_DMN_H

#include "db/db.h"
#include "error_lib.h"
#include "types_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LOCKFILE "/tmp/aurad.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

struct aura_daemon_glob_conf {
    struct aura_iovec aura_app_path;
    struct aura_iovec aura_db_path;
    AURA_DBHANDLE db_handle;
};

int aura_daemon(void);

#endif