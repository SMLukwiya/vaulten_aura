#ifndef AURA_DMN_H
#define AURA_DMN_H

#include "error_lib.h"
#include "types_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LOCKFILE "/tmp/aurad.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

struct aura_daemon_glob_conf {
    struct aura_iovec fn_data_path;
};

int aura_daemon(void);

#endif