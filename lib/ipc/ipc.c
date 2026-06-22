#include "ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void aura_ipc_get_unix_sock_path(bool dev_mode, char *path, size_t len) {
    char *base;

    memset(path, 0, len);
    if (dev_mode) {
        char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
        base = xdg_runtime ? xdg_runtime : "/tmp";
    } else {
        /* Created by systemd.exec */
        base = getenv("RUNTIME_DIRECTORY");
    }

    snprintf(path, len, "%s/%s", base, "aurad.sock");
}