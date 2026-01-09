#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

extern int aura_cli_system_start(void *opts_ptr, void *glob_opts);
extern int aura_cli_system_stop(void *opts_ptr, void *glob_opts);
extern int aura_cli_system_status(void *opts, void *glob_opts);

struct start_options {
    char *system_config_path;
};

static void a_test_daemon_system_lifecycle() {
    pid_t pid, pid_;
    int res, status;
    struct stat statbuf;
    struct start_options opts = {
      .system_config_path = "config.yaml",
    };

    res = aura_cli_system_start((void *)&opts, NULL);
    assert(res == 0);

    res = stat(AURA_PID, &statbuf);
    assert(res == 0);

    res = aura_cli_system_status(NULL, NULL);
    assert(res == 0);

    aura_cli_system_stop(NULL, NULL);

    res = stat(AURA_PID, &statbuf);
    assert(res == -1);
}

int main(int argc, char *argv[]) {
    a_test_daemon_system_lifecycle();

    return 0;
}