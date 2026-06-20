#include "command/sys_dmn.h"
#include "error_lib.h"
#include "unix/sock.h"
#include <sys/signal.h>
#include <unistd.h>
#include <wait.h>

void aura_dmn_system_stop(int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_msg_hdr hdr;
    int rv;

    if (gc->server_pid != 0) {
        a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);
        rv = aura_msg_send(gc->poll_fds[A_SOCK_PAIR_FD_IDX].fd, &hdr, NULL, 0, -1);
        /* if server is alive */
        if (rv == 0) {
            if (waitpid(gc->server_pid, NULL, 0) != gc->server_pid)
                sys_debug(true, 0, "aura_dmn_system_stop: waitpid error:");
        }
    }

    aura_db_close(gc->db_handle);
    rv = aura_resp_send(cli_fd, NULL, 0);

    close(cli_fd);
}