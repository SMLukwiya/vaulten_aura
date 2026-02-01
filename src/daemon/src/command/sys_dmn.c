#include "command/sys_dmn.h"
#include "error_lib.h"
#include "unix_socket_lib.h"
#include <sys/signal.h>
#include <unistd.h>
#include <wait.h>

void aura_dmn_system_stop(int cli_fd, struct aura_daemon_glob_conf *glob_conf) {
    struct aura_msg_hdr hdr;
    int res;

    if (glob_conf->server_pid != 0) {
        a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);
        res = aura_msg_send(glob_conf->poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, &hdr, NULL, 0, -1);
        /* if server is alive */
        if (res == 0) {
            if (waitpid(glob_conf->server_pid, NULL, 0) != glob_conf->server_pid)
                sys_debug(true, 0, "aura_dmn_system_stop: waitpid error:");
        }
    }

    aura_db_close(glob_conf->db_handle);

    res = aura_send_resp(cli_fd, NULL, 0);

    close(cli_fd);
}