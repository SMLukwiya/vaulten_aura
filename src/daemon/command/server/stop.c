#include "command/server.h"
#include "dmn.h"

int aura_dmn_stop_server(struct aura_msg *msg, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_msg_hdr hdr;
    int rv;

    if (gc->server_pid == 0) {
        rv = aura_resp_send(cli_fd, (void *)server_down, sizeof(server_down) - 1);
        close(cli_fd);
        return 0;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);
    if (aura_msg_send(gc->server_fd, &hdr, NULL, 0, -1) != 0) {
        rv = aura_resp_send(cli_fd, (void *)server_stopped_failed, sizeof(server_stopped_failed) - 1);
        close(cli_fd);
        return -1;
    }

    /* close and reset server socket */
    close(gc->server_fd);
    gc->server_fd = A_DMN_DEFAULT_SERVER_FD;
    gc->server_pid = 0;

    /* respond to cli */
    rv = aura_resp_send(cli_fd, (void *)server_stopped, sizeof(server_stopped) - 1);
    close(cli_fd);
    return 0;
}