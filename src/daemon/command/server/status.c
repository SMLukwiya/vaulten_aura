#include "command/server.h"
#include "dmn.h"

int aura_dmn_get_server_status(int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_msg_hdr hdr;
    struct aura_msg res_msg;
    int rv, srv_fd;

    srv_fd = gc->server_fd;
    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);

    if (aura_msg_send(srv_fd, &hdr, NULL, 0, -1) < 0) {
        sys_debug(true, errno, "aura_dmn_get_server_status: aura_msg_send error:");
        goto out;
    }

    if (aura_msg_recv(srv_fd, &res_msg) < 0) {
        sys_debug(true, errno, "aura_dmn_get_server_status: aura_msg_recv error:");
        goto out;
    }

    hdr = res_msg.hdr;
    if (hdr.type != A_MSG_PING) {
        app_debug(true, 0, "aura_dmn_get_server_status: Incorrect msg hdr type: %d!", hdr.type);
        goto out;
    }

    rv = aura_resp_send(cli_fd, server_up, sizeof(server_up) - 1);
    close(cli_fd);
    return 0;
out:
    rv = aura_resp_send(cli_fd, server_down, sizeof(server_down) - 1);
    close(cli_fd);
    return -1;
}