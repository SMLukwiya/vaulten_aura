#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "ipc/ipc.h"
#include "unix/sock.h"

int aura_cli_run_server_status(void *opts_ptr, void *glob_opt) {
    struct aura_msg_hdr hdr;
    struct aura_iovec data;
    char sock_file[A_MAX_SOCK_FILE_LEN];
    int sock_fd;
    bool dev_mode = false;

#ifdef AURA_DEV_BUILD
    dev_mode = true;
#endif

    aura_ipc_get_unix_sock_path(dev_mode, sock_file, sizeof(sock_file));
    sock_fd = aura_try_connect_or_error(sock_file);
    if (sock_fd == -1) {
        app_info(false, 0, system_down);
        app_info(false, 0, system_start);
        return -1;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STATUS);
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) != 0) {
        sys_info(false, errno, cmd_send_failed);
        return -1;
    }

    if (aura_recv_resp(&data, sock_fd, NULL) < 0) {
        close(sock_fd);
        return -1;
    }

    if (data.base != NULL)
        app_info(false, 0, "%s", data.base);

    close(sock_fd);
    return 0;
}

/**/
static void a_server_status_help_fn() {
    app_info(false, 0, "aura status stop");
}

/* aura server status aura_cli_cmd */
struct aura_cli_cmd server_status_cli = {
  .version = "1.0.0",
  .name = "status",
  .description = "get server status",
  .usage = "aura server status",
  .deprecated = NULL,
  .flags = NULL,
  .flag_cnt = 0,
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = NULL,
  .sub_cmd_cnt = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .opt_allocator = NULL,
  .opt_destructor = NULL,
  .handler = aura_cli_run_server_status,
  .opt_help = a_server_status_help_fn,
};