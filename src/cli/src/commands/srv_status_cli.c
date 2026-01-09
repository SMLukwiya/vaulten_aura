#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "unix_socket_lib.h"

int aura_cli_run_server_status(void *opts_ptr, void *glob_opt) {
    int sock_fd, res;
    struct aura_msg_hdr hdr;
    char *data;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STATUS);
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) != 0) {
        close(sock_fd);
        sys_exit(false, errno, "Failed to send aura server status cli cmd");
    }

    data = aura_recv_resp(sock_fd);
    if (data != NULL)
        app_info(false, 0, "%s", data);

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
  .flag_count = 0,
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