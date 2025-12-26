#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "unix_socket_lib.h"

void run_server_stop(void *opts_ptr, int argc, char *argv[], void *glob_opt) {
    int sock_fd, res;
    struct aura_msg_hdr hdr;
    char *data;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);

    res = aura_msg_send(sock_fd, &hdr, NULL, 0, -1);
    if (res != 0) {
        close(sock_fd);
        sys_exit(false, errno, "Failed to send aura server start cli cmd");
    }

    data = aura_recv_resp(sock_fd);
    if (data != NULL)
        app_info(false, 0, "%s", data);

    close(sock_fd);
}

/**/
void server_stop_help_fn() {
    app_info(false, 0, "aura server stop");
}

/* aura server start aura_cli_cmd */
struct aura_cli_cmd server_stop_cli = {
  .version = "1.0.0",
  .name = "stop",
  .description = "stop the server",
  .usage = "aura server stop",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .opt_allocator = NULL,
  .opt_destructor = NULL,
  .handler = run_server_stop,
  .opt_help = server_stop_help_fn,
};