#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

/* server cli options */
struct svr_start_opts {
    char *server_config_path;
};

/* Allocator fn */
static void *a_server_start_opt_allocator(void) {
    return malloc(sizeof(struct svr_start_opts));
}

/* Deallocator fn */
static void a_server_start_opt_deallocator(void *opts_ptr) {
    struct svr_start_opts *opts = (struct svr_start_opts *)opts_ptr;
    if (!opts)
        return;

    if (opts->server_config_path)
        free(opts->server_config_path);

    free(opts);
}

/* server start cli flags */
struct aura_cli_flag server_start_path_flag = {
  .name = "path",
  .short_name = 'p',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = A_CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct svr_start_opts, server_config_path),
  .description = "path to server config file to use",
};

struct aura_cli_flag *svr_start_flags[] = {
  &server_start_path_flag,
};

int aura_cli_run_server_start(void *opts_ptr, void *glob_opt) {
    char resolved_svr_conf_file_path[1024];
    int sock_fd, file_fd, res;
    struct aura_msg_hdr hdr;
    char *data;
    struct svr_start_opts *opts;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    opts = (struct svr_start_opts *)opts_ptr;
    res = aura_get_absolute_path(opts->server_config_path, resolved_svr_conf_file_path);
    if (res != 0)
        sys_exit(false, errno, "Failed to resolve file path: %s", opts->server_config_path);

    if (access(resolved_svr_conf_file_path, R_OK) < 0)
        sys_exit(false, errno, "Failed to get read access file: %s", resolved_svr_conf_file_path);

    file_fd = open(resolved_svr_conf_file_path, O_RDONLY);
    if (file_fd < 0)
        sys_exit(false, errno, "Failed to open file: %s", resolved_svr_conf_file_path);

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_START);
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, file_fd) != 0) {
        close(sock_fd);
        sys_exit(false, errno, "Failed to send aura server start cli cmd");
    }
    close(file_fd);

    data = aura_recv_resp(sock_fd);
    if (data != NULL)
        app_info(false, 0, "%s", data);

    close(sock_fd);
    return 0;
}

/**/
static void a_server_help_fn() {
    app_info(false, 0, "aura server start -p <path to config file>");
}

/* aura server start aura_cli_cmd */
struct aura_cli_cmd server_start_cli = {
  .version = "1.0.0",
  .name = "start",
  .description = "start the server with the configuration file provided",
  .usage = "aura server start -p <path to config file>",
  .deprecated = NULL,
  .flags = svr_start_flags,
  .flag_count = ARRAY_SIZE(svr_start_flags),
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
  .options_size = sizeof(struct svr_start_opts),
  .opt_allocator = a_server_start_opt_allocator,
  .opt_destructor = a_server_start_opt_deallocator,
  .handler = aura_cli_run_server_start,
  .opt_help = a_server_help_fn,
};