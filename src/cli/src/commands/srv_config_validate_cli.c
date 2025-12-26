#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

/* validate cli options */
struct srv_conf_validate_opt {
    char *server_conf_path;
};

/* Allocator fn */
void *server_conf_validate_opt_allocator(void) {
    return malloc(sizeof(struct srv_conf_validate_opt));
}

/* Deallocator fn */
void server_conf_validate_opt_deallocator(void *opts_ptr) {
    struct srv_conf_validate_opt *opts = (struct srv_conf_validate_opt *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->server_conf_path)
        free(opts->server_conf_path);

    free(opts);
}

/* Handler fn */
void run_server_validate_conf_cli(void *opts_ptr, int argc, char *argv[], void *glob_opts) {
    char resolved_conf_file_path[1024];
    int sock_fd, file_fd, res;
    struct aura_msg_hdr hdr;
    char *data;
    struct srv_conf_validate_opt *opts = (struct srv_conf_validate_opt *)opts_ptr;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    res = aura_get_absolute_path(opts->server_conf_path, resolved_conf_file_path);
    if (res != 0)
        sys_exit(false, errno, "Failed to resolve file path: %s", opts->server_conf_path);

    res = access(resolved_conf_file_path, R_OK);
    if (res < 0)
        sys_exit(false, 0, "Failed to get read access file: %s", resolved_conf_file_path);

    file_fd = open(resolved_conf_file_path, O_RDONLY);
    if (file_fd < 0)
        sys_exit(false, 0, "Failed to open file: %s", resolved_conf_file_path);

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_VALIDATE_CONF);

    if (aura_msg_send(sock_fd, &hdr, NULL, 0, file_fd) != 0) {
        close(sock_fd);
        close(file_fd);
        sys_exit(false, errno, "Failed to send aura validate config cmd");
    }
    close(file_fd);

    data = aura_recv_resp(sock_fd);
    if (data == NULL)
        app_exit(false, 0, "No data");
    else
        app_info(false, 0, "%s", data);

    close(sock_fd);
}

/* HELP CMD */
void server_conf_validate_help() {
    app_info(false, 0, "aura function validate -p <path to config file>");
}

struct aura_cli_flag server_conf_validate_flag = {
  .name = "path",
  .short_name = 'p',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct srv_conf_validate_opt, server_conf_path),
  .description = "path to config file location",
};

struct aura_cli_flag *svr_validate_conf_flags[] = {
  &server_conf_validate_flag,
};

struct aura_cli_cmd server_config_validate_cli = {
  .version = "1.0.0",
  .name = "validate",
  .description = "validate a configuration file for syntax semantic errors",
  .usage = "aura server validate -p <path to config file>",
  .deprecated = NULL,
  .flags = svr_validate_conf_flags,
  .flag_count = ARRAY_SIZE(svr_validate_conf_flags),
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = sizeof(struct srv_conf_validate_opt),
  .opt_allocator = server_conf_validate_opt_allocator,
  .opt_destructor = server_conf_validate_opt_deallocator,
  .handler = run_server_validate_conf_cli,
  .opt_help = server_conf_validate_help,
};
