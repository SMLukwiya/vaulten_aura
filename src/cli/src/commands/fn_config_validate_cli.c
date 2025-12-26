#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

/* validate cli options */
struct fn_config_validate_opt {
    char *fn_config_path;
};

/* Allocator fn */
void *fn_config_validate_opt_allocator(void) {
    return malloc(sizeof(struct fn_config_validate_opt));
}

/* Deallocator fn */
void fn_config_validate_opt_deallocator(void *opts_ptr) {
    struct fn_config_validate_opt *opts = (struct fn_config_validate_opt *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->fn_config_path)
        free(opts->fn_config_path);

    free(opts);
}

/* Handler fn */
void run_fn_validate_config_cli(void *opts_ptr, int argc, char *argv[], void *glob_opts) {
    char resolved_config_file_path[1024];
    struct fn_config_validate_opt *opts;
    int sock_fd, file_fd, res;
    bool ret;
    struct aura_msg_hdr hdr;
    struct aura_msg response;
    char *data;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    opts = (struct fn_config_validate_opt *)opts_ptr;
    if (!opts->fn_config_path)
        sys_exit(false, 0, "Missing configuration file");

    ret = aura_open_file(opts->fn_config_path, &file_fd);
    if (!ret)
        sys_exit(false, 0, "Failed to open file: %s\n", opts->fn_config_path);

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_FN_VALIDATE_CONF);

    res = aura_msg_send(sock_fd, &hdr, NULL, 0, file_fd);
    if (res != 0)
        sys_exit(false, errno, "Failed to send aura cli command");

    data = aura_recv_resp(sock_fd);
    if (data != NULL) {
        app_info(false, 0, "%s", data);
    }
    close(sock_fd); /** Is there need since the cli exits here */
}

/* HELP CMD */
void fn_config_validate_help() {
    app_info(false, 0, "aura function validate -p <path to config file>");
}

struct aura_cli_flag fn_config_validate_flag = {
  .name = "path",
  .short_name = 'p',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct fn_config_validate_opt, fn_config_path),
  .description = "path to config file location",
};

struct aura_cli_flag *validate_config_flags[] = {
  &fn_config_validate_flag,
};

struct aura_cli_cmd fn_config_validate_cli = {
  .version = "1.0.0",
  .name = "validate",
  .description = "validate a configuration file for syntax semantic errors",
  .usage = "aura function validate -p <path to config file>",
  .deprecated = NULL,
  .flags = validate_config_flags,
  .flag_count = ARRAY_SIZE(validate_config_flags),
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = sizeof(struct fn_config_validate_opt),
  .opt_allocator = fn_config_validate_opt_allocator,
  .opt_destructor = fn_config_validate_opt_deallocator,
  .handler = run_fn_validate_config_cli,
  .opt_help = fn_config_validate_help,
};
