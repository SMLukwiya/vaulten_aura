#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "function_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

const char fn_status_error[] = "\x1B[1;31mFunction status failed\x1B[0m";
const char fn_not_exist[] = "\x1B[1;31mFunction status failed. Provided function does not exist!\x1B[0m";

struct fn_status_config {
    char *fn_name;
};

/* Allocator fn */
static void *a_fn_status_option_allocator(void) {
    return malloc(sizeof(struct fn_status_config));
}

/* Deallocator fn */
static void a_fn_status_option_deallocator(void *opts_ptr) {
    struct fn_status_config *opts = (struct fn_status_config *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->fn_name)
        free(opts->fn_name);

    free(opts);
}

struct aura_cli_flag fn_status_flag = {
  .name = "function",
  .short_name = 'f',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = A_CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct fn_status_config, fn_name),
  .description = "Name of the function",
};

int aura_cli_fn_status(void *opts_ptr, void *glob_opts) {
    char *data;
    struct aura_msg_hdr hdr;
    struct aura_msg msg;
    struct fn_status_config *opts;
    int sock_fd, res;
    char *fn_name, *sep;
    uint32_t fn_verion;
    struct aura_fn_evt *evt;
    bool ret;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    opts = (struct fn_status_config *)opts_ptr;
    fn_name = opts->fn_name;
    sep = strchr(fn_name, ':');
    if (sep) {
        /* Try and parse fn version */
        if (*(sep + 1) == '\0') {
            app_exit(false, 0, "Missing function version, Expected a valid integer");
        }
        res = aura_scan_str(sep + 1, "%d" SCNu32, &fn_verion);
        if (res == 0) {
            app_exit(false, 0, "Invalid function version: %s, Expected a valid integer", sep + 1);
        }
    }

    a_init_msg_hdr(hdr, strlen(fn_name), A_MSG_CMD_EXECUTE, A_CMD_FN_STATUS);

    /* send over the directory file descriptor */
    if (aura_msg_send(sock_fd, &hdr, opts->fn_name, strlen(opts->fn_name), -1) != 0)
        sys_exit(false, errno, "aura_cli_fn_status: aura_msg_send error:");

    bool should_terminate;

    while (true) {
        should_terminate = false;
        evt = aura_recv_resp(sock_fd);

        if (!evt)
            break;

        if (evt->state == A_FN_OP_STATE_DONE || evt->state == A_FN_OP_STATE_FAILED) {
            should_terminate = true;
        }

        if (evt->msg_len > 0) {
            app_info(false, 0, "%s", evt->msg);
        } else {
            switch (evt->error_code) {
            case A_FN_ERROR_GENERIC:
                app_info(false, 0, fn_status_error);
                break;

            case A_FN_ERROR_NOT_EXIST:
                app_info(false, 0, fn_not_exist);
                break;

            case A_FN_ERROR_NONE:
                break;

            default:
                break;
            }
        }
        free(evt);
        if (should_terminate)
            break;
    }

    close(sock_fd);
    return 0;
}

/* HELP CMD */
static void a_fn_status_help() {
    app_info(false, 0, "aura function status -f <function name>");
}

struct aura_cli_flag *fn_status_flags[] = {
  &fn_status_flag,
};

struct aura_cli_cmd fn_status_cli = {
  .version = "1.0.0",
  .name = "status",
  .description = "Get the status of the provided function",
  .usage = "aura function status -f <function name>",
  .deprecated = NULL,
  .flags = fn_status_flags,
  .flag_count = ARRAY_SIZE(fn_status_flags),
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
  .options_size = sizeof(struct fn_status_config),
  .opt_allocator = a_fn_status_option_allocator,
  .opt_destructor = a_fn_status_option_deallocator,
  .handler = aura_cli_fn_status,
  .opt_help = a_fn_status_help,
};
