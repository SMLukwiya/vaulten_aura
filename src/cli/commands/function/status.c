#include "cmdline.h"
#include "command.h"
#include "error_lib.h"
#include "file/lib.h"
#include "flag.h"
#include "fn/lib.h"
#include "ipc/ipc.h"
#include "log_msg.h"
#include "unix/sock.h"
#include "utils_lib.h"

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
    struct aura_msg_hdr hdr;
    struct fn_status_config *opts;
    int sock_fd, rv;
    char *fn_name, *sep;
    uint32_t fn_verion;
    struct aura_iovec data;
    struct aura_fn_evt *evt;
    char sock_file[A_MAX_SOCK_FILE_LEN];
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

    opts = (struct fn_status_config *)opts_ptr;
    fn_name = opts->fn_name;
    sep = strchr(fn_name, ':');
    if (sep) {
        /* Try and parse fn version */
        if (*(sep + 1) == '\0') {
            app_info(false, 0, "Missing function version, Expected a valid integer");
            return -1;
        }

        if (aura_scan_str(sep + 1, "%d" SCNu32, &fn_verion) < 0) {
            app_info(false, 0, "Invalid function version: %s, Expected a valid integer", sep + 1);
            return -1;
        }
    }

    a_init_msg_hdr(hdr, strlen(fn_name), A_MSG_CMD_EXECUTE, A_CMD_FN_STATUS);

    /* send over the directory file descriptor */
    if (aura_msg_send(sock_fd, &hdr, opts->fn_name, strlen(opts->fn_name), -1) != 0) {
        sys_info(false, errno, cmd_send_failed);
        return -1;
    }

    bool should_terminate;

    while (true) {
        should_terminate = false;
        if (aura_recv_resp(&data, sock_fd, NULL) < 0) {
            close(sock_fd);
            return -1;
        }

        evt = (struct aura_fn_evt *)data.base;
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
                app_info(false, 0, cli_cmd_msg[A_FN_ERROR_GENERIC].base);
                break;

            case A_FN_ERROR_NOT_EXIST:
                app_info(false, 0, cli_cmd_msg[A_FN_ERROR_NOT_EXIST].base);
                break;

            case A_FN_ERROR_NONE:
                app_info(false, 0, cli_cmd_msg[A_FN_ERROR_NONE].base);
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
  .flag_cnt = ARRAY_SIZE(fn_status_flags),
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
