#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "function_lib.h"
#include "log_cli.h"
#include "unix/sock.h"
#include "utils_lib.h"

struct fn_list_config {
    bool running;
    bool stopped;
};

/* Allocator fn */
static void *a_fn_list_option_allocator(void) {
    struct fn_list_config *c;

    c = malloc(sizeof(*c));
    if (!c) {
        sys_debug(false, errno, "a_fn_list_option_allocator");
        exit(1);
    }
    c->running = false;
    c->stopped = false;
    return (void *)c;
}

/* Deallocator fn */
static void a_fn_list_option_deallocator(void *opts_ptr) {
    struct fn_list_config *opts = (struct fn_list_config *)opts_ptr;
    if (!opts_ptr)
        return;

    free(opts);
}

struct aura_cli_flag fn_list_running_flag = {
  .name = "running",
  .short_name = 'r',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = false,
  .is_set = false,
  .type = A_CLI_FLAG_BOOL,
  .offset_in_option = OPT_OFFSET(struct fn_list_config, running),
  .description = "List functions in running state",
};

struct aura_cli_flag fn_list_stopped_flag = {
  .name = "stopped",
  .short_name = 's',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = false,
  .is_set = false,
  .type = A_CLI_FLAG_BOOL,
  .offset_in_option = OPT_OFFSET(struct fn_list_config, stopped),
  .description = "List functions in stopped state",
};

int aura_cli_fn_list(void *opts_ptr, void *glob_opts) {
    struct aura_msg_hdr hdr;
    struct fn_list_config *opts;
    int sock_fd, res;
    struct aura_iovec data;
    char *state;
    struct aura_fn_evt *evt;

    sock_fd = aura_try_connect_or_error();
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    opts = (struct fn_list_config *)opts_ptr;
    if (opts->running)
        state = "running";
    else if (opts->stopped)
        state = "stopped";
    else
        state = "all";

    a_init_msg_hdr(hdr, strlen(state), A_MSG_CMD_EXECUTE, A_CMD_FN_LIST);

    if (aura_msg_send(sock_fd, &hdr, state, sizeof(state), -1) != 0) {
        sys_debug(false, errno, "aura_cli_fn_list: aura_msg_send error:");
        app_exit(false, 0, "Cmd Failed");
    }

    bool should_terminate;

    while (true) {
        should_terminate = false;
        res = aura_recv_resp(&data, sock_fd, NULL);
        if (res < 0) {
            close(sock_fd);
            return res;
        }

        evt = (struct aura_fn_evt *)data.base;
        if (!evt)
            break;

        if (evt->state == A_FN_OP_STATE_DONE || evt->state == A_FN_OP_STATE_FAILED) {
            should_terminate = true;
        }

        if (evt->msg_len > 0) {
            struct aura_fn_list *fn_list;
            evt->_msg = (char *)evt + sizeof(*evt);

            fn_list = (struct aura_fn_list *)evt->_msg;
            fn_list->fns = (struct aura_fn_rep *)((char *)fn_list + sizeof(*fn_list));

            if (fn_list->cnt == 0) {
                app_info(false, 0, "No functions deployed!");
            } else {
                for (int i = 0; i < fn_list->cnt; ++i) {
                    app_info(false, 0, "%s: %u", fn_list->fns[i].fn_name, fn_list->fns[i].fn_version);
                }
            }
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
static void a_fn_list_help() {
    app_info(false, 0, "aura function list (-s/-r)");
}

struct aura_cli_flag *fn_list_flags[] = {
  &fn_list_running_flag,
  &fn_list_stopped_flag,
};

struct aura_cli_cmd fn_list_cli = {
  .version = "1.0.0",
  .name = "list",
  .description = "Get the list of deployed functions",
  .usage = "aura function list (-r/-s)",
  .deprecated = NULL,
  .flags = fn_list_flags,
  .flag_cnt = ARRAY_SIZE(fn_list_flags),
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
  .options_size = sizeof(struct fn_list_config),
  .opt_allocator = a_fn_list_option_allocator,
  .opt_destructor = a_fn_list_option_deallocator,
  .handler = aura_cli_fn_list,
  .opt_help = a_fn_list_help,
};
