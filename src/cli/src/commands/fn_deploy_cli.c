#include "bug_lib.h"
#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "function_lib.h"
#include "log_cli.h"
#include "unix/sock.h"
#include "utils_lib.h"

#include <dirent.h>

struct fn_deploy_config {
    char *fn_dir_path;
};

/* Allocator fn */
static void *a_fn_deploy_opt_allocator(void) {
    return malloc(sizeof(struct fn_deploy_config));
}

/* Deallocator fn */
static void a_fn_deploy_opt_deallocator(void *opts_ptr) {
    struct fn_deploy_config *opts = (struct fn_deploy_config *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->fn_dir_path)
        free(opts->fn_dir_path);

    free(opts);
}

struct aura_cli_flag fn_deploy_flag = {
  .name = "path",
  .short_name = 'p',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = A_CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct fn_deploy_config, fn_dir_path),
  .description = "path to function function dir",
};

int aura_cli_run_fn_deploy(void *opts_ptr, void *glob_opts) {
    char *fn_dir, *conf_file;
    DIR *dp;
    struct dirent *dirp;
    struct aura_msg_hdr hdr;
    struct fn_deploy_config *opts;
    struct aura_fn_evt *evt;
    struct aura_iovec data;
    int sock_fd, file_fd, dir_fd, res;

    sock_fd = aura_try_connect_or_error();
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    conf_file = NULL;
    opts = (struct fn_deploy_config *)opts_ptr;
    fn_dir = opts->fn_dir_path ? opts->fn_dir_path : ".";
    dp = opendir(opts->fn_dir_path);
    if (!dp)
        sys_exit(false, errno, "Failed to open function directory: %s", opts->fn_dir_path);

    dir_fd = dirfd(dp);
    if (dir_fd == -1)
        sys_exit(false, errno, "Failed to open function directory: %s", opts->fn_dir_path);

    while (true) {
        dirp = readdir(dp);
        if (!dirp)
            break;

        if (strcmp(dirp->d_name, "function.yml") == 0 || strcmp(dirp->d_name, "function.yaml") == 0) {
            conf_file = dirp->d_name;
            break;
        }
    }

    if (!conf_file)
        app_exit(false, 0, "Failed to locate function configuration, ensure a function.yaml or function.yml exists in the funtion directory");

    /* do a simple check on the config file */
    file_fd = openat(dir_fd, conf_file, O_RDONLY);
    if (file_fd < 0)
        sys_exit(false, errno, "Failed to open configuration file: %s\n", conf_file);
    close(file_fd);

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_FN_DEPLOY);

    /* send over the directory file descriptor */
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, dir_fd) != 0)
        sys_exit(false, errno, "Failed to send aura cli command");

    bool should_terminate;
    while (true) {
        should_terminate = false;
        res = aura_recv_resp(&data, sock_fd, NULL);
        if (res < 0) {
            closedir(dp);
            close(sock_fd);
            return res;
        }

        evt = (struct aura_fn_evt *)data.base;
        if (!evt)
            break;

        if (evt->state == A_FN_OP_STATE_DONE || evt->state == A_FN_OP_STATE_FAILED) {
            should_terminate = true;
        }

        if (evt->msg_len > 0)
            app_info(false, 0, "%s", evt->msg);
        else {
            switch (evt->error_code) {
            case A_FN_ERROR_GENERIC:
                app_info(false, 0, "%s", cli_cmd_msg[A_FN_ERROR_GENERIC].base);
                break;

            case A_FN_ERROR_CONFIG:
                app_info(false, 0, "%s", cli_cmd_msg[A_FN_ERROR_CONFIG].base);
                break;

            case A_FN_ERROR_DUPLICATE:
                app_info(false, 0, "%s", cli_cmd_msg[A_FN_ERROR_DUPLICATE].base);
                break;

            case A_FN_ERROR_NONE:
                app_info(false, 0, "%s", cli_cmd_msg[A_FN_ERROR_NONE].base);
                break;

            default:
                break;
            }
        }
        free(evt);
        if (should_terminate)
            break;
    }

    closedir(dp);
    close(sock_fd);
    return 0;
}

/* HELP CMD */
static void a_fn_deploy_validate_help() {
    app_info(false, 0, "aura function deploy -p <path to config file>");
}

struct aura_cli_flag *fn_deploy_flags[] = {
  &fn_deploy_flag,
};

struct aura_cli_cmd fn_deploy_cli = {
  .version = "1.0.0",
  .name = "deploy",
  .description = "deploy a function according to the configuration file provided",
  .usage = "aura function deploy -p <path to config file>",
  .deprecated = NULL,
  .flags = fn_deploy_flags,
  .flag_cnt = ARRAY_SIZE(fn_deploy_flags),
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
  .options_size = sizeof(struct fn_deploy_config),
  .opt_allocator = a_fn_deploy_opt_allocator,
  .opt_destructor = a_fn_deploy_opt_deallocator,
  .handler = aura_cli_run_fn_deploy,
  .opt_help = a_fn_deploy_validate_help,
};
