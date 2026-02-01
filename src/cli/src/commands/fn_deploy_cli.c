#include "bug_lib.h"
#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "function_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <dirent.h>

const char fn_deploy_success[] = "\x1B[1;32mDeployment complete\x1B[0m";
const char fn_deploy_failed_error[] = "\x1B[1;31mDeployment Failed\x1B[0m";
const char fn_deploy_config_error[] = "\x1B[1;31mDeployment Failed, Could not successfully parse config\x1B[0m";
const char fn_deploy_entry_file_error[] = "\x1B[1;31mFailed to load entry file\x1B[0m";
const char fn_deploy_fn_exists_error[] = "\x1B[1;31mDeployment failed. Function with same name and version already exists\x1B[0m";

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
    char *data, *fn_dir, *conf_file;
    DIR *dp;
    struct dirent *dirp;
    struct aura_msg_hdr hdr;
    struct aura_msg msg;
    struct fn_deploy_config *opts;
    struct aura_fn_evt *evt;
    int sock_fd, file_fd, dir_fd, res;
    bool ret;

    aura_try_connect_or_error(&sock_fd);
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
    ret = openat(dir_fd, conf_file, O_RDONLY);
    if (!ret)
        sys_exit(false, errno, "Failed to open configuration file: %s\n", conf_file);
    close(file_fd);

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_FN_DEPLOY);

    /* send over the directory file descriptor */
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, dir_fd) != 0)
        sys_exit(false, errno, "Failed to send aura cli command");

    bool terminate;
    while (true) {
        terminate = false;
        evt = aura_recv_resp(sock_fd);
        if (!evt)
            break;

        aura_fn_evt_cli_response_dump(evt);
        if (evt->state == A_FN_DEPLOY_STATE_DONE || evt->state == A_FN_DEPLOY_STATE_FAILED) {
            terminate = true;
        }

        if (evt->msg_len > 0)
            app_info(false, 0, "%s", evt->msg);
        else {
            switch (evt->error_code) {
            case A_FN_DEPLOY_ERROR_GENERIC:
                app_info(false, 0, "%s", fn_deploy_failed_error);
                break;

            case A_FN_DEPLOY_ERROR_CONFIG:
                app_info(false, 0, "%s", fn_deploy_config_error);
                break;

            case A_FN_DEPLOY_ERROR_DUPLICATE:
                app_info(false, 0, "%s", fn_deploy_fn_exists_error);
                break;

            case A_FN_DEPLOY_ERROR_NONE:
                app_info(false, 0, "%s", fn_deploy_success);
                break;

            default:
                break;
            }
        }
        free(evt);
        if (terminate)
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
  .flag_count = ARRAY_SIZE(fn_deploy_flags),
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
