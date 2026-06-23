#include "cmdline.h"
#include "command.h"
#include "error_lib.h"
#include "file/lib.h"
#include "flag.h"
#include "ipc/ipc.h"
#include "unix/sock.h"
#include "utils_lib.h"

/* validate cli options */
struct srv_conf_validate_opt {
    char *server_conf_path;
};

/* Allocator fn */
static void *a_server_conf_validate_opt_allocator(void) {
    return malloc(sizeof(struct srv_conf_validate_opt));
}

/* Deallocator fn */
static void a_server_conf_validate_opt_deallocator(void *opts_ptr) {
    struct srv_conf_validate_opt *opts = (struct srv_conf_validate_opt *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->server_conf_path)
        free(opts->server_conf_path);

    free(opts);
}

/* Handler fn */
int aura_cli_run_server_validate_conf_cli(void *opts_ptr, void *glob_opts) {
    char resolved_conf_file_path[1024];
    int sock_fd, file_fd;
    struct aura_msg_hdr hdr;
    struct aura_iovec data;
    struct srv_conf_validate_opt *opts = (struct srv_conf_validate_opt *)opts_ptr;
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

    if (aura_get_absolute_path(opts->server_conf_path, resolved_conf_file_path) != 0) {
        sys_info(false, errno, "%s %s", file_error, opts->server_conf_path);
        return -1;
    }

    // if (access(resolved_conf_file_path, R_OK) < 0)
    //     sys_exit(false, 0, "Failed to get read access file: %s", resolved_conf_file_path);

    file_fd = open(resolved_conf_file_path, O_RDONLY);
    if (file_fd < 0) {
        sys_info(false, errno, "%s %s", file_error, resolved_conf_file_path);
        return -1;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_VALIDATE_CONF);

    if (aura_msg_send(sock_fd, &hdr, NULL, 0, file_fd) != 0) {
        sys_info(false, errno, cmd_send_failed);
        return -1;
    }
    close(file_fd);

    if (aura_recv_resp(&data, sock_fd, NULL) < 0) {
        close(sock_fd);
        return -1;
    }

    if (data.base)
        app_info(false, 0, "%s", data.base);

    close(sock_fd);
    return 0;
}

/* HELP CMD */
static void a_server_conf_validate_help() {
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
  .type = A_CLI_FLAG_STRING,
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
  .flag_cnt = ARRAY_SIZE(svr_validate_conf_flags),
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
  .options_size = sizeof(struct srv_conf_validate_opt),
  .opt_allocator = a_server_conf_validate_opt_allocator,
  .opt_destructor = a_server_conf_validate_opt_deallocator,
  .handler = aura_cli_run_server_validate_conf_cli,
  .opt_help = a_server_conf_validate_help,
};
